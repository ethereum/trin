pub mod handlers;

use std::marker::Sync;

use discv5::{enr::NodeId, rpc::RequestId};
use ethportal_api::{
    types::{
        distance::Metric,
        enr::Enr,
        ping_extensions::{
            decode::DecodedExtension,
            extension_types::Extensions,
            extensions::{
                type_0::ClientInfoRadiusCapabilities,
                type_1::BasicRadius,
                type_2::HistoryRadius,
                type_65535::{ErrorCodes, PingError},
            },
        },
        portal_wire::{CustomPayload, Ping, Pong, Request},
    },
    OverlayContentKey,
};
use handlers::{handle_basic_radius, handle_capabilities, handle_history_radius};
use tracing::{trace, warn};
use trin_storage::ContentStore;
use trin_validation::validator::Validator;

use super::OverlayService;
use crate::{
    overlay::{
        command::OverlayCommand,
        ping_extensions::PingExtension,
        request::{OverlayRequest, RequestDirection},
    },
    types::node::Node,
};

/// Implementation of the `OverlayService` for handling Ping and Pong Extensions.
impl<
        TContentKey: 'static + OverlayContentKey + Send + Sync,
        TMetric: Metric + Send + Sync,
        TValidator: 'static + Validator<TContentKey> + Send + Sync,
        TStore: 'static + ContentStore<Key = TContentKey> + Send + Sync,
        TPingExtensions: 'static + PingExtension + Send + Sync,
    > OverlayService<TContentKey, TMetric, TValidator, TStore, TPingExtensions>
{
    fn create_pong(&self, payload_type: u16, payload: CustomPayload) -> Pong {
        Pong {
            enr_seq: self.local_enr().seq(),
            payload_type,
            payload,
        }
    }

    /// Builds a `Pong` response for a `Ping` request.
    pub(super) fn handle_ping(
        &self,
        request: Ping,
        source: &NodeId,
        request_id: RequestId,
    ) -> Pong {
        trace!(
            protocol = %self.protocol,
            request.source = %source,
            request.discv5.id = %request_id,
            "Handling Ping message {request}",
        );

        let extension_type = match Extensions::try_from(request.payload_type) {
            Ok(extension) => extension,
            Err(err) => {
                warn!(
                    protocol = %self.protocol,
                    request.source = %source,
                    request.discv5.id = %request_id,
                    "Received non-supported extension type in ping message: {err:?}",
                );
                return self.create_pong(
                    Extensions::Error.into(),
                    PingError::new(ErrorCodes::ExtensionNotSupported).into(),
                );
            }
        };

        if !self.ping_extensions.is_supported(extension_type) {
            warn!(
                protocol = %self.protocol,
                request.source = %source,
                request.discv5.id = %request_id,
                "Received non-supported ping extension on this portal subnetwork: {extension_type:?}",
            );
            return self.create_pong(
                Extensions::Error.into(),
                PingError::new(ErrorCodes::ExtensionNotSupported).into(),
            );
        }

        match extension_type {
            Extensions::Capabilities => {
                self.create_pong(extension_type.into(), self.create_capabilities().into())
            }
            Extensions::BasicRadius => self.create_pong(
                extension_type.into(),
                BasicRadius {
                    data_radius: self.data_radius(),
                }
                .into(),
            ),
            Extensions::HistoryRadius => self.create_pong(
                extension_type.into(),
                HistoryRadius {
                    data_radius: self.data_radius(),
                    ephemeral_header_count: 0,
                }
                .into(),
            ),
            Extensions::Error => {
                warn!(
                    protocol = %self.protocol,
                    request.source = %source,
                    request.discv5.id = %request_id,
                    "Received invalid Ping message, Errors should only be received from pong",
                );
                self.create_pong(
                    extension_type.into(),
                    PingError::new(ErrorCodes::SystemError).into(),
                )
            }
        }
    }

    /// Processes a ping request from some source node.
    pub(super) fn process_ping(&self, ping: Ping, source: NodeId) {
        // If the node is in the routing table, then check if we need to update the node.
        if let Some(node) = self.kbuckets.entry(source).present_or_pending() {
            // TODO: How do we handle data in the custom payload? This is unique to each overlay
            // network, so there may need to be some way to parameterize the update for a
            // ping/pong.

            // If the ENR sequence number in pong is less than the ENR sequence number for the
            // routing table entry, then request the node.
            if node.enr().seq() < ping.enr_seq {
                self.request_node(&node.enr());
            }

            let extension =
                match DecodedExtension::decode_extension(ping.payload_type, ping.payload) {
                    Ok(extension) => extension,
                    Err(err) => {
                        warn!(
                            protocol = %self.protocol,
                            request.source = %source,
                            "Failed to decode custom payload during process_ping: {err:?}",
                        );
                        return;
                    }
                };

            if !self.ping_extensions.is_supported(extension.clone().into()) {
                warn!(
                    protocol = %self.protocol,
                    request.source = %source,
                    "Extension type isn't supported on this subnetwork: {extension:?}",
                );
                return;
            }

            let node = match extension {
                DecodedExtension::Capabilities(radius_capabilities) => {
                    handle_capabilities(radius_capabilities, node, self.protocol)
                }
                DecodedExtension::BasicRadius(basic_radius) => {
                    handle_basic_radius(basic_radius, node)
                }
                DecodedExtension::HistoryRadius(history_radius) => {
                    handle_history_radius(history_radius, node)
                }
                DecodedExtension::Error(ping_error) => {
                    warn!(
                        protocol = %self.protocol,
                        request.source = %source,
                        "Received an error response from a ping request: {ping_error:?}",
                    );
                    return;
                }
            };

            if let Some(node) = node {
                self.update_node(node);
            }
        }
    }

    /// Processes a Pong response.
    ///
    /// Refreshes the node if necessary. Attempts to mark the node as connected.
    pub(super) fn process_pong(&self, pong: Pong, source: Enr) {
        let node_id = source.node_id();
        trace!(
            protocol = %self.protocol,
            response.source = %node_id,
            "Processing Pong message {pong}"
        );

        // If the ENR sequence number in pong is less than the ENR sequence number for the routing
        // table entry, then request the node.
        //
        // TODO: Perform update on non-ENR node entry state. See note in `process_ping`.
        if let Some(node) = self.kbuckets.entry(node_id).present_or_pending() {
            if node.enr().seq() < pong.enr_seq {
                self.request_node(&node.enr());
            }

            let extension =
                match DecodedExtension::decode_extension(pong.payload_type, pong.payload) {
                    Ok(extension) => extension,
                    Err(err) => {
                        warn!(
                            protocol = %self.protocol,
                            request.source = %source,
                            "Failed to decode custom payload during process_pong: {err:?}",
                        );
                        return;
                    }
                };

            if !self.ping_extensions.is_supported(extension.clone().into()) {
                warn!(
                    protocol = %self.protocol,
                    request.source = %source,
                    "Extension type isn't supported on this subnetwork: {extension:?}",
                );
                return;
            }

            let node = match extension {
                DecodedExtension::Capabilities(radius_capabilities) => {
                    handle_capabilities(radius_capabilities, node, self.protocol)
                }
                DecodedExtension::BasicRadius(basic_radius) => {
                    handle_basic_radius(basic_radius, node)
                }
                DecodedExtension::HistoryRadius(history_radius) => {
                    handle_history_radius(history_radius, node)
                }
                DecodedExtension::Error(ping_error) => {
                    warn!(
                        protocol = %self.protocol,
                        request.source = %source,
                        "Received an error response from a pong request: {ping_error:?}",
                    );
                    return;
                }
            };

            if let Some(node) = node {
                self.update_node(node);
            }
        }
    }

    fn create_capabilities(&self) -> ClientInfoRadiusCapabilities {
        ClientInfoRadiusCapabilities::new(self.data_radius(), self.ping_extensions.raw_extensions())
    }

    fn handle_base_extension(
        &self,
        extension: Extensions,
        node_id: NodeId,
    ) -> (u16, CustomPayload) {
        match extension {
            Extensions::BasicRadius => (
                extension.into(),
                BasicRadius {
                    data_radius: self.data_radius(),
                }
                .into(),
            ),
            Extensions::HistoryRadius => (
                extension.into(),
                HistoryRadius {
                    data_radius: self.data_radius(),
                    ephemeral_header_count: 0,
                }
                .into(),
            ),
            _ => {
                warn!(
                    protocol = %self.protocol,
                    request.dest = %node_id,
                    "Base extension wasn't implemented: {extension:?}, sending Capabilities instead. This is a bug!",
                );
                (0, self.create_capabilities().into())
            }
        }
    }

    /// Submits a request to ping a destination (target) node.
    ///
    /// This can block the thread, so make sure you are not holding any lock while calling this.
    pub(super) fn ping_node(&self, node: Node) {
        trace!(
            protocol = %self.protocol,
            request.dest = %node.enr.node_id(),
            "Sending Ping message",
        );

        let (payload_type, payload) = match node.capabilities().map(|capabilities| {
            self.ping_extensions
                .latest_mutually_supported_base_extension(capabilities)
        }) {
            Some(Some(extension)) => self.handle_base_extension(extension, node.enr.node_id()),
            _ => (0, self.create_capabilities().into()),
        };

        let ping = Request::Ping(Ping {
            enr_seq: self.local_enr().seq(),
            payload_type,
            payload,
        });
        let request = OverlayRequest::new(
            ping,
            RequestDirection::Outgoing {
                destination: node.enr.clone(),
            },
            None,
            None,
            None,
        );
        let _ = self.command_tx.send(OverlayCommand::Request(request));
    }
}
