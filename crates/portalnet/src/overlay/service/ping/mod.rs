pub mod handlers;

use std::marker::Sync;

use discv5::{enr::NodeId, rpc::RequestId};
use ethportal_api::{
    types::{
        distance::Metric,
        enr::Enr,
        ping_extensions::{
            decode::PingExtension,
            extension_types::PingExtensionType,
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
        ping_extensions::PingExtensions,
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
        TPingExtensions: 'static + PingExtensions + Send + Sync,
    > OverlayService<TContentKey, TMetric, TValidator, TStore, TPingExtensions>
{
    fn create_pong(&self, payload_type: PingExtensionType, payload: CustomPayload) -> Pong {
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

        let extension_type = request.payload_type;

        if !self.ping_extensions.is_supported(extension_type) {
            warn!(
                protocol = %self.protocol,
                request.source = %source,
                request.discv5.id = %request_id,
                "Received unsupported ping extension: {extension_type:?}"
            );
            return self.create_pong(
                PingExtensionType::Error,
                PingError::new(ErrorCodes::ExtensionNotSupported).into(),
            );
        }

        match extension_type {
            PingExtensionType::Capabilities => {
                self.create_pong(extension_type, self.create_capabilities().into())
            }
            PingExtensionType::BasicRadius => self.create_pong(
                extension_type,
                BasicRadius {
                    data_radius: self.data_radius(),
                }
                .into(),
            ),
            PingExtensionType::HistoryRadius => self.create_pong(
                extension_type,
                HistoryRadius {
                    data_radius: self.data_radius(),
                    ephemeral_header_count: 0,
                }
                .into(),
            ),
            PingExtensionType::Error => {
                warn!(
                    protocol = %self.protocol,
                    request.source = %source,
                    request.discv5.id = %request_id,
                    "Received invalid Ping message, Errors should only be received from pong",
                );
                self.create_pong(
                    extension_type,
                    PingError::new(ErrorCodes::SystemError).into(),
                )
            }
            PingExtensionType::NonSupportedExtension(non_supported_extension) => {
                unreachable!("Non supported extension type: {non_supported_extension}")
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

            let extension = match PingExtension::decode_ssz(ping.payload_type, ping.payload) {
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
                PingExtension::Capabilities(radius_capabilities) => {
                    handle_capabilities(radius_capabilities, node)
                }
                PingExtension::BasicRadius(basic_radius) => handle_basic_radius(basic_radius, node),
                PingExtension::HistoryRadius(history_radius) => {
                    handle_history_radius(history_radius, node)
                }
                PingExtension::Error(ping_error) => {
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

            let extension = match PingExtension::decode_ssz(pong.payload_type, pong.payload) {
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
                PingExtension::Capabilities(radius_capabilities) => {
                    handle_capabilities(radius_capabilities, node)
                }
                PingExtension::BasicRadius(basic_radius) => handle_basic_radius(basic_radius, node),
                PingExtension::HistoryRadius(history_radius) => {
                    handle_history_radius(history_radius, node)
                }
                PingExtension::Error(ping_error) => {
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
        ClientInfoRadiusCapabilities::new(
            self.data_radius(),
            self.ping_extensions.supported_extensions().to_vec(),
        )
    }

    fn handle_base_extension(
        &self,
        extension: PingExtensionType,
        node_id: NodeId,
    ) -> PingExtension {
        match extension {
            PingExtensionType::BasicRadius => PingExtension::BasicRadius(BasicRadius {
                data_radius: self.data_radius(),
            }),
            PingExtensionType::HistoryRadius => PingExtension::HistoryRadius(HistoryRadius {
                data_radius: self.data_radius(),
                ephemeral_header_count: 0,
            }),
            _ => {
                warn!(
                    protocol = %self.protocol,
                    request.dest = %node_id,
                    "Base extension wasn't implemented: {extension:?}, sending Capabilities instead. This is a bug!",
                );
                PingExtension::Capabilities(self.create_capabilities())
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

        let ping_extension = match node.capabilities().map(|capabilities| {
            self.ping_extensions
                .latest_mutually_supported_base_extension(capabilities)
        }) {
            Some(Some(extension)) => self.handle_base_extension(extension, node.enr.node_id()),
            _ => PingExtension::Capabilities(self.create_capabilities()),
        };

        let ping = Request::Ping(Ping {
            enr_seq: self.local_enr().seq(),
            payload_type: ping_extension.ping_extension_type(),
            payload: ping_extension.into(),
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
