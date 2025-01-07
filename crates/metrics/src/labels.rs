use ethportal_api::types::portal_wire::{Request, Response};

pub type MetricLabel = &'static str;

impl From<MessageDirectionLabel> for MetricLabel {
    fn from(label: MessageDirectionLabel) -> Self {
        match label {
            MessageDirectionLabel::Sent => "sent",
            MessageDirectionLabel::Received => "received",
        }
    }
}

impl From<MessageLabel> for MetricLabel {
    fn from(label: MessageLabel) -> Self {
        match label {
            MessageLabel::Ping => "ping",
            MessageLabel::FindNodes => "find_nodes",
            MessageLabel::FindContent => "find_content",
            MessageLabel::Offer => "offer",
            MessageLabel::Pong => "pong",
            MessageLabel::Nodes => "nodes",
            MessageLabel::Content => "content",
            MessageLabel::Accept => "accept",
        }
    }
}

impl From<UtpDirectionLabel> for MetricLabel {
    fn from(label: UtpDirectionLabel) -> Self {
        match label {
            UtpDirectionLabel::Outbound => "outbound",
            UtpDirectionLabel::Inbound => "inbound",
        }
    }
}

impl From<UtpOutcomeLabel> for MetricLabel {
    fn from(label: UtpOutcomeLabel) -> Self {
        match label {
            UtpOutcomeLabel::Success => "success",
            UtpOutcomeLabel::FailedConnection => "failed connection",
            UtpOutcomeLabel::FailedDataTx => "failed data tx",
            UtpOutcomeLabel::FailedShutdown => "failed shutdown",
        }
    }
}

impl From<&Request> for MessageLabel {
    fn from(request: &Request) -> Self {
        match request {
            Request::Ping(_) => MessageLabel::Ping,
            Request::FindNodes(_) => MessageLabel::FindNodes,
            Request::FindContent(_) => MessageLabel::FindContent,
            Request::Offer(_) => MessageLabel::Offer,
            // Populated offers are the same as regular offers, from a metrics point of view
            Request::PopulatedOffer(_) => MessageLabel::Offer,
            // Populated offers with result are the same as regular offers, from a metrics point of
            // view
            Request::PopulatedOfferWithResult(_) => MessageLabel::Offer,
        }
    }
}

impl From<&Response> for MessageLabel {
    fn from(response: &Response) -> Self {
        match response {
            Response::Pong(_) => MessageLabel::Pong,
            Response::Nodes(_) => MessageLabel::Nodes,
            Response::Content(_) => MessageLabel::Content,
            Response::Accept(_) => MessageLabel::Accept,
        }
    }
}

/// Message Direction Labels
pub enum MessageDirectionLabel {
    /// Messages sent to the network
    Sent,
    /// Messages received from the network
    Received,
}

/// Message Labels
/// - These label values identify the type of message in the metrics
pub enum MessageLabel {
    Ping,
    FindNodes,
    FindContent,
    Offer,
    Pong,
    Nodes,
    Content,
    Accept,
}

/// uTP Transfer Direction Labels
#[derive(Debug, Clone, Copy)]
pub enum UtpDirectionLabel {
    /// uTP transfers initiated by a peer
    Inbound,
    /// uTP transfers initiated by the node
    Outbound,
}

/// uTP Transfer Outcome Labels
#[derive(Debug, Clone, Copy)]
pub enum UtpOutcomeLabel {
    /// uTP transfers that completed successfully
    Success,
    /// uTP transfers that failed
    FailedConnection,
    FailedDataTx,
    FailedShutdown,
}
