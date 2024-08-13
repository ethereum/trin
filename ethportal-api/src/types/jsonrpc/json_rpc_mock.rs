use serde::Serialize;
use serde_json::Value;
use tokio::sync::mpsc;

use super::request::JsonRpcRequest;

type FilterFn<T> = Box<dyn Fn(&T) -> bool + Send>;

/// Defines whether and how to respond to the request.
struct Interaction<T> {
    request_selector_fn: FilterFn<T>,
    response: Result<Value, String>,
}

impl<T> Interaction<T> {
    /// Returns `Some(response)` if selector returns `true`, `None` otherwise.
    fn maybe_respond(&self, request: &T) -> Option<Result<Value, String>> {
        if (self.request_selector_fn)(request) {
            Some(self.response.clone())
        } else {
            None
        }
    }
}

/// Builder for mocking the JSPN-RPC handler.
pub struct MockJsonRpcBuilder<T> {
    interactions: Vec<Interaction<T>>,
}

impl<T: PartialEq + Send + 'static> MockJsonRpcBuilder<T> {
    pub fn new_builder() -> Self {
        Self {
            interactions: vec![],
        }
    }

    pub fn with_response(mut self, request: T, response: impl Serialize) -> Self {
        self.interactions.push(Interaction {
            request_selector_fn: Box::new(move |r| r == &request),
            response: serde_json::to_value(response).map_err(|err| err.to_string()),
        });
        self
    }

    pub fn with_error(mut self, request: T, error: impl ToString) -> Self {
        self.interactions.push(Interaction {
            request_selector_fn: Box::new(move |r| r == &request),
            response: Err(error.to_string()),
        });
        self
    }

    pub fn with_custom_trigger(
        mut self,
        trigger_fn: FilterFn<T>,
        response: Result<Value, String>,
    ) -> Self {
        self.interactions.push(Interaction {
            request_selector_fn: trigger_fn,
            response,
        });
        self
    }

    pub fn or_else(mut self, response: impl Serialize) -> mpsc::UnboundedSender<JsonRpcRequest<T>> {
        self.interactions.push(Interaction {
            request_selector_fn: Box::new(|_| true),
            response: serde_json::to_value(response).map_err(|err| err.to_string()),
        });
        self.or_fail()
    }

    pub fn or_fail(self) -> mpsc::UnboundedSender<JsonRpcRequest<T>> {
        let (tx, mut rx) = mpsc::unbounded_channel::<JsonRpcRequest<T>>();
        tokio::spawn(async move {
            while let Some(request) = rx.recv().await {
                let response = self
                    .interactions
                    .iter()
                    .find_map(|interaction| interaction.maybe_respond(&request.endpoint))
                    .unwrap_or_else(|| Err("No expected response found".to_string()));
                request
                    .resp
                    .send(response)
                    .expect("Something should receive response");
            }
        });
        tx
    }
}
