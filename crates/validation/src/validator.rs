use std::{fmt::Debug, future::Future};

use ethportal_api::{types::content_key::overlay::IdentityContentKey, RawContentValue};
use futures::future::JoinAll;

/// The result of the content key/value validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationResult {
    /// The content is proved to be canonical, and it's safe to store it.
    CanonicallyValid,
    /// The content value is proven to match content key, but it's not proven that it's canonical.
    ///
    /// This type of content is not safe for storing, but it is safe to return as a result of Find
    /// Content request.
    Valid,
    /// Content is invalid or validation failed for some other reason.
    Invalid(String),
}

impl ValidationResult {
    /// Returns `true` if content is [ValidationResult::CanonicallyValid].
    pub fn is_canonically_valid(&self) -> bool {
        self == &Self::CanonicallyValid
    }

    /// Returns `true` if content is [ValidationResult::CanonicallyValid] or
    /// [ValidationResult::Valid].
    ///
    /// See [ValidationResult] for details.
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::CanonicallyValid | Self::Valid)
    }
}

/// Used by all overlay-network Validators to validate content in the overlay service.
pub trait Validator<TContentKey> {
    /// Validates the provided content key/value pair.
    fn validate_content(
        &self,
        content_key: &TContentKey,
        content_value: &[u8],
    ) -> impl Future<Output = ValidationResult> + Send;

    /// Validates multiple content key/value pairs.
    ///
    /// The default implementation calls `self.validate_content(key, value)` for each content pair.
    fn validate_content_batch(
        &self,
        content: &[(TContentKey, RawContentValue)],
    ) -> impl Future<Output = Vec<ValidationResult>> + Send {
        content
            .iter()
            .map(|(content_key, content_value)| self.validate_content(content_key, content_value))
            .collect::<JoinAll<_>>()
    }
}

/// For use in tests where no validation needs to be performed.
pub struct MockValidator {}

impl Validator<IdentityContentKey> for MockValidator {
    async fn validate_content(
        &self,
        _content_key: &IdentityContentKey,
        _content_value: &[u8],
    ) -> ValidationResult {
        ValidationResult::CanonicallyValid
    }
}
