use ethportal_api::types::content_key::overlay::IdentityContentKey;

/// The result of the content key/value validation.
#[derive(Debug, PartialEq, Eq)]
pub struct ValidationResult<TContentKey> {
    /// Whether validation proved that content is canonical, in which case it's safe to store it.
    ///
    /// Content obtained via Offer/Accept should always be provable, but that's not always the case
    /// for content obtained via Find/Found Content (e.g.for the state network, we can verify that
    /// content-value corresponds to the content-key, but not that it's canonical).
    pub valid_for_storing: bool,

    /// The optional content key/value pair to be propagated (together with original content
    /// key/value). This is used for Recursive Gossip in the state network (see [specs](
    /// https://github.com/ethereum/portal-network-specs/blob/04cc360179aeda179e0b1cac6fea900a74e87f2b/state-network.md#gossip
    /// ) for details.).
    pub additional_content_to_propagate: Option<(TContentKey, Vec<u8>)>,
}

impl<TContentKey> ValidationResult<TContentKey> {
    pub fn new(valid_for_storing: bool) -> Self {
        Self {
            valid_for_storing,
            additional_content_to_propagate: None,
        }
    }

    pub fn new_with_additional_content_to_propagate(
        additional_content_key: TContentKey,
        additional_content_value: Vec<u8>,
    ) -> Self {
        Self {
            valid_for_storing: true,
            additional_content_to_propagate: Some((
                additional_content_key,
                additional_content_value,
            )),
        }
    }
}

/// Used by all overlay-network Validators to validate content in the overlay service.
pub trait Validator<TContentKey: Send> {
    /// The `Ok` indicates that `content` corresponds to the `content_key`, but not necessarily
    /// that content is canonical. See `ValidationResult` for details.
    ///
    /// The `Err` indicates that either content is not valid or that validation failed for some
    /// other reason.
    fn validate_content(
        &self,
        content_key: &TContentKey,
        content: &[u8],
    ) -> impl std::future::Future<Output = anyhow::Result<ValidationResult<TContentKey>>> + Send;
}

/// For use in tests where no validation needs to be performed.
pub struct MockValidator {}

impl Validator<IdentityContentKey> for MockValidator {
    async fn validate_content(
        &self,
        _content_key: &IdentityContentKey,
        _content: &[u8],
    ) -> anyhow::Result<ValidationResult<IdentityContentKey>> {
        Ok(ValidationResult::new(true))
    }
}
