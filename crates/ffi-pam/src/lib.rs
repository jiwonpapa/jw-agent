#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(target_os = "linux")]
mod linux;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PamSubject {
    pub canonical_username: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PamError {
    AuthenticationFailed,
    AccountDenied,
    UnsupportedConversation,
    InvalidInput,
    Unavailable,
    UnsupportedPlatform,
}

impl std::fmt::Display for PamError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::AuthenticationFailed => "authentication failed",
            Self::AccountDenied => "account denied",
            Self::UnsupportedConversation => "unsupported PAM conversation",
            Self::InvalidInput => "invalid PAM input",
            Self::Unavailable => "PAM unavailable",
            Self::UnsupportedPlatform => "PAM is unsupported on this platform",
        })
    }
}

impl std::error::Error for PamError {}

#[cfg(target_os = "linux")]
pub use linux::authenticate;

#[cfg(not(target_os = "linux"))]
pub fn authenticate(
    _service: &str,
    _username: &str,
    _password: &str,
    _remote_address: Option<&str>,
) -> Result<PamSubject, PamError> {
    Err(PamError::UnsupportedPlatform)
}

#[must_use]
pub const fn platform_supported() -> bool {
    cfg!(target_os = "linux")
}
