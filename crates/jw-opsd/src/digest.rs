use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::error::OpsError;

pub fn canonical_digest<T: Serialize>(domain: &[u8], value: &T) -> Result<String, OpsError> {
    let canonical =
        serde_json::to_vec(value).map_err(|error| OpsError::Storage(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(canonical);
    Ok(format_sha256(&hasher.finalize()))
}

pub fn ledger_event_digest(previous: &str, canonical_event: &[u8]) -> Result<String, OpsError> {
    let raw_previous = decode_sha256(previous)?;
    let mut hasher = Sha256::new();
    hasher.update(b"jw-agent/ledger/v1");
    hasher.update([0]);
    hasher.update(raw_previous);
    hasher.update(canonical_event);
    Ok(format_sha256(&hasher.finalize()))
}

#[must_use]
pub fn format_sha256(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(7 + bytes.len().saturating_mul(2));
    output.push_str("sha256:");
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

pub fn decode_sha256(value: &str) -> Result<[u8; 32], OpsError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(OpsError::ForensicLockdown);
    };
    if hex.len() != 64 {
        return Err(OpsError::ForensicLockdown);
    }
    let mut output = [0_u8; 32];
    for (index, slot) in output.iter_mut().enumerate() {
        let offset = index.saturating_mul(2);
        let Some(pair) = hex.get(offset..offset.saturating_add(2)) else {
            return Err(OpsError::ForensicLockdown);
        };
        *slot = u8::from_str_radix(pair, 16).map_err(|_| OpsError::ForensicLockdown)?;
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use jw_contracts::{nginx_enabled_state_digest, nginx_site_id, sha256_digest};

    #[test]
    fn site_identity_matches_normative_fixture() -> Result<(), String> {
        let fixture: Value = serde_json::from_str(include_str!(
            "../../../tests/spec-fixtures/nginx-site-state-set-v1.json"
        ))
        .map_err(|error| error.to_string())?;
        let layout = fixture
            .get("layoutId")
            .and_then(Value::as_str)
            .ok_or_else(|| String::from("fixture layoutId missing"))?;
        let vector = fixture
            .get("siteIdentityVector")
            .ok_or_else(|| String::from("fixture siteIdentityVector missing"))?;
        let basename = vector
            .get("basename")
            .and_then(Value::as_str)
            .ok_or_else(|| String::from("fixture basename missing"))?;
        let expected = vector
            .get("siteId")
            .and_then(Value::as_str)
            .ok_or_else(|| String::from("fixture siteId missing"))?;
        assert_eq!(nginx_site_id(layout, basename), expected);
        let first_case = fixture
            .get("cases")
            .and_then(Value::as_array)
            .and_then(|cases| cases.first())
            .ok_or_else(|| String::from("fixture first case missing"))?;
        let content = first_case
            .get("availableContent")
            .and_then(Value::as_str)
            .ok_or_else(|| String::from("fixture availableContent missing"))?;
        let available_digest = first_case
            .get("availableDigest")
            .and_then(Value::as_str)
            .ok_or_else(|| String::from("fixture availableDigest missing"))?;
        assert_eq!(sha256_digest(content.as_bytes()), available_digest);
        let before_enabled = first_case
            .get("beforeEnabled")
            .and_then(Value::as_bool)
            .ok_or_else(|| String::from("fixture beforeEnabled missing"))?;
        let state_digest = first_case
            .get("beforeLinkStateDigest")
            .and_then(Value::as_str)
            .ok_or_else(|| String::from("fixture beforeLinkStateDigest missing"))?;
        assert_eq!(nginx_enabled_state_digest(before_enabled), state_digest);
        Ok(())
    }
}
