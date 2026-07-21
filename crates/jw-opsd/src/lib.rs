#![forbid(unsafe_code)]

use jw_contracts::{IPC_PROTOCOL_VERSION, OpsCapabilityRequest, OpsCapabilityResponse};

#[must_use]
pub fn capability_response(
    request: &OpsCapabilityRequest,
    now_unix_ms: i64,
) -> OpsCapabilityResponse {
    let compatible = request.validate(now_unix_ms).is_ok();
    OpsCapabilityResponse {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        read_only: compatible,
        supported_operations: Vec::new(),
        forensic_lockdown: false,
    }
}

#[cfg(test)]
mod tests {
    use jw_contracts::{IPC_PROTOCOL_VERSION, OpsCapabilityRequest};

    use super::capability_response;

    #[test]
    fn current_unexpired_request_is_read_only_and_has_no_operations() {
        let response = capability_response(
            &OpsCapabilityRequest {
                protocol_version: IPC_PROTOCOL_VERSION,
                request_id: String::from("request-1"),
                deadline_unix_ms: 2_000,
            },
            1_000,
        );
        assert!(response.read_only);
        assert!(response.supported_operations.is_empty());
    }

    #[test]
    fn expired_or_incompatible_request_fails_closed() {
        for request in [
            OpsCapabilityRequest {
                protocol_version: IPC_PROTOCOL_VERSION,
                request_id: String::from("request-1"),
                deadline_unix_ms: 1_000,
            },
            OpsCapabilityRequest {
                protocol_version: IPC_PROTOCOL_VERSION.saturating_add(1),
                request_id: String::from("request-2"),
                deadline_unix_ms: 2_000,
            },
        ] {
            assert!(!capability_response(&request, 1_000).read_only);
        }
    }
}
