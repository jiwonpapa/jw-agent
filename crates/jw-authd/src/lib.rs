#![forbid(unsafe_code)]

#[cfg(target_os = "linux")]
use std::ffi::CString;

use ffi_pam::PamError;
#[cfg(target_os = "linux")]
use jw_contracts::Role;
use jw_contracts::{
    AuthFailureClass, AuthRequest, AuthResponse, AuthResult, IPC_PROTOCOL_VERSION, Subject,
};

pub const PAM_SERVICE_NAME: &str = "jw-agent";
pub const ADMIN_GROUP: &str = "jw-agent-admin";
pub const OPERATOR_GROUP: &str = "jw-agent-operator";
pub const VIEWER_GROUP: &str = "jw-agent-viewer";

pub fn authenticate_request(request: &AuthRequest, now_unix_ms: i64) -> AuthResponse {
    let result = if request.protocol_version != IPC_PROTOCOL_VERSION
        || request.validate(now_unix_ms).is_err()
    {
        AuthResult::Failed {
            class: AuthFailureClass::InvalidRequest,
        }
    } else {
        authenticate_validated(request)
    };
    AuthResponse {
        protocol_version: IPC_PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        result,
    }
}

fn authenticate_validated(request: &AuthRequest) -> AuthResult {
    match ffi_pam::authenticate(
        PAM_SERVICE_NAME,
        &request.username,
        request.password.expose(),
        request.remote_address.as_deref(),
    ) {
        Ok(subject) => match resolve_subject(&subject.canonical_username) {
            Ok(subject) => match now_rfc3339() {
                Some(account_validated_at) => AuthResult::Authenticated {
                    subject,
                    account_validated_at,
                },
                None => AuthResult::Failed {
                    class: AuthFailureClass::Unavailable,
                },
            },
            Err(class) => AuthResult::Failed { class },
        },
        Err(error) => AuthResult::Failed {
            class: map_pam_error(error),
        },
    }
}

fn map_pam_error(error: PamError) -> AuthFailureClass {
    match error {
        PamError::AuthenticationFailed | PamError::AccountDenied => AuthFailureClass::Denied,
        PamError::UnsupportedConversation | PamError::UnsupportedPlatform => {
            AuthFailureClass::Unsupported
        }
        PamError::InvalidInput => AuthFailureClass::InvalidRequest,
        PamError::Unavailable => AuthFailureClass::Unavailable,
    }
}

#[cfg(target_os = "linux")]
fn resolve_subject(username: &str) -> Result<Subject, AuthFailureClass> {
    use nix::unistd::{Group, User, getgrouplist};

    let user = User::from_name(username)
        .map_err(|_| AuthFailureClass::Unavailable)?
        .ok_or(AuthFailureClass::Denied)?;
    if user.uid.is_root() {
        return Err(AuthFailureClass::Denied);
    }
    let c_username = CString::new(username).map_err(|_| AuthFailureClass::InvalidRequest)?;
    let groups = getgrouplist(&c_username, user.gid).map_err(|_| AuthFailureClass::Unavailable)?;

    let role_groups = [
        (ADMIN_GROUP, Role::Admin),
        (OPERATOR_GROUP, Role::Operator),
        (VIEWER_GROUP, Role::Viewer),
    ];
    let mut selected_role: Option<Role> = None;
    for (group_name, role) in role_groups {
        let group = Group::from_name(group_name)
            .map_err(|_| AuthFailureClass::Unavailable)?
            .ok_or(AuthFailureClass::Denied)?;
        if groups.contains(&group.gid) {
            if selected_role.is_some() {
                return Err(AuthFailureClass::Denied);
            }
            selected_role = Some(role);
        }
    }
    selected_role
        .map(|role| Subject {
            uid: user.uid.as_raw(),
            username: username.to_owned(),
            role,
        })
        .ok_or(AuthFailureClass::Denied)
}

#[cfg(not(target_os = "linux"))]
fn resolve_subject(_username: &str) -> Result<Subject, AuthFailureClass> {
    Err(AuthFailureClass::Unsupported)
}

fn now_rfc3339() -> Option<String> {
    let now = time::OffsetDateTime::now_utc();
    now.format(&time::format_description::well_known::Rfc3339)
        .ok()
}
