use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use jw_contracts::{AdditionalAuthPolicy, IngressChannel, ReauthPurpose, Role, Subject};

use crate::session::{OperationClaimError, PolicyUpdateError, SessionStore};

#[test]
fn policy_update_requires_admin_reauth_and_ready_provider() -> Result<(), String> {
    let path = test_path()?;
    let store = SessionStore::open(path.clone(), 1_000)?;
    let admin = Subject {
        uid: 1_000,
        username: String::from("admin"),
        role: Role::Admin,
    };
    let issued = store.issue_session(&admin, IngressChannel::Recovery, 1_000)?;
    let target = AdditionalAuthPolicy::Disabled;
    assert!(matches!(
        store.update_additional_auth_policy(issued.token(), &admin, target, None, 2_000),
        Err(PolicyUpdateError::ReauthRequired)
    ));

    let claim = store.issue_reauth_claim(
        issued.token(),
        &admin,
        &ReauthPurpose::SecurityPolicyChange {
            target_policy: target,
        },
        2_000,
    )?;
    store
        .update_additional_auth_policy(issued.token(), &admin, target, Some(claim.token()), 2_001)
        .map_err(|error| format!("first policy update failed: {error:?}"))?;
    assert_eq!(store.additional_auth_policy()?, target);
    assert!(matches!(
        store.update_additional_auth_policy(
            issued.token(),
            &admin,
            target,
            Some(claim.token()),
            2_002,
        ),
        Err(PolicyUpdateError::InvalidReauth)
    ));
    assert!(matches!(
        store.update_additional_auth_policy(
            issued.token(),
            &admin,
            AdditionalAuthPolicy::RiskyOperations,
            None,
            2_003,
        ),
        Err(PolicyUpdateError::ProviderUnavailable)
    ));
    cleanup_test_database(&path)
}

#[test]
fn operation_claim_is_bound_to_session_uid_and_plan() -> Result<(), String> {
    let path = test_path()?;
    let store = SessionStore::open(path.clone(), 1_000)?;
    let subject = Subject {
        uid: 1_000,
        username: String::from("admin"),
        role: Role::Admin,
    };
    let session = store.issue_session(&subject, IngressChannel::Public, 1_000)?;
    let plan_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let purpose = ReauthPurpose::Operation {
        plan_hash: String::from(plan_hash),
    };
    let claim = store.issue_reauth_claim(session.token(), &subject, &purpose, 1_100)?;
    store
        .consume_operation_claim(session.token(), &subject, plan_hash, claim.token(), 1_200)
        .map_err(|error| format!("{error:?}"))?;
    assert!(matches!(
        store.consume_operation_claim(session.token(), &subject, plan_hash, claim.token(), 1_300,),
        Err(OperationClaimError::Invalid)
    ));
    cleanup_test_database(&path)
}

fn test_path() -> Result<PathBuf, String> {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_nanos();
    Ok(std::env::temp_dir().join(format!("jw-agent-session-additional-{suffix}.sqlite3")))
}

fn cleanup_test_database(path: &Path) -> Result<(), String> {
    for candidate in [
        path.to_path_buf(),
        path.with_extension("totp.key"),
        path.with_extension("sqlite3-wal"),
        path.with_extension("sqlite3-shm"),
    ] {
        match fs::remove_file(candidate) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}
