#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct OpsPaths {
    pub database: PathBuf,
    pub snapshots: PathBuf,
    pub proposals: PathBuf,
    pub checkpoint: PathBuf,
    pub nginx_available: PathBuf,
    pub nginx_enabled: PathBuf,
    pub letsencrypt_live: PathBuf,
    pub letsencrypt_archive: PathBuf,
    pub letsencrypt_renewal: PathBuf,
    pub certbot_executable: PathBuf,
    pub enforce_root_ownership: bool,
}

impl Default for OpsPaths {
    fn default() -> Self {
        let state = PathBuf::from("/var/lib/jw-agent/opsd");
        Self {
            database: state.join("opsd.sqlite3"),
            snapshots: state.join("snapshots"),
            proposals: state.join("proposals"),
            checkpoint: state.join("ledger.checkpoint"),
            nginx_available: PathBuf::from("/etc/nginx/sites-available"),
            nginx_enabled: PathBuf::from("/etc/nginx/sites-enabled"),
            letsencrypt_live: PathBuf::from("/etc/letsencrypt/live"),
            letsencrypt_archive: PathBuf::from("/etc/letsencrypt/archive"),
            letsencrypt_renewal: PathBuf::from("/etc/letsencrypt/renewal"),
            certbot_executable: PathBuf::from("/usr/bin/certbot"),
            enforce_root_ownership: true,
        }
    }
}

impl OpsPaths {
    #[cfg(test)]
    #[must_use]
    pub fn for_test(root: &Path) -> Self {
        let state = root.join("state");
        Self {
            database: state.join("opsd.sqlite3"),
            snapshots: state.join("snapshots"),
            proposals: state.join("proposals"),
            checkpoint: state.join("ledger.checkpoint"),
            nginx_available: root.join("etc/nginx/sites-available"),
            nginx_enabled: root.join("etc/nginx/sites-enabled"),
            letsencrypt_live: root.join("etc/letsencrypt/live"),
            letsencrypt_archive: root.join("etc/letsencrypt/archive"),
            letsencrypt_renewal: root.join("etc/letsencrypt/renewal"),
            certbot_executable: root.join("usr/bin/certbot"),
            enforce_root_ownership: false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct OpsPolicy {
    pub plan_ttl: Duration,
    pub command_timeout: Duration,
    pub output_cap_bytes: usize,
    pub snapshot_min_free_bytes: u64,
}

impl Default for OpsPolicy {
    fn default() -> Self {
        Self {
            plan_ttl: Duration::from_secs(10 * 60),
            command_timeout: Duration::from_secs(15),
            output_cap_bytes: 64 * 1_024,
            snapshot_min_free_bytes: 4 * 1_024 * 1_024,
        }
    }
}
