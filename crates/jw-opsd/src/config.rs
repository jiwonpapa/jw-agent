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
    pub nginx_main: PathBuf,
    pub nginx_conf_d: PathBuf,
    pub nginx_available: PathBuf,
    pub nginx_enabled: PathBuf,
    pub apache_main: PathBuf,
    pub apache_ports: PathBuf,
    pub apache_conf_available: PathBuf,
    pub apache_conf_enabled: PathBuf,
    pub apache_sites_available: PathBuf,
    pub apache_sites_enabled: PathBuf,
    pub php_fpm_ini: PathBuf,
    pub php_fpm_global: PathBuf,
    pub php_fpm_pool_www: PathBuf,
    pub php_fpm_pool_dir: PathBuf,
    pub letsencrypt_live: PathBuf,
    pub letsencrypt_archive: PathBuf,
    pub letsencrypt_renewal: PathBuf,
    pub acme_webroot: PathBuf,
    pub certbot_executable: PathBuf,
    pub ufw_executable: PathBuf,
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
            nginx_main: PathBuf::from("/etc/nginx/nginx.conf"),
            nginx_conf_d: PathBuf::from("/etc/nginx/conf.d"),
            nginx_available: PathBuf::from("/etc/nginx/sites-available"),
            nginx_enabled: PathBuf::from("/etc/nginx/sites-enabled"),
            apache_main: PathBuf::from("/etc/apache2/apache2.conf"),
            apache_ports: PathBuf::from("/etc/apache2/ports.conf"),
            apache_conf_available: PathBuf::from("/etc/apache2/conf-available"),
            apache_conf_enabled: PathBuf::from("/etc/apache2/conf-enabled"),
            apache_sites_available: PathBuf::from("/etc/apache2/sites-available"),
            apache_sites_enabled: PathBuf::from("/etc/apache2/sites-enabled"),
            php_fpm_ini: PathBuf::from("/etc/php/8.3/fpm/php.ini"),
            php_fpm_global: PathBuf::from("/etc/php/8.3/fpm/php-fpm.conf"),
            php_fpm_pool_www: PathBuf::from("/etc/php/8.3/fpm/pool.d/www.conf"),
            php_fpm_pool_dir: PathBuf::from("/etc/php/8.3/fpm/pool.d"),
            letsencrypt_live: PathBuf::from("/etc/letsencrypt/live"),
            letsencrypt_archive: PathBuf::from("/etc/letsencrypt/archive"),
            letsencrypt_renewal: PathBuf::from("/etc/letsencrypt/renewal"),
            acme_webroot: PathBuf::from("/var/lib/jw-agent/acme-webroot"),
            certbot_executable: PathBuf::from("/usr/bin/certbot"),
            ufw_executable: PathBuf::from("/usr/sbin/ufw"),
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
            nginx_main: root.join("etc/nginx/nginx.conf"),
            nginx_conf_d: root.join("etc/nginx/conf.d"),
            nginx_available: root.join("etc/nginx/sites-available"),
            nginx_enabled: root.join("etc/nginx/sites-enabled"),
            apache_main: root.join("etc/apache2/apache2.conf"),
            apache_ports: root.join("etc/apache2/ports.conf"),
            apache_conf_available: root.join("etc/apache2/conf-available"),
            apache_conf_enabled: root.join("etc/apache2/conf-enabled"),
            apache_sites_available: root.join("etc/apache2/sites-available"),
            apache_sites_enabled: root.join("etc/apache2/sites-enabled"),
            php_fpm_ini: root.join("etc/php/8.3/fpm/php.ini"),
            php_fpm_global: root.join("etc/php/8.3/fpm/php-fpm.conf"),
            php_fpm_pool_www: root.join("etc/php/8.3/fpm/pool.d/www.conf"),
            php_fpm_pool_dir: root.join("etc/php/8.3/fpm/pool.d"),
            letsencrypt_live: root.join("etc/letsencrypt/live"),
            letsencrypt_archive: root.join("etc/letsencrypt/archive"),
            letsencrypt_renewal: root.join("etc/letsencrypt/renewal"),
            acme_webroot: root.join("var/lib/jw-agent/acme-webroot"),
            certbot_executable: root.join("usr/bin/certbot"),
            ufw_executable: root.join("usr/sbin/ufw"),
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
