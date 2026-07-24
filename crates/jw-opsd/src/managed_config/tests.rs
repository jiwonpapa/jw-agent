use std::fs;

use jw_contracts::{
    APACHE_SITE_CONFIG_ADAPTER_ID, APACHE_SITE_RESOURCE_PREFIX, NGINX_CONFIG_ADAPTER_ID,
    NGINX_MAIN_CONFIG_ADAPTER_ID, NGINX_MAIN_RESOURCE_PREFIX, PHP_FPM_CONFIG_ADAPTER_ID,
    managed_service_config_resource_id, nginx_config_resource_id, php_fpm_config_resource_id,
    php_fpm_pool_config_resource_id,
};

use crate::config::OpsPaths;

use super::{
    cleanup_internal_temporaries, diff_stats, discover_managed_config, replace_managed_config,
};

#[test]
fn discovers_and_atomically_replaces_allowlisted_resource() -> Result<(), String> {
    let root = test_root("replace")?;
    let paths = OpsPaths::for_test(&root);
    fs::create_dir_all(&paths.nginx_available).map_err(|error| error.to_string())?;
    fs::create_dir_all(&paths.nginx_enabled).map_err(|error| error.to_string())?;
    fs::write(paths.nginx_available.join("example.com"), "server {}\n")
        .map_err(|error| error.to_string())?;
    fs::write(
        paths.nginx_available.join(".jw-agent-0123456789abcdef.tmp"),
        "not a resource\n",
    )
    .map_err(|error| error.to_string())?;
    std::os::unix::fs::symlink(
        "../sites-available/example.com",
        paths.nginx_enabled.join("example.com"),
    )
    .map_err(|error| error.to_string())?;
    let id = nginx_config_resource_id(NGINX_CONFIG_ADAPTER_ID, "example.com");
    let before = discover_managed_config(&paths, &id).map_err(|error| error.to_string())?;
    let after = replace_managed_config(&paths, &before, "server { listen 8080; }\n")
        .map_err(|error| error.to_string())?;
    assert_eq!(after.content, "server { listen 8080; }\n");
    assert_ne!(before.content_digest, after.content_digest);
    fs::remove_dir_all(root).map_err(|error| error.to_string())
}

#[test]
fn diff_summary_is_bounded_and_directional() {
    let stats = diff_stats("a\nb\nc\n", "a\nx\nc\n");
    assert_eq!(stats.removed_lines, 1);
    assert_eq!(stats.added_lines, 1);
    assert_eq!(stats.summary, vec![String::from("-b"), String::from("+x")]);
}

#[test]
fn discovers_and_replaces_php_fpm_php_ini_without_widening_nginx_profile() -> Result<(), String> {
    let root = test_root("php-fpm-replace")?;
    let paths = OpsPaths::for_test(&root);
    let parent = paths
        .php_fpm_ini
        .parent()
        .ok_or_else(|| String::from("php parent missing"))?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    fs::write(&paths.php_fpm_ini, "memory_limit = 128M\n").map_err(|error| error.to_string())?;
    let id = php_fpm_config_resource_id(PHP_FPM_CONFIG_ADAPTER_ID);
    let before = discover_managed_config(&paths, &id).map_err(|error| error.to_string())?;
    assert_eq!(before.adapter.adapter_id(), PHP_FPM_CONFIG_ADAPTER_ID);
    let after = replace_managed_config(&paths, &before, "memory_limit = 256M\n")
        .map_err(|error| error.to_string())?;
    assert_eq!(after.content, "memory_limit = 256M\n");
    assert_eq!(after.root, parent);
    fs::remove_dir_all(root).map_err(|error| error.to_string())
}

#[test]
fn discovers_nginx_main_config_by_stable_resource_id() -> Result<(), String> {
    let root = test_root("nginx-main")?;
    let paths = OpsPaths::for_test(&root);
    let parent = paths
        .nginx_main
        .parent()
        .ok_or_else(|| String::from("nginx parent missing"))?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    fs::write(&paths.nginx_main, "events {}\nhttp {}\n").map_err(|error| error.to_string())?;
    let id = managed_service_config_resource_id(
        NGINX_MAIN_RESOURCE_PREFIX,
        NGINX_MAIN_CONFIG_ADAPTER_ID,
        "nginx.conf",
    );

    let resource = discover_managed_config(&paths, &id).map_err(|error| error.to_string())?;

    assert_eq!(resource.adapter.adapter_id(), NGINX_MAIN_CONFIG_ADAPTER_ID);
    assert_eq!(resource.basename, "nginx.conf");
    fs::remove_dir_all(root).map_err(|error| error.to_string())
}

#[test]
fn apache_site_requires_exact_enabled_symlink() -> Result<(), String> {
    let root = test_root("apache-site")?;
    let paths = OpsPaths::for_test(&root);
    fs::create_dir_all(&paths.apache_sites_available).map_err(|error| error.to_string())?;
    fs::create_dir_all(&paths.apache_sites_enabled).map_err(|error| error.to_string())?;
    fs::write(
        paths.apache_sites_available.join("example.conf"),
        "<VirtualHost *:80></VirtualHost>\n",
    )
    .map_err(|error| error.to_string())?;
    let id = managed_service_config_resource_id(
        APACHE_SITE_RESOURCE_PREFIX,
        APACHE_SITE_CONFIG_ADAPTER_ID,
        "example.conf",
    );
    let inactive = match discover_managed_config(&paths, &id) {
        Ok(_) => return Err(String::from("disabled Apache site was editable")),
        Err(error) => error,
    };
    assert_eq!(inactive.code(), "resource_not_active");

    std::os::unix::fs::symlink(
        "../sites-available/example.conf",
        paths.apache_sites_enabled.join("example.conf"),
    )
    .map_err(|error| error.to_string())?;
    let active = discover_managed_config(&paths, &id).map_err(|error| error.to_string())?;
    assert_eq!(active.adapter.adapter_id(), APACHE_SITE_CONFIG_ADAPTER_ID);

    fs::remove_file(paths.apache_sites_enabled.join("example.conf"))
        .map_err(|error| error.to_string())?;
    std::os::unix::fs::symlink(
        "../sites-available/other.conf",
        paths.apache_sites_enabled.join("example.conf"),
    )
    .map_err(|error| error.to_string())?;
    let mismatched = match discover_managed_config(&paths, &id) {
        Ok(_) => return Err(String::from("mismatched Apache link was editable")),
        Err(error) => error,
    };
    assert_eq!(mismatched.code(), "enabled_target_mismatch");
    fs::remove_dir_all(root).map_err(|error| error.to_string())
}

#[test]
fn discovers_each_php_fpm_pool_as_its_own_resource() -> Result<(), String> {
    let root = test_root("php-fpm-pool")?;
    let paths = OpsPaths::for_test(&root);
    fs::create_dir_all(&paths.php_fpm_pool_dir).map_err(|error| error.to_string())?;
    fs::write(
        paths.php_fpm_pool_dir.join("shop.conf"),
        "[shop]\nlisten = /run/php/shop.sock\n",
    )
    .map_err(|error| error.to_string())?;
    let id = php_fpm_pool_config_resource_id("shop.conf");

    let resource = discover_managed_config(&paths, &id).map_err(|error| error.to_string())?;

    assert_eq!(resource.basename, "shop.conf");
    assert_eq!(resource.resource_id, id);
    fs::remove_dir_all(root).map_err(|error| error.to_string())
}

#[test]
fn removes_only_exact_internal_temporary_files() -> Result<(), String> {
    let root = test_root("cleanup-temp")?;
    let paths = OpsPaths::for_test(&root);
    fs::create_dir_all(&paths.nginx_available).map_err(|error| error.to_string())?;
    let temporary = paths.nginx_available.join(".jw-agent-0123456789abcdef.tmp");
    let ordinary = paths.nginx_available.join(".jw-agent-example.com.tmp");
    fs::write(&temporary, "pending").map_err(|error| error.to_string())?;
    fs::write(&ordinary, "owned elsewhere").map_err(|error| error.to_string())?;
    cleanup_internal_temporaries(&paths).map_err(|error| error.to_string())?;
    assert!(!temporary.exists());
    assert!(ordinary.exists());
    fs::remove_dir_all(root).map_err(|error| error.to_string())
}

fn test_root(label: &str) -> Result<std::path::PathBuf, String> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| error.to_string())?;
    Ok(std::env::temp_dir().join(format!(
        "jw-opsd-managed-{label}-{}-{}",
        std::process::id(),
        u64::from_le_bytes(random)
    )))
}
