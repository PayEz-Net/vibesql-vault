use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default = "default_server")]
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub purge: PurgeConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
    #[serde(default = "default_min_connections")]
    pub min_connections: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PurgeConfig {
    #[serde(default = "default_purge_enabled")]
    pub enabled: bool,
    #[serde(default = "default_purge_interval")]
    pub interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

fn default_server() -> ServerConfig {
    ServerConfig {
        listen_addr: default_listen_addr(),
        request_timeout_secs: default_request_timeout(),
        max_body_bytes: default_max_body_bytes(),
    }
}

fn default_listen_addr() -> String {
    "127.0.0.1:8420".into()
}
fn default_request_timeout() -> u64 {
    30
}
fn default_max_body_bytes() -> usize {
    1_048_576
}
fn default_max_connections() -> u32 {
    20
}
fn default_min_connections() -> u32 {
    2
}
fn default_api_key_env() -> String {
    "VSQL_VAULT_API_KEY".into()
}
fn default_purge_enabled() -> bool {
    true
}
fn default_purge_interval() -> u64 {
    3600
}
fn default_log_level() -> String {
    "info".into()
}
fn default_log_format() -> String {
    "json".into()
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            api_key_env: default_api_key_env(),
        }
    }
}

impl Default for PurgeConfig {
    fn default() -> Self {
        Self {
            enabled: default_purge_enabled(),
            interval_secs: default_purge_interval(),
        }
    }
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn database_url(&self) -> &str {
        &self.database.url
    }

    pub fn api_key(&self) -> Option<String> {
        std::env::var(&self.auth.api_key_env).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let toml_str = r#"
[database]
url = "postgresql://user@localhost/db"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.database.url, "postgresql://user@localhost/db");
        assert_eq!(config.server.listen_addr, "127.0.0.1:8420");
        assert_eq!(config.server.max_body_bytes, 1_048_576);
        assert_eq!(config.database.max_connections, 20);
        assert!(config.purge.enabled);
    }

    #[test]
    fn test_parse_full_config() {
        let toml_str = r#"
[server]
listen_addr = "0.0.0.0:9000"
request_timeout_secs = 60
max_body_bytes = 2097152

[database]
url = "postgresql://vault@db:5432/vault"
max_connections = 50
min_connections = 5

[auth]
api_key_env = "MY_KEY"

[purge]
enabled = false
interval_secs = 7200

[logging]
level = "debug"
format = "text"
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.server.listen_addr, "0.0.0.0:9000");
        assert_eq!(config.server.max_body_bytes, 2_097_152);
        assert_eq!(config.database.max_connections, 50);
        assert_eq!(config.auth.api_key_env, "MY_KEY");
        assert!(!config.purge.enabled);
        assert_eq!(config.logging.level, "debug");
    }
}
