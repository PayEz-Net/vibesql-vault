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
    #[serde(default = "default_mode")]
    pub mode: String,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_secs: u64,
    #[serde(default = "default_max_body_bytes")]
    pub max_body_bytes: usize,
    pub tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
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
        mode: default_mode(),
        request_timeout_secs: default_request_timeout(),
        max_body_bytes: default_max_body_bytes(),
        tls: None,
    }
}

fn default_mode() -> String {
    "dev".into()
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
        config.validate()?;
        Ok(config)
    }

    pub fn from_toml(s: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let config: Config = toml::from_str(s)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), Box<dyn std::error::Error>> {
        match self.server.mode.as_str() {
            "dev" => Ok(()),
            "prod" => {
                let tls = self
                    .server
                    .tls
                    .as_ref()
                    .ok_or("mode = 'prod' requires [server.tls] with cert_path and key_path")?;
                if tls.cert_path.is_empty() {
                    return Err("tls.cert_path must not be empty in prod mode".into());
                }
                if tls.key_path.is_empty() {
                    return Err("tls.key_path must not be empty in prod mode".into());
                }
                Ok(())
            }
            other => {
                Err(format!("unknown server mode: '{other}' (expected 'dev' or 'prod')").into())
            }
        }
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

    #[test]
    fn test_dev_mode_without_tls_ok() {
        let toml_str = r#"
[database]
url = "postgresql://user@localhost/db"

[server]
mode = "dev"
"#;
        let config = Config::from_toml(toml_str).unwrap();
        assert_eq!(config.server.mode, "dev");
        assert!(config.server.tls.is_none());
    }

    #[test]
    fn test_prod_mode_without_tls_errors() {
        let toml_str = r#"
[database]
url = "postgresql://user@localhost/db"

[server]
mode = "prod"
"#;
        let result = Config::from_toml(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("prod"), "error should mention prod: {err}");
    }

    #[test]
    fn test_prod_mode_with_tls_ok() {
        let toml_str = r#"
[database]
url = "postgresql://user@localhost/db"

[server]
mode = "prod"

[server.tls]
cert_path = "/etc/ssl/cert.pem"
key_path = "/etc/ssl/key.pem"
"#;
        let config = Config::from_toml(toml_str).unwrap();
        assert_eq!(config.server.mode, "prod");
        let tls = config.server.tls.unwrap();
        assert_eq!(tls.cert_path, "/etc/ssl/cert.pem");
        assert_eq!(tls.key_path, "/etc/ssl/key.pem");
    }

    #[test]
    fn test_prod_mode_empty_cert_path_errors() {
        let toml_str = r#"
[database]
url = "postgresql://user@localhost/db"

[server]
mode = "prod"

[server.tls]
cert_path = ""
key_path = "/etc/ssl/key.pem"
"#;
        let result = Config::from_toml(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("cert_path"),
            "error should mention cert_path: {err}"
        );
    }

    #[test]
    fn test_unknown_mode_errors() {
        let toml_str = r#"
[database]
url = "postgresql://user@localhost/db"

[server]
mode = "staging"
"#;
        let result = Config::from_toml(toml_str);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("staging"),
            "error should mention the invalid mode: {err}"
        );
    }
}
