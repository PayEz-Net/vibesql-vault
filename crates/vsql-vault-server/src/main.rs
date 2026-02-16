use std::sync::Arc;

use axum::{
    middleware as axum_mw,
    routing::{delete, get, head, put},
    Router,
};
use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use tokio::net::TcpListener;
use tower_http::limit::RequestBodyLimitLayer;
use tracing_subscriber::{fmt, EnvFilter};

use vsql_vault_server::api;
use vsql_vault_server::config::Config;
use vsql_vault_server::health;
use vsql_vault_server::middleware::{self, ApiKey};
use vsql_vault_server::pg_storage::PgStorage;
use vsql_vault_server::state::AppState;

#[derive(Parser)]
#[command(
    name = "vsql-vault",
    about = "Governed at-rest vault for encrypted values"
)]
struct Cli {
    #[arg(short, long, default_value = "vsql-vault.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    let config = Config::from_file(std::path::Path::new(&cli.config))?;

    let filter =
        std::env::var("VSQL_VAULT_LOG_LEVEL").unwrap_or_else(|_| config.logging.level.clone());

    match config.logging.format.as_str() {
        "json" => {
            fmt().json().with_env_filter(EnvFilter::new(&filter)).init();
        }
        _ => {
            fmt().with_env_filter(EnvFilter::new(&filter)).init();
        }
    }

    let db_url = std::env::var("VSQL_VAULT_DB_URL").unwrap_or_else(|_| config.database.url.clone());

    let pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .min_connections(config.database.min_connections)
        .connect(&db_url)
        .await?;

    tracing::info!("connected to PostgreSQL");

    sqlx::migrate!("../../migrations").run(&pool).await?;

    tracing::info!("migrations applied");

    let api_key = config.api_key().ok_or("API key not set in environment")?;

    let storage = PgStorage::new(pool.clone());
    let app_state = Arc::new(AppState {
        storage: Box::new(storage),
        max_body_bytes: config.server.max_body_bytes,
    });

    if config.purge.enabled {
        let purge_state = app_state.clone();
        let interval = config.purge.interval_secs;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_secs(interval));
            loop {
                ticker.tick().await;
                match purge_state.storage.purge_expired().await {
                    Ok(0) => {}
                    Ok(n) => tracing::info!(purged = n, "purged expired entries"),
                    Err(e) => tracing::error!(error = %e, "purge failed"),
                }
            }
        });
    }

    // Vault CRUD routes (authenticated)
    let vault_routes = Router::new()
        .route("/{purpose}/{entry_id}", put(api::store_entry))
        .route("/{purpose}/{entry_id}", get(api::retrieve_entry))
        .route("/{purpose}/{entry_id}", delete(api::delete_entry))
        .route("/{purpose}/{entry_id}", head(api::head_entry))
        .route("/{purpose}", get(api::list_entries))
        .layer(axum_mw::from_fn(middleware::auth_middleware));

    // Admin routes (authenticated)
    let admin_routes = Router::new()
        .route("/retention-policies", get(api::list_retention_policies))
        .route(
            "/retention-policies/{purpose}",
            put(api::upsert_retention_policy),
        )
        .route("/access-policies", get(api::list_access_policies))
        .route("/access-policies/{name}", put(api::upsert_access_policy))
        .route("/purge-log", get(api::list_purge_log))
        .layer(axum_mw::from_fn(middleware::auth_middleware));

    let app = Router::new()
        .nest("/v1/vault", vault_routes)
        .nest("/admin", admin_routes)
        .route("/health", get(health::health))
        .route("/health/ready", get(health::ready))
        .layer(RequestBodyLimitLayer::new(config.server.max_body_bytes))
        .layer(axum::Extension(ApiKey(api_key)))
        .with_state(app_state);

    let listener = TcpListener::bind(&config.server.listen_addr).await?;
    tracing::info!(addr = %config.server.listen_addr, "vsql-vault listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    tracing::info!("shutdown signal received");
}
