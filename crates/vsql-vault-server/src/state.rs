use vsql_vault_core::storage::VaultStorage;

pub struct AppState {
    pub storage: Box<dyn VaultStorage>,
    pub max_body_bytes: usize,
}
