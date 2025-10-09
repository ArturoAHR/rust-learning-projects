use std::error::Error;

use crate::password_manager::models::{PasswordManagerEntry, Vault};

pub trait VaultIO {
    fn create_vault(&self) -> Result<(), Box<dyn Error>>;
    fn read_vault(&self) -> Result<Vault, Box<dyn Error>>;
    fn write_to_vault(&self, data: &Vault) -> Result<(), Box<dyn Error>>;
}

pub trait VaultEncryptor {
    fn decrypt_vault_entries(&self, password: &str)
    -> Result<PasswordManagerEntry, Box<dyn Error>>;
    fn encrypt_vault_entries(
        &self,
        password: &str,
        entries: &Vec<PasswordManagerEntry>,
    ) -> Result<(), Box<dyn Error>>;
    fn initialize_vault(&self, password: &str) -> Result<(), Box<dyn Error>>;
}
