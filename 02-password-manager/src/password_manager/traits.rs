use std::error::Error;

use crate::password_manager::models::{PasswordManagerEntry, Vault};

pub trait VaultIO {
    fn create_vault(&self) -> Result<(), Box<dyn Error>>;
    fn read_vault(&self) -> Result<Vault, Box<dyn Error>>;
    fn write_to_vault(&self, data: &Vault) -> Result<(), Box<dyn Error>>;
    fn delete_vault(&self) -> Result<(), Box<dyn Error>>;
    fn get_vault_path(&self) -> Result<&String, Box<dyn Error>>;
}

pub trait VaultEncryptor {
    fn decrypt_vault_entries(
        &self,
        password: &str,
        vault_data: &Vault,
    ) -> Result<Vec<PasswordManagerEntry>, Box<dyn Error>>;
    fn encrypt_vault_entries(
        &self,
        password: &str,
        entries: &Vec<PasswordManagerEntry>,
    ) -> Result<Vault, Box<dyn Error>>;
}

pub trait Prompter {
    fn prompt_confirmation(&self, message: &str) -> Result<bool, Box<dyn Error>>;
    fn prompt_password(&self) -> Result<String, Box<dyn Error>>;
}
