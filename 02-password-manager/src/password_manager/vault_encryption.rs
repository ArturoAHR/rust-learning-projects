use std::error::Error;

use crate::password_manager::{
    models::PasswordManagerEntry,
    traits::{VaultEncryptor, VaultIO},
};

pub struct VaultEncryption<IO: VaultIO> {
    vault_io: IO,
}

impl<IO: VaultIO> VaultEncryption<IO> {
    pub fn new(vault_io_service: IO) -> Self {
        VaultEncryption {
            vault_io: vault_io_service,
        }
    }
}

impl<IO: VaultIO> VaultEncryptor for VaultEncryption<IO> {
    fn decrypt_vault_entries(
        &self,
        password: &str,
    ) -> Result<PasswordManagerEntry, Box<dyn Error>> {
        unimplemented!()
    }
    fn encrypt_vault_entries(
        &self,
        password: &str,
        entries: &Vec<PasswordManagerEntry>,
    ) -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
    fn initialize_vault(&self, password: &str) -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
}
