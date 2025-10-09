use std::error::Error;

use crate::password_manager::{models::Vault, traits::VaultIO};

pub struct VaultFileIO {
    vault_path: String,
}

impl VaultFileIO {
    pub fn new(vault_path: String) -> Self {
        VaultFileIO { vault_path }
    }
}

impl VaultIO for VaultFileIO {
    fn create_vault(&self) -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
    fn read_vault(&self) -> Result<Vault, Box<dyn Error>> {
        unimplemented!()
    }
    fn write_to_vault(&self, data: &Vault) -> Result<(), Box<dyn Error>> {
        unimplemented!()
    }
}
