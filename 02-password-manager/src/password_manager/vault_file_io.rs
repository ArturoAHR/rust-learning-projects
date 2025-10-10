use std::{env, error::Error, fs, io::Write};

use crate::password_manager::{models::Vault, traits::VaultIO};

pub struct VaultFileIO {
    vault_path: String,
}

impl VaultFileIO {
    pub fn new(user_vault_path: Option<String>) -> Self {
        let default_path =
            env::var("PASSWORD_MANAGER_VAULT_FILE_PATH").unwrap_or("./vault.json".into());

        let resolved_path = user_vault_path.unwrap_or(default_path);

        VaultFileIO {
            vault_path: resolved_path,
        }
    }
}

impl VaultIO for VaultFileIO {
    fn get_vault_path(&self) -> Result<&String, Box<dyn Error>> {
        Ok(&self.vault_path)
    }

    fn create_vault(&self) -> Result<(), Box<dyn Error>> {
        fs::File::create(&self.vault_path)?;

        Ok(())
    }

    fn read_vault(&self) -> Result<Vault, Box<dyn Error>> {
        let vault_data_raw = fs::read_to_string(&self.vault_path)?;

        let vault_data_parse_result = serde_json::from_str(&vault_data_raw);

        match vault_data_parse_result {
            Ok(vault_data) => Ok(vault_data),
            Err(error) => Err(Box::new(error) as Box<dyn Error>),
        }
    }

    fn write_to_vault(&self, data: &Vault) -> Result<(), Box<dyn Error>> {
        let mut vault_file = fs::OpenOptions::new().write(true).open(&self.vault_path)?;

        let vault_json = serde_json::to_string_pretty(&data)?;

        vault_file.write_all(&vault_json.as_bytes())?;
        vault_file.flush()?;

        Ok(())
    }

    fn delete_vault(&self) -> Result<(), Box<dyn Error>> {
        fs::remove_file(&self.vault_path)?;

        Ok(())
    }
}
