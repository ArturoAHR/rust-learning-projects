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

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn test_getting_vault_path() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let vault_path = temp_dir.path().join("test_vault.json");
        let vault_path_str = vault_path.to_str().unwrap();

        let vault_file_io = VaultFileIO::new(Some(vault_path_str.into()));

        let vault_file_io_path = vault_file_io.get_vault_path().unwrap();

        assert_eq!(&vault_path_str, vault_file_io_path);
    }

    #[test]
    fn test_creating_vault() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let vault_path = temp_dir.path().join("test_vault.json");
        let vault_path_str = vault_path.to_str().unwrap();

        let vault_file_io = VaultFileIO::new(Some(vault_path_str.into()));

        let _ = vault_file_io.create_vault().unwrap();

        let vault_exists = fs::exists(&vault_path_str).unwrap();

        assert!(vault_exists);
    }

    #[test]
    fn test_deleting_vault() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let vault_path = temp_dir.path().join("test_vault.json");
        let vault_path_str = vault_path.to_str().unwrap();

        let vault_file_io = VaultFileIO::new(Some(vault_path_str.into()));

        let _ = vault_file_io.create_vault().unwrap();
        let _ = vault_file_io.delete_vault().unwrap();

        let vault_exists = fs::exists(&vault_path_str).unwrap();

        assert!(!vault_exists);
    }

    #[test]
    fn test_reading_into_written_vault() {
        let temp_dir = tempdir().expect("Failed to create temp directory");
        let vault_path = temp_dir.path().join("test_vault.json");
        let vault_path_str = vault_path.to_str().unwrap();

        let vault_file_io = VaultFileIO::new(Some(vault_path_str.into()));

        let test_vault_data: Vault = Vault {
            encrypted_data: "test encrypted_data".into(),
            nonce: "test nonce".into(),
            salt: "test salt".into(),
        };

        let _ = vault_file_io.create_vault().unwrap();
        let _ = vault_file_io.write_to_vault(&test_vault_data).unwrap();
        let vault_data_read = vault_file_io.read_vault().unwrap();

        assert_eq!(test_vault_data, vault_data_read);
    }
}
