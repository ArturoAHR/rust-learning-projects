use std::env;
use std::error::Error;
use std::fs;
use std::io;

use dialoguer::Confirm;
use serde_json::Value;

pub struct PasswordManager {
    vault_file_path: String,
    vault_data: Option<Value>,
}

impl PasswordManager {
    pub fn new() -> PasswordManager {
        let vault_file_path =
            env::var("PASSWORD_MANAGER_VAULT_FILE_PATH").unwrap_or("./vault.json".into());

        PasswordManager {
            vault_file_path,
            vault_data: None,
        }
    }

    fn get_vault_data(&self) -> Result<Value, io::Error> {
        if let Some(vault_data) = &self.vault_data {
            return Ok(vault_data.clone());
        }

        let vault_data_raw = fs::read_to_string(&self.vault_file_path)?;

        let vault_data = serde_json::from_str(&vault_data_raw)?;

        // self.vault_data = vault_data;

        Ok(vault_data)
    }

    // fn get_derived_key(&self, master_password: &str) -> Result<(), Box<dyn Error>> {}

    fn reset_vault(&self) -> Result<(), io::Error> {
        fs::remove_file(&self.vault_file_path)?;

        Ok({})
    }

    fn prompt_reset_vault(&self, message: &str) -> Result<(), Box<dyn Error>> {
        let data_reset_confirmation = Confirm::new().with_prompt(message).interact()?;

        if data_reset_confirmation {
            self.reset_vault()?
        }

        Ok({})
    }

    pub fn initialize(&self) -> Result<(), Box<dyn Error>> {
        println!("Verifying if vault file already exists");
        let get_vault_data_result = self.get_vault_data();

        match get_vault_data_result {
            Ok(_database) => {
                self.prompt_reset_vault(
                    "Your vault file already exists, do you wish to reset it?",
                )?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // File is absent, we continue.
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                self.prompt_reset_vault("Your vault file is corrupted, do you wish to reset it?")?;
            }
            Err(e) => return Err(e.into()),
        }

        println!("Proceeding with initialization");

        Ok({})
    }
}
