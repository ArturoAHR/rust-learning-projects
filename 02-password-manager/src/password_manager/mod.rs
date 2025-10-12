pub mod manager_prompter;
mod models;
mod traits;
pub mod vault_encryption;
pub mod vault_file_io;

use std::error::Error;
use std::io;
use std::thread;
use std::time::Duration;
use std::u32;

use arboard::Clipboard;

use crate::password_manager::models::PasswordManagerEntry;
use crate::password_manager::traits::Prompter;
use crate::password_manager::traits::VaultEncryptor;
use crate::password_manager::traits::VaultIO;

pub struct PasswordManager<'a, T: VaultEncryptor, U: VaultIO, V: Prompter> {
    vault_encryptor: &'a T,
    vault_io: &'a U,
    prompter: &'a V,
}

impl<'a, T: VaultEncryptor, U: VaultIO, V: Prompter> PasswordManager<'a, T, U, V> {
    pub fn new(vault_encryptor: &'a T, vault_io: &'a U, prompter: &'a V) -> Self {
        PasswordManager {
            vault_io,
            vault_encryptor,
            prompter,
        }
    }

    fn prompt_reset_vault(&self, message: &str) -> Result<(), Box<dyn Error>> {
        let data_reset_confirmation = self.prompter.prompt_confirmation(message)?;

        if data_reset_confirmation {
            self.vault_io.delete_vault()?;
        } else {
            return Err("Vault file already exists.".into());
        }

        Ok(())
    }

    fn prompt_master_password_setup(&self) -> Result<String, Box<dyn Error>> {
        loop {
            println!("Please enter your master password:");
            let password = self.prompter.prompt_password()?;

            println!("Enter your master password again to confirm:");
            let repeated_password = self.prompter.prompt_password()?;

            if password == repeated_password {
                return Ok(password.clone());
            }

            println!("The passwords do not match, repeating the process");
        }
    }

    fn prompt_master_password(&self) -> Result<String, Box<dyn Error>> {
        println!("Please enter your master password:");
        let password = self.prompter.prompt_password()?;

        return Ok(password.clone());
    }

    pub fn list_password_ids(&mut self) -> Result<(), Box<dyn Error>> {
        let password = self.prompt_master_password()?;

        let vault_data = self.vault_io.read_vault()?;

        let entries = self
            .vault_encryptor
            .decrypt_vault_entries(&password, &vault_data)?;

        println!("List of password IDs:");
        for (index, entry) in entries.iter().enumerate() {
            println!("{} - {}", index + 1, entry.id);
        }

        Ok(())
    }

    pub fn add_password_entry(&mut self, entry_id: &str) -> Result<(), Box<dyn Error>> {
        let password = self.prompt_master_password()?;

        let vault_data = self.vault_io.read_vault()?;

        let mut entries = self
            .vault_encryptor
            .decrypt_vault_entries(&password, &vault_data)?;

        for entry in entries.iter() {
            if entry.id.as_str() == entry_id {
                return Err("Entry ID already exists in Vault".into());
            }
        }

        println!("Introduce the password tied to this entry:");
        let entry_password = self.prompter.prompt_password()?;

        entries.push(PasswordManagerEntry {
            id: entry_id.trim().into(),
            password: entry_password,
        });

        let encrypted_vault = self
            .vault_encryptor
            .encrypt_vault_entries(&password, &entries)?;

        let _ = self.vault_io.write_to_vault(&encrypted_vault);

        Ok(())
    }

    pub fn get_password(&mut self, entry_id: &str) -> Result<(), Box<dyn Error>> {
        let mut clipboard = Clipboard::new()?;
        let password = self.prompt_master_password()?;

        let vault_data = self.vault_io.read_vault()?;

        let entries = self
            .vault_encryptor
            .decrypt_vault_entries(&password, &vault_data)?;

        let password_id = &entry_id.trim();
        let mut password_index: Option<u32> = None;

        let parse_password_id_to_index_result = entry_id.trim().parse::<u32>();
        if let Ok(index) = parse_password_id_to_index_result {
            password_index = Some(index);
        }

        let mut selected_entry: Option<&PasswordManagerEntry> = None;
        for entry in entries.iter() {
            if entry.id.as_str() == *password_id {
                selected_entry = Some(&entry);
                break;
            }
        }

        if selected_entry.is_none() {
            if let Some(searched_index) = password_index {
                for (index, entry) in entries.iter().enumerate() {
                    if (index + 1) as u64 == searched_index as u64 {
                        selected_entry = Some(&entry);
                    }
                }
            }
        }

        if let Some(entry) = &selected_entry {
            clipboard.set_text(&entry.password)?;
            thread::sleep(Duration::from_millis(10));

            println!("The password has been copied to your clipboard")
        }

        if selected_entry.is_none() {
            println!("There is no password with id {entry_id}")
        }

        Ok(())
    }

    pub fn initialize(&mut self) -> Result<(), Box<dyn Error>> {
        println!("Verifying if vault file already exists");
        let get_vault_data_result = self.vault_io.read_vault();

        match get_vault_data_result {
            Ok(_database) => {
                self.prompt_reset_vault(
                    "Your vault file already exists, do you wish to reset it?",
                )?;
            }
            Err(error)
                if matches!(error.downcast_ref::<io::Error>(), Some(_))
                    && error.downcast_ref::<io::Error>().unwrap().kind()
                        == io::ErrorKind::NotFound =>
            {
                // File is absent, we continue.
            }
            Err(error)
                if matches!(error.downcast_ref::<io::Error>(), Some(_))
                    && error.downcast_ref::<io::Error>().unwrap().kind()
                        == io::ErrorKind::InvalidData =>
            {
                self.prompt_reset_vault("Your vault file is corrupted, do you wish to reset it?")?;
            }
            Err(e) => return Err(e.into()),
        }

        println!("Proceeding with initialization");

        let password = self.prompt_master_password_setup()?;

        self.vault_io.create_vault()?;

        let encrypted_vault = self
            .vault_encryptor
            .encrypt_vault_entries(&password, &Vec::new())?;

        let _ = self.vault_io.write_to_vault(&encrypted_vault);

        println!(
            "Vault has been created successfully at {}",
            &self.vault_io.get_vault_path()?
        );

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::password_manager::models::Vault;

    use super::*;

    struct MockVaultEncryptor {}
    struct MockVaultIO {
        vault_path: String,
        vault_data: Vault,
    }
    struct MockPrompter {
        password: String,
        confirmation: bool,
    }

    impl VaultEncryptor for MockVaultEncryptor {
        fn encrypt_vault_entries(
            &self,
            _password: &str,
            entries: &Vec<PasswordManagerEntry>,
        ) -> Result<models::Vault, Box<dyn Error>> {
            let entries_json = serde_json::to_string_pretty(entries)?;

            Ok(Vault {
                encrypted_data: entries_json.into(),
                nonce: "".into(),
                salt: "".into(),
            })
        }

        fn decrypt_vault_entries(
            &self,
            _password: &str,
            vault_data: &models::Vault,
        ) -> Result<Vec<PasswordManagerEntry>, Box<dyn Error>> {
            let entries: Vec<PasswordManagerEntry> =
                serde_json::from_str(&vault_data.encrypted_data)?;

            Ok(entries)
        }
    }

    impl VaultIO for MockVaultIO {
        fn create_vault(&self) -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        fn delete_vault(&self) -> Result<(), Box<dyn Error>> {
            Ok(())
        }

        fn get_vault_path(&self) -> Result<&String, Box<dyn Error>> {
            Ok(&self.vault_path)
        }

        fn read_vault(&self) -> Result<Vault, Box<dyn Error>> {
            Ok(self.vault_data.clone())
        }

        fn write_to_vault(&self, _data: &Vault) -> Result<(), Box<dyn Error>> {
            Ok(())
        }
    }

    impl Prompter for MockPrompter {
        fn prompt_password(&self) -> Result<String, Box<dyn Error>> {
            Ok(self.password.clone())
        }

        fn prompt_confirmation(&self, _message: &str) -> Result<bool, Box<dyn Error>> {
            Ok(self.confirmation)
        }
    }

    fn generate_vault_data(entries: &Vec<PasswordManagerEntry>) -> Vault {
        Vault {
            encrypted_data: serde_json::to_string_pretty(entries).unwrap().into(),
            nonce: "".into(),
            salt: "".into(),
        }
    }

    #[test]
    fn test_listing_passwords() {
        let mock_entries = vec![PasswordManagerEntry {
            id: "".into(),
            password: "".into(),
        }];
        let vault_data = generate_vault_data(&mock_entries);

        let mock_vault_encryptor = MockVaultEncryptor {};
        let mock_vault_io = MockVaultIO {
            vault_data,
            vault_path: "vault-path".into(),
        };
        let mock_prompter = MockPrompter {
            password: "test-password".into(),
            confirmation: true,
        };

        let mut password_manager =
            PasswordManager::new(&mock_vault_encryptor, &mock_vault_io, &mock_prompter);

        let _ = password_manager.list_password_ids().unwrap();
    }

    #[test]
    fn test_getting_password() {
        let mock_entries = vec![PasswordManagerEntry {
            id: "id-1".into(),
            password: "test-1".into(),
        }];
        let vault_data = generate_vault_data(&mock_entries);

        let mock_vault_encryptor = MockVaultEncryptor {};
        let mock_vault_io = MockVaultIO {
            vault_data,
            vault_path: "vault-path".into(),
        };
        let mock_prompter = MockPrompter {
            password: "test-password".into(),
            confirmation: true,
        };

        let mut password_manager =
            PasswordManager::new(&mock_vault_encryptor, &mock_vault_io, &mock_prompter);

        let _ = password_manager.get_password("id-1").unwrap();
    }

    #[test]
    fn test_getting_non_existent_password() {
        let mock_entries = vec![PasswordManagerEntry {
            id: "id-1".into(),
            password: "test-1".into(),
        }];
        let vault_data = generate_vault_data(&mock_entries);

        let mock_vault_encryptor = MockVaultEncryptor {};
        let mock_vault_io = MockVaultIO {
            vault_data,
            vault_path: "vault-path".into(),
        };
        let mock_prompter = MockPrompter {
            password: "test-password".into(),
            confirmation: true,
        };

        let mut password_manager =
            PasswordManager::new(&mock_vault_encryptor, &mock_vault_io, &mock_prompter);

        let _ = password_manager.get_password("id-2").unwrap();
    }

    #[test]
    fn test_adding_password() {
        let mock_entries = vec![PasswordManagerEntry {
            id: "id-1".into(),
            password: "test-1".into(),
        }];
        let vault_data = generate_vault_data(&mock_entries);

        let mock_vault_encryptor = MockVaultEncryptor {};
        let mock_vault_io = MockVaultIO {
            vault_data,
            vault_path: "vault-path".into(),
        };
        let mock_prompter = MockPrompter {
            password: "test-password".into(),
            confirmation: true,
        };

        let mut password_manager =
            PasswordManager::new(&mock_vault_encryptor, &mock_vault_io, &mock_prompter);

        let _ = password_manager.add_password_entry("id-2").unwrap();
    }

    #[test]
    #[should_panic]
    fn test_adding_password_with_existing_password_id() {
        let mock_entries = vec![PasswordManagerEntry {
            id: "id-1".into(),
            password: "test-1".into(),
        }];
        let vault_data = generate_vault_data(&mock_entries);

        let mock_vault_encryptor = MockVaultEncryptor {};
        let mock_vault_io = MockVaultIO {
            vault_data,
            vault_path: "vault-path".into(),
        };
        let mock_prompter = MockPrompter {
            password: "test-password".into(),
            confirmation: true,
        };

        let mut password_manager =
            PasswordManager::new(&mock_vault_encryptor, &mock_vault_io, &mock_prompter);

        let _ = password_manager.add_password_entry("id-1".into()).unwrap();
    }

    #[test]
    fn test_initialize_manager() {
        let mock_entries = vec![PasswordManagerEntry {
            id: "id-1".into(),
            password: "test-1".into(),
        }];
        let vault_data = generate_vault_data(&mock_entries);

        let mock_vault_encryptor = MockVaultEncryptor {};
        let mock_vault_io = MockVaultIO {
            vault_data,
            vault_path: "vault-path".into(),
        };
        let mock_prompter = MockPrompter {
            password: "test-password".into(),
            confirmation: true,
        };

        let mut password_manager =
            PasswordManager::new(&mock_vault_encryptor, &mock_vault_io, &mock_prompter);

        let _ = password_manager.initialize().unwrap();
    }
}
