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
use dialoguer::Confirm;

use crate::password_manager::models::PasswordManagerEntry;
use crate::password_manager::traits::VaultEncryptor;
use crate::password_manager::traits::VaultIO;

pub struct PasswordManager<'a, T: VaultEncryptor, U: VaultIO> {
    vault_encryptor: &'a T,
    vault_io: &'a U,
}

impl<'a, T: VaultEncryptor, U: VaultIO> PasswordManager<'a, T, U> {
    pub fn new(vault_encryptor: &'a T, vault_io: &'a U) -> Self {
        PasswordManager {
            vault_io,
            vault_encryptor,
        }
    }

    fn prompt_reset_vault(&self, message: &str) -> Result<(), Box<dyn Error>> {
        let data_reset_confirmation = Confirm::new().with_prompt(message).interact()?;

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
            let password = rpassword::read_password()?;

            println!("Enter your master password again to confirm:");
            let repeated_password = rpassword::read_password()?;

            if password == repeated_password {
                return Ok(password.clone());
            }

            println!("The passwords do not match, repeating the process");
        }
    }

    fn prompt_master_password(&self) -> Result<String, Box<dyn Error>> {
        println!("Please enter your master password:");
        let password = rpassword::read_password()?;

        return Ok(password.clone());
    }

    pub fn list_password_ids(&mut self) -> Result<(), Box<dyn Error>> {
        let password = self.prompt_master_password()?;

        let entries = self.vault_encryptor.decrypt_vault_entries(&password)?;

        println!("List of password IDs:");
        for (index, entry) in entries.iter().enumerate() {
            println!("{} - {}", index + 1, entry.id);
        }

        Ok(())
    }

    pub fn add_password_entry(&mut self, entry_id: &str) -> Result<(), Box<dyn Error>> {
        let password = self.prompt_master_password()?;

        let mut entries = self.vault_encryptor.decrypt_vault_entries(&password)?;

        println!("Introduce the password tied to this entry:");
        let entry_password = rpassword::read_password()?;

        entries.push(PasswordManagerEntry {
            id: entry_id.trim().into(),
            password: entry_password,
        });

        self.vault_encryptor
            .encrypt_vault_entries(&password, &entries)?;

        Ok(())
    }

    pub fn get_password(&mut self, entry_id: &str) -> Result<(), Box<dyn Error>> {
        let mut clipboard = Clipboard::new()?;
        let password = self.prompt_master_password()?;

        let entries = self.vault_encryptor.decrypt_vault_entries(&password)?;

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

        self.vault_encryptor.initialize_vault(&password)?;

        println!(
            "Vault has been created successfully at {}",
            &self.vault_io.get_vault_path()?
        );

        Ok(())
    }
}
