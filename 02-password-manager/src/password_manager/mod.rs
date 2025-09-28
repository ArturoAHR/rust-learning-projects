#[cfg(test)]
mod tests;

use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::io::Write;
use std::thread;
use std::time::Duration;
use std::u32;

use arboard::Clipboard;
use argon2::Argon2;
use argon2::password_hash::rand_core::RngCore;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::OsRng;
use chacha20poly1305::aead::generic_array::GenericArray;
use dialoguer::Confirm;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize, Clone)]
pub struct Vault {
    salt: String,
    nonce: String,
    encrypted_data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasswordManagerEntry {
    id: String,
    password: String,
}

pub struct PasswordManager {
    vault_path: String,
    vault_data: Option<Vault>,
}

impl PasswordManager {
    pub fn new(user_vault_path: Option<String>) -> PasswordManager {
        let default_path =
            env::var("PASSWORD_MANAGER_VAULT_FILE_PATH").unwrap_or("./vault.json".into());

        let resolved_path = user_vault_path.unwrap_or(default_path);

        PasswordManager {
            vault_path: resolved_path,
            vault_data: None,
        }
    }

    fn get_vault_data(&mut self) -> Result<&Vault, io::Error> {
        if self.vault_data.is_none() {
            let vault_data_raw = fs::read_to_string(&self.vault_path)?;
            let vault_data: Vault = serde_json::from_str(&vault_data_raw)?;
            self.vault_data = Some(vault_data);
        }

        Ok(&self.vault_data.as_ref().unwrap())
    }

    // fn get_derived_key(&self, master_password: &str) -> Result<(), Box<dyn Error>> {}

    fn reset_vault(&self) -> Result<(), io::Error> {
        fs::remove_file(&self.vault_path)?;

        Ok({})
    }

    fn prompt_reset_vault(&self, message: &str) -> Result<(), Box<dyn Error>> {
        let data_reset_confirmation = Confirm::new().with_prompt(message).interact()?;

        if data_reset_confirmation {
            self.reset_vault()?;
        }

        Ok({})
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

        let entries = self.decrypt_file(&password)?;

        println!("List of password IDs:");
        for (index, entry) in entries.iter().enumerate() {
            println!("{} - {}", index + 1, entry.id);
        }

        Ok({})
    }

    pub fn add_password_entry(&mut self, entry_id: &str) -> Result<(), Box<dyn Error>> {
        let password = self.prompt_master_password()?;

        let mut entries = self.decrypt_file(&password)?;

        println!("Introduce the password tied to this entry:");
        let entry_password = rpassword::read_password()?;

        entries.push(PasswordManagerEntry {
            id: entry_id.trim().into(),
            password: entry_password,
        });

        self.encrypt_file(&password, entries)?;

        Ok({})
    }

    pub fn get_password(&mut self, entry_id: &str) -> Result<(), Box<dyn Error>> {
        let mut clipboard = Clipboard::new()?;
        let password = self.prompt_master_password()?;

        let entries = self.decrypt_file(&password)?;

        let password_id = &entry_id.trim();
        let mut password_index: Option<u32> = None;

        let parse_password_id_to_index_result = entry_id.trim().parse::<u32>();
        if let Ok(index) = parse_password_id_to_index_result {
            password_index = Some(index);
        }

        let mut selected_entry: Option<PasswordManagerEntry> = None;
        for entry in entries.iter() {
            if entry.id.as_str() == *password_id {
                selected_entry = Some(entry.clone());
                break;
            }
        }

        if let None = selected_entry {
            if let Some(searched_index) = password_index {
                for (index, entry) in entries.iter().enumerate() {
                    if (index + 1) as u64 == searched_index as u64 {
                        selected_entry = Some(entry.clone());
                    }
                }
            }
        }

        if let Some(entry) = &selected_entry {
            clipboard.set_text(&entry.password)?;
            thread::sleep(Duration::from_millis(10));

            println!("The password has been copied to your clipboard")
        }

        if let None = selected_entry {
            println!("There is no password with id {entry_id}")
        }

        Ok({})
    }

    pub fn encrypt_file(
        &mut self,
        password: &str,
        entries: Vec<PasswordManagerEntry>,
    ) -> Result<(), Box<dyn Error>> {
        let mut vault_file = fs::OpenOptions::new().write(true).open(&self.vault_path)?;

        let json_entries = serde_json::to_string_pretty(&entries)?;

        let mut salt = vec![0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let mut password_derive_key = [0u8; 32];
        let password_hash_result = Argon2::default().hash_password_into(
            &password.as_bytes(),
            &salt,
            &mut password_derive_key,
        );

        if let Err(_e) = password_hash_result {
            return Err("Error while generating password hash".into());
        }

        let cipher = XChaCha20Poly1305::new(&password_derive_key.into());

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let data_encryption_result = cipher.encrypt(nonce, json_entries.as_bytes());

        match data_encryption_result {
            Ok(encrypted_data) => {
                let vault = Vault {
                    salt: STANDARD.encode(salt),
                    nonce: STANDARD.encode(nonce.to_vec()),
                    encrypted_data: STANDARD.encode(encrypted_data),
                };

                let vault_json = serde_json::to_string_pretty(&vault)?;

                vault_file.write_all(&vault_json.as_bytes())?;
                vault_file.flush()?;
                self.vault_data = None;
            }
            Err(_e) => return Err("Error while performing encryption".into()),
        }

        Ok({})
    }

    pub fn decrypt_file(
        &mut self,
        password: &str,
    ) -> Result<Vec<PasswordManagerEntry>, Box<dyn Error>> {
        let vault_data = self.get_vault_data()?;

        let salt = STANDARD.decode(&vault_data.salt)?;
        let nonce = GenericArray::clone_from_slice(&STANDARD.decode(&vault_data.nonce)?);
        let encrypted_data = STANDARD.decode(&vault_data.encrypted_data)?;

        let mut password_derive_key = [0u8; 32];
        let password_hash_result = Argon2::default().hash_password_into(
            &password.as_bytes(),
            &salt,
            &mut password_derive_key,
        );

        if let Err(_e) = password_hash_result {
            return Err("Error while generating password hash".into());
        }

        let cipher = XChaCha20Poly1305::new(&password_derive_key.into());

        let decrypted_data_result = cipher.decrypt(&nonce, encrypted_data.as_ref());

        let entries: Vec<PasswordManagerEntry>;
        match decrypted_data_result {
            Err(_e) => {
                return Err("Error while decrypting".into());
            }
            Ok(decrypted_data) => {
                let entries_json = str::from_utf8(&decrypted_data)?;

                entries = serde_json::from_str(&entries_json)?;
            }
        }

        Ok(entries)
    }

    pub fn initialize(&mut self) -> Result<(), Box<dyn Error>> {
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

        let password = self.prompt_master_password_setup()?;

        let entries: Vec<PasswordManagerEntry> = Vec::new();

        let mut vault_file = fs::File::create(&self.vault_path)?;

        let json_entries = serde_json::to_string_pretty(&entries)?;

        let mut salt = vec![0u8; 16];
        OsRng.fill_bytes(&mut salt);

        let mut password_derive_key = [0u8; 32];
        let password_hash_result = Argon2::default().hash_password_into(
            &password.as_bytes(),
            &salt,
            &mut password_derive_key,
        );

        if let Err(_e) = password_hash_result {
            return Err("Error while generating password hash".into());
        }

        let cipher = XChaCha20Poly1305::new(&password_derive_key.into());

        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        let data_encryption_result = cipher.encrypt(nonce, json_entries.as_bytes());

        match data_encryption_result {
            Ok(encrypted_data) => {
                let vault = Vault {
                    salt: STANDARD.encode(salt),
                    nonce: STANDARD.encode(nonce.to_vec()),
                    encrypted_data: STANDARD.encode(encrypted_data),
                };

                let vault_json = serde_json::to_string_pretty(&vault)?;

                vault_file.write_all(&vault_json.as_bytes())?;
                vault_file.flush()?;
                self.vault_data = None;
            }
            Err(_e) => return Err("Error while performing encryption".into()),
        }

        println!(
            "Vault has been created successfully at {}",
            &self.vault_path
        );

        Ok({})
    }
}
