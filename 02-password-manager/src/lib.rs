use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::io::Write;

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

#[derive(Serialize, Deserialize, Debug)]
pub struct PasswordManagerEntry {
    id: String,
    password: String,
}

pub struct PasswordManager {
    vault_file_path: String,
    vault_data: Option<Vault>,
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

    fn get_vault_data(&mut self) -> Result<&Vault, io::Error> {
        if self.vault_data.is_none() {
            let vault_data_raw = fs::read_to_string(&self.vault_file_path)?;
            let vault_data: Vault = serde_json::from_str(&vault_data_raw)?;
            self.vault_data = Some(vault_data);
        }

        Ok(self.vault_data.as_ref().unwrap())
    }

    // fn get_derived_key(&self, master_password: &str) -> Result<(), Box<dyn Error>> {}

    fn reset_vault(&self) -> Result<(), io::Error> {
        fs::remove_file(&self.vault_file_path)?;

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

        let mut vault_file = fs::File::create(&self.vault_file_path)?;

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
            }
            Err(_e) => return Err("Error while performing encryption".into()),
        }

        println!(
            "Vault has been created successfully at {}",
            &self.vault_file_path
        );

        let entries = &self.decrypt_file(&password)?;

        println!("{:?}", entries);

        Ok({})
    }
}
