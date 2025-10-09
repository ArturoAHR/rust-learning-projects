use std::{error::Error, io};

use argon2::{Argon2, password_hash::rand_core::RngCore};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, OsRng, generic_array::GenericArray},
};

use crate::password_manager::{
    models::{PasswordManagerEntry, Vault},
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
    ) -> Result<Vec<PasswordManagerEntry>, Box<dyn Error>> {
        let vault_data: Vault;
        let get_vault_data_result = self.vault_io.read_vault();

        match get_vault_data_result {
            Ok(data) => vault_data = data,
            Err(error) => {
                if let Some(io_error) = error.downcast_ref::<io::Error>()
                    && io_error.kind() == io::ErrorKind::NotFound
                {
                    let error_message = format!(
                        "Vault file doesn't exist at location: {}",
                        &self.vault_io.get_vault_path()?
                    );

                    return Err(error_message.into());
                }

                return Err(error);
            }
        }

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

    fn encrypt_vault_entries(
        &self,
        password: &str,
        entries: &Vec<PasswordManagerEntry>,
    ) -> Result<(), Box<dyn Error>> {
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

                let _ = self.vault_io.write_to_vault(&vault);
            }
            Err(_e) => return Err("Error while performing encryption".into()),
        }

        Ok({})
    }

    fn initialize_vault(&self, password: &str) -> Result<(), Box<dyn Error>> {
        let entries: Vec<PasswordManagerEntry> = Vec::new();

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

                let _ = &self.vault_io.write_to_vault(&vault);
            }
            Err(_e) => return Err("Error while performing encryption".into()),
        }

        Ok(())
    }
}
