use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Vault {
    pub salt: String,
    pub nonce: String,
    pub encrypted_data: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PasswordManagerEntry {
    pub id: String,
    pub password: String,
}
