use std::env;
use std::error::Error;
use std::fs;
use std::io;

use dialoguer::Confirm;
use serde_json::Value;

pub struct PasswordManager {
    database_file_path: String,
}

impl PasswordManager {
    pub fn new() -> PasswordManager {
        let database_file_path =
            env::var("PASSWORD_MANAGER_DATABASE_FILE_PATH").unwrap_or("./database.json".into());

        PasswordManager {
            database_file_path: database_file_path,
        }
    }

    fn get_database_data(&self) -> Result<Value, io::Error> {
        let database_raw = fs::read_to_string(&self.database_file_path)?;

        let database = serde_json::from_str(&database_raw)?;

        Ok(database)
    }

    pub fn initialize(&self) -> Result<(), Box<dyn Error>> {
        println!("Verifying if database already exists");
        let get_database_data_result = self.get_database_data();

        match get_database_data_result {
            Ok(_database) => {
                return Err("Database already exists".into());
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // File is absent, we continue.
            }
            Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                let database_reset_confirmation = Confirm::new()
                    .with_prompt(
                        "Database seems to be  corrupted, do you wish to recreate your database file?",
                    )
                    .interact()?;

                if database_reset_confirmation {
                    fs::remove_file(&self.database_file_path)?;
                } else {
                    return Ok({});
                }
            }
            Err(e) => return Err(e.into()),
        }

        println!("Proceeding with database creation");

        Ok({})
    }
}
