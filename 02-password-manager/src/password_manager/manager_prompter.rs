use std::error::Error;

use dialoguer::Confirm;

use crate::password_manager::traits::Prompter;

pub struct PasswordManagerPrompter {}

impl PasswordManagerPrompter {
    pub fn new() -> Self {
        PasswordManagerPrompter {}
    }
}

impl Prompter for PasswordManagerPrompter {
    fn prompt_confirmation(&self, message: &str) -> Result<bool, Box<dyn Error>> {
        let data_reset_confirmation = Confirm::new().with_prompt(message).interact()?;

        Ok(data_reset_confirmation)
    }

    fn prompt_password(&self) -> Result<String, Box<dyn Error>> {
        Ok(rpassword::read_password()?)
    }
}
