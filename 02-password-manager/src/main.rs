mod password_manager;

use std::error::Error;
use std::process;

use clap::{Parser, Subcommand};

use crate::password_manager::{
    PasswordManager, vault_encryption::VaultEncryption, vault_file_io::VaultFileIO,
};

#[derive(Parser)]
#[command(
    version = "0.1.0",
    about,
    long_about = "Helps you securely manage your passwords behind a master password"
)]
struct Args {
    /// Vault file path, you can also set this value with the PASSWORD_MANAGER_VAULT_FILE_PATH environment variable.
    #[arg(short, long)]
    vault: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// To set up your master password and password storage.
    Init {},

    /// Displays all the registered names.
    List {},

    /// Adds a password entry under the given name.
    Add {
        /// The name of the new entry.
        entry: String,
    },

    /// Allows you to get a password entry identified by the given name.
    Get {
        /// The name of the existing entry.
        entry: String,
    },
}

fn main() {
    let args = Args::parse();

    if let Err(e) = run(args) {
        eprintln!("Application error: {e}");
        process::exit(1);
    }
}

fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let vault_file_io = VaultFileIO::new(args.vault);
    let vault_encryption = VaultEncryption::new();
    let mut password_manager = PasswordManager::new(&vault_encryption, &vault_file_io);

    return match &args.command {
        Some(Commands::Init {}) => password_manager.initialize(),
        Some(Commands::Add { entry }) => password_manager.add_password_entry(&entry),
        Some(Commands::Get { entry }) => password_manager.get_password(&entry),
        Some(Commands::List {}) => password_manager.list_password_ids(),
        None => Err("Command not supported".into()),
    };
}
