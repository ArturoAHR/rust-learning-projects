mod password_manager;

use clap::{Parser, Subcommand};
use password_manager::PasswordManager;
use std::error::Error;
use std::process;

#[derive(Parser)]
#[command(
    version = "0.1.0",
    about,
    long_about = "Helps you securely manage your passwords behind a master password"
)]
struct Args {
    /// Vault file path
    #[arg(short)]
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
        // /// The name of the new entry.
        // #[arg(short, long)]
        // entry: String,
    },

    /// Allows you to get a password entry identified by the given name.
    Get {
        // /// The name of the existing entry.
        // #[arg(short, long)]
        // entry: String,
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
    let mut password_manager = PasswordManager::new(args.vault);

    return match &args.command {
        Some(Commands::Init {}) => password_manager.initialize(),
        Some(Commands::Add {}) => password_manager.add_password_entry(),
        Some(Commands::Get {}) => password_manager.get_password(),
        Some(Commands::List {}) => password_manager.list_password_ids(),
        None => Err("Command not supported".into()),
    };
}
