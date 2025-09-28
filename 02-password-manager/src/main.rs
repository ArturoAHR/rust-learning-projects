mod password_manager;

use clap::{ArgMatches, Command};
use password_manager::PasswordManager;
use std::error::Error;
use std::process;

fn get_arg_matches() -> ArgMatches {
    Command::new("password-manager")
        .version("0.1.0")
        .about("Helps you securely manage your passwords behind a master password")
        .subcommand(
            Command::new("init").about("To set up your master password and password storage."),
        )
        .subcommand(Command::new("add").about("Adds a password under the given name."))
        .subcommand(
            Command::new("get").about("Allows you to get a password identified by the given name."),
        )
        .subcommand(Command::new("list").about("Displays all the registered names."))
        .get_matches()
}

fn main() {
    let command = get_arg_matches();

    if let Err(e) = run(command) {
        eprintln!("Application error: {e}");
        process::exit(1);
    }
}

fn run(command: ArgMatches) -> Result<(), Box<dyn Error>> {
    let mut password_manager = PasswordManager::new();

    return match command.subcommand() {
        Some(("init", _)) => password_manager.initialize(),
        Some(("add", _)) => password_manager.add_password_entry(),
        Some(("get", _)) => password_manager.get_password(),
        Some(("list", _)) => password_manager.list_password_ids(),
        _ => Err("Command not supported".into()),
    };
}
