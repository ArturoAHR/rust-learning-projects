use clap::{ArgMatches, Command, arg};
use std::error::Error;
use std::process;

fn get_arg_matches() -> ArgMatches {
    Command::new("password-manager")
        .version("0.1.0")
        .about("Helps you securely manage your passwords behind a master password")
        .subcommand(
            Command::new("init").about("To set up your master password and password storage."),
        )
        .subcommand(
            Command::new("add")
                .about("Adds a password under the given name.")
                .arg(arg!([name] "Password Identifier")),
        )
        .subcommand(
            Command::new("get")
                .about("Allows you to get a password identified by the given name.")
                .arg(arg!([name] "Password Identifier")),
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
    match command.subcommand() {
        Some(("init", subcommand)) => {}
        Some(("add", subcommand)) => {}
        Some(("get", subcommand)) => {}
        Some(("list", subcommand)) => {}
        _ => {}
    }

    Ok(())
}
