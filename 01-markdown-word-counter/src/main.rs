use std::env;
use std::error::Error;
use std::fs;
use std::process;

use markdown_word_counter::count_words;

struct Args {
    /// The word to count
    word: String,

    /// The path to the text file
    path: String,
}

impl Args {
    fn build(args: Vec<String>) -> Result<Args, &'static str> {
        if args.len() < 3 {
            return Err("Not enough arguments");
        }

        let word = args[1].clone();
        let path = args[2].clone();

        Ok(Args { path, word })
    }
}

fn main() {
    let args: Args = Args::build(env::args().collect()).unwrap_or_else(|err| {
        println!("Argument parsing error: {err}");
        process::exit(1);
    });

    if let Err(e) = run(args) {
        println!("Application error: {e}");
        process::exit(1);
    };
}

fn run(args: Args) -> Result<(), Box<dyn Error>> {
    let contents = fs::read_to_string(&args.path)?;

    println!("Text:\n{contents}");

    let word_count = count_words(&args.word, &contents);

    println!(
        "The word \"{}\" was found {} times in {}",
        args.word, word_count, args.path
    );

    Ok(())
}
