use std::env;
use std::fs;

struct Args {
    /// The word to count
    word: String,

    /// The path to the text file
    path: String,
}

impl Args {
    fn new(args: Vec<String>) -> Args {
        let word = args[1].clone();
        let path = args[2].clone();

        Args { path, word }
    }
}

fn main() {
    let args: Args = Args::new(env::args().collect());

    let contents = fs::read_to_string(args.path).expect("Should have been able to read the file");

    println!("Text:\n{contents}")
}
