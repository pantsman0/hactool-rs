
use clap::Parser;

mod args;
mod file_formats;
//mod settings;
mod utils;

fn main() {
    let _args = args::Args::parse();
    println!("Hello, world!");
}
