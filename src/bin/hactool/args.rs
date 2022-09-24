use clap::{Parser, ValueEnum, Subcommand};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Args {
   /// The base file type to work on.
   #[clap(value_enum, subcommand)]
   pub r#type: SupportedFileTypes,

   /// The action required on the input file
   #[clap(short, long, value_enum, default_value_t = Action::Verify, global = true)]
   pub action: Action,

   /// Input file
   #[clap(short, long, value_parser, global = true)]
   pub input: Option<String>,
}


#[derive(Debug,Subcommand,ValueEnum, Clone)]
pub enum SupportedFileTypes {
    Npdm
}

#[derive(Debug,ValueEnum, Clone)]
pub enum Action {
    Verify
}