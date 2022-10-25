use clap::{Parser, ValueEnum, Subcommand};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
pub struct Args {
   /// The base file type to work on.
   #[clap(value_enum, subcommand)]
   pub file_type: SupportedFileTypes,

   /// The action required on the input file/folder
   #[clap(short, long, default_value_t = Action::Verify, global = true)]
   pub action: Vec<Action>,

   /// Input file/folder
   #[clap(short, long, value_parser, global = true)]
   pub input: Option<String>,
}


#[derive(Debug,Subcommand,ValueEnum, Clone)]
pub enum SupportedFileTypes {
    Npdm,
    Pfs0
}

#[derive(Debug,ValueEnum, Clone)]
pub enum Action {
    Info,
    Verify,
    Extract,
    Create
}