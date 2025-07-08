use clap::{Parser, ValueEnum, Subcommand};
use hactool_rs::keys::KeysetType;

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
pub struct Args {
   /// The base file type to work on.
   #[clap(value_enum, subcommand)]
   pub file_type: SupportedFileTypes,

   /// The action required on the input file/folder
   #[clap(short, long, value_parser, value_delimiter = ',', global = true)]
   pub action: Vec<Action>,

   /// Input file/folder
   #[clap(short, long, value_parser, global = true)]
   pub input: Option<String>,

    /// Output file/folder
    #[clap(short, long, value_parser, global = true)]
    pub output: Option<String>,

    /// Key set
    #[clap(short, long, value_parser, global = true, default_value = "retail")]
    pub keyset: KeysetType
}


#[derive(Debug,Subcommand,ValueEnum, Clone)]
pub enum SupportedFileTypes {
    Npdm,
    Pfs0,
    Nca
}

#[derive(Debug,ValueEnum, Clone, PartialEq, PartialOrd, Eq, Ord)]
pub enum Action {
    Info,
    Verify,
    Extract,
    Create
}