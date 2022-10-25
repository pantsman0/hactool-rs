
use std::{io::Write, fs::File};

use clap::Parser;
use dirs::home_dir;
use log::{info, warn, error};

mod args;

use args::Args;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    //let pubkey_test()
    //let pubkey = rsa::RsaPublicKey::new(BigUint::from_bytes_le(pubkey_test.as_slice()), BigUint::from_bytes_le([1u8,0, 1].as_slice())).unwrap();
    //let key: VerifyingKey<Sha256> = rsa::pss::VerifyingKey::new(pubkey);
    let keys = match home_dir() {
        Some(ref mut path) => {
            path.push(".switch");
            path.push("prod.keys");
            match hactool_rs::keys::NcaKeys::from_file(&path) {
                Ok(keys) => {Some(keys)},
                Err(e) => {
                    warn!("Warning: unable to read keys file {}. Error: {}", path.to_string_lossy(), e);
                    None
                }
            }
        },
        None => {
            error!("Error: Unable to determine user home directory");
            std::process::exit(1);
        }
    };

    let args = Args::parse();

    //println!("{:?}", args);

    let mut pfs = hactool_rs::file_formats::pfs0::Pfs0Reader::parse_file(args.input.unwrap())?;
    println!("{:#X?}", pfs);

    Ok(())
}
