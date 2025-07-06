use std::{fs::File, io::Write};

use clap::Parser;
use dirs::home_dir;

mod args;

use anyhow::anyhow;
use args::Args;

fn main() -> anyhow::Result<()> {
    //let pubkey_test()
    //let pubkey = rsa::RsaPublicKey::new(BigUint::from_bytes_le(pubkey_test.as_slice()), BigUint::from_bytes_le([1u8,0, 1].as_slice())).unwrap();
    //let key: VerifyingKey<Sha256> = rsa::pss::VerifyingKey::new(pubkey);
    let _keys = match home_dir() {
        Some(ref mut path) => {
            path.push(".switch");
            path.push("prod.keys");
            match hactool_rs::keys::NcaKeys::from_file(&path) {
                Ok(keys) => keys,
                Err(e) => {
                    return Err(anyhow!(
                        "Warning: unable to read keys file {}. Error: {}",
                        path.to_string_lossy(),
                        e
                    ));
                }
            }
        }
        None => {
            return Err(anyhow!("Error: Unable to determine user home directory"));
        }
    };

    let args = Args::parse();

    let pfs = hactool_rs::file_formats::pfs0::Pfs0Reader::parse_file(args.input.unwrap())?;
    println!("{:#X?}", pfs);

    Ok(())
}
