use std::{fs::File, path::PathBuf};

use clap::Parser;
use dirs::home_dir;

mod args;

use anyhow::anyhow;
use args::Args;
use hactool_rs::file_formats::Validity;

use crate::args::Action;

fn main() -> anyhow::Result<()> {
    //let pubkey_test()
    //let pubkey = rsa::RsaPublicKey::new(BigUint::from_bytes_le(pubkey_test.as_slice()), BigUint::from_bytes_le([1u8,0, 1].as_slice())).unwrap();
    //let key: VerifyingKey<Sha256> = rsa::pss::VerifyingKey::new(pubkey);
    let keys = match home_dir() {
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

    let mut args = Args::parse();
    args.action.sort();

    match args.file_type {
        args::SupportedFileTypes::Npdm => {
            for action in args.action.iter() {
                match action {
                    Action::Info => {
                        let file_name = args
                            .input
                            .clone()
                            .ok_or(anyhow!("Input file must be provided for info action"))?;
                        let npdm = hactool_rs::file_formats::npdm::NpdmFile::parse(&file_name)?;

                        println!("Npdm file: {}, content: {:#?}", file_name, npdm);
                    }
                    Action::Verify => {
                        let file_name = args
                            .input
                            .clone()
                            .ok_or(anyhow!("Input file must be provided for verify action"))?;
                        let npdm = hactool_rs::file_formats::npdm::NpdmFile::parse(&file_name)?;
                        println!(
                            "Npdm parsed successfully. Valid: {}, content: {:?}",
                            npdm.verify_acid(hactool_rs::keys::KeysetType::Dev) == Ok(Validity::Valid)
                                || npdm.verify_acid(hactool_rs::keys::KeysetType::Retail) == Ok(Validity::Valid),
                            npdm
                        );
                    }
                    Action::Extract => {
                        eprintln!("Npdm files have no files to extract.");
                    }
                    Action::Create => {
                        eprintln!("Creating npdm files not supported.")
                    }
                }
            }
        }
        args::SupportedFileTypes::Pfs0 => {
            for action in args.action.iter() {
                match action {
                    Action::Info => {
                        let file_name = args
                            .input
                            .clone()
                            .ok_or(anyhow!("Input file must be provided for info action"))?;
                        let pfs =
                            hactool_rs::file_formats::pfs0::Pfs0Reader::parse_file(&file_name)?;
                        println!(
                            "Pfs0 file: {}, files: {:?}",
                            file_name,
                            pfs.list_files().as_slice()
                        );
                    }
                    Action::Verify => {
                        eprintln!("Pfs0 files have no verification metadata.");
                        let file_name = args
                            .input
                            .clone()
                            .ok_or(anyhow!("Input file must be provided for verify action"))?;
                        let pfs =
                            hactool_rs::file_formats::pfs0::Pfs0Reader::parse_file(&file_name)?;
                        println!("Pfs0 parsed successfully: {:?}", pfs);
                    }
                    Action::Extract => {
                        let file_name = args
                            .input
                            .clone()
                            .ok_or(anyhow!("Input file must be provided for extract action"))?;
                        let output_folder =
                            PathBuf::from(args.output.as_ref().ok_or(anyhow!(
                                "Output folder must be provided for extract action"
                            ))?);
                        let mut pfs =
                            hactool_rs::file_formats::pfs0::Pfs0Reader::parse_file(&file_name)?;

                        for file in pfs.list_files() {
                            let mut output_file = output_folder.clone();
                            output_file.push(&file);

                            println!("Extracting {}...", output_file.display());

                            pfs.read_file_into(file, &mut File::create(output_file.as_path())?)?;
                        }
                    }
                    Action::Create => {
                        todo!()
                    }
                }
            }
        },
        args::SupportedFileTypes::Nca => {
            for action in args.action.iter() {
                match action {
                    Action::Info => {
                        let file_name = args
                            .input
                            .clone()
                            .ok_or(anyhow!("Input file must be provided for info action"))?;
                        let nca_reader =
                            hactool_rs::file_formats::nca::NcaFileReader::parse_file(&file_name, &keys)?;
                        println!(
                            "Nca file: {:X?}",
                            nca_reader.nca_ctx
                        );
                    }
                    Action::Verify => {
                        todo!()
                    }
                    Action::Extract => {
                        todo!()
                    }
                    Action::Create => {
                        todo!()
                    }
                }
            }
        }
    }
    Ok(())
}
