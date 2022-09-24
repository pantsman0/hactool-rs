
use clap::Parser;

mod args;

use args::Args;

use rsa::{BigUint, pss::VerifyingKey};
use sha2::Sha256;

fn main() {
    //let pubkey_test()
    //let pubkey = rsa::RsaPublicKey::new(BigUint::from_bytes_le(pubkey_test.as_slice()), BigUint::from_bytes_le([1u8,0, 1].as_slice())).unwrap();
    //let key: VerifyingKey<Sha256> = rsa::pss::VerifyingKey::new(pubkey);
    let _args = Args::parse();
    println!("Hello, {:?}!", _args.input);
}
