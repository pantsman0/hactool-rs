use hactool_rs::file_formats::pfs0::Pfs0Reader;
use std::path::PathBuf;

#[test]
pub fn parse_test_pfs0() {
    let path: PathBuf = vec!["test_files", "test.nsp"].iter().collect();
    let parsed = Pfs0Reader::parse_file(path);

    println!("{:x?}", parsed);
    assert!(parsed.is_ok());

    
    //assert_eq!(parsed.verify_acid(hactool_rs::keys::KeysetType::Retail), Ok(Validity::Valid))
}
