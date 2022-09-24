use hactool_rs::file_formats::{npdm::NpdmFile, Validity};
use std::path::PathBuf;

#[test]
pub fn parse_test_ndpm() {
    let path: PathBuf = vec!["test_files", "main.npdm"].iter().collect();
    let parsed = NpdmFile::parse(path);
    assert!(parsed.is_ok());
    let parsed = parsed.unwrap();

    println!("{:x?}", parsed);

    
    assert_eq!(parsed.verify_acid(hactool_rs::keys::KeysetType::Retail), Ok(Validity::Valid))
}
