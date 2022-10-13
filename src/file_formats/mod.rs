pub mod hfs0;
pub mod nca;
pub mod npdm;
pub mod pfs0;

pub type SHA256Hash = [u8;0x20];

#[derive(Debug,PartialEq, Eq)]
pub enum Validity {
    Unchecked,
    Invalid,
    Valid,
    CheckError
}