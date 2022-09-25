
pub mod npdm;
pub mod pfs0;


#[derive(Debug,PartialEq, Eq)]
pub enum Validity {
    Unchecked,
    Invalid,
    Valid,
    CheckError
}