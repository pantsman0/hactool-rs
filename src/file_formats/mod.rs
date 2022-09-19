
pub mod npdm;
pub mod pfs0;


#[derive(Debug)]
pub enum Validity {
    Unchecked,
    Invalid,
    Valid
}