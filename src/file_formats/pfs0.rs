use std::path::Path;

use binrw::prelude::*;
use binrw::FilePtr32;
use binrw::NullString;

use crate::file_formats::Validity;
use crate::utils::Placement;

const MAGIC_PFS0: u32 = 0x30534650;

#[binread]
#[derive(Debug)]
#[br(assert(magic == MAGIC_PFS0))]
pub struct Pfs0File {
    /// Embed current cursor position since the PFS0 may be embedded in an NCA file
    #[br(temp)] _cursor_position: crate::utils::CurPos,
    /// "PFS0" magic value
    #[br(temp)] magic: u32,
    /// number of embedded files
    #[br(temp)] file_count: u32,
    /// size of the file name string buffer in bytes
    #[br(temp)] string_table_byte_size: u32,
    /// Padding
    #[br(temp)] _0xc: u32,
    /// Embedded file entries
    #[br(count = file_count, args { inner: (_cursor_position.0 /* PFS0 start position */ + 0x10 /* Offset of file entries */ + u64::from(file_count)*0x18 /* Size of file entry table */,)})]
    pub files: Vec<Pfs0FileEntry>,
}

#[binread]
#[derive(Debug)]
#[br(import(string_table_offset: u64))]
pub struct Pfs0FileEntry {
    /// Offset of file from PFS0 header start
    #[br(temp)] file_offset: u64,
    /// Size of the file in bytes
    #[br(temp)] file_size: u64,
    /// Embedded file path
    #[br(parse_with = FilePtr32::parse, offset = string_table_offset)]
    pub file_name: NullString,
    /// Padding
    #[br(temp)] _0x14: u32,
    /// File Data
    #[br(parse_with = Placement::parse, offset = file_offset, count = file_size)]
    pub file_data: Vec<u8>,
}
/*
struct Pfs0Superblock {
    pub master_hash: [u8;0x20],
    pub block_size: u32,
    pub _always2: u32,
    pub hash_table_offset: u64,
    pub hash_table_size: u64,
    pub pfs0_offset: u64,
    pub pfs0_size: u64,
    pub _reserved: [u8;0xF0]
}

struct Pfs0Context<'context> {
    pub superblock: &'context Pfs0Superblock,
    pub file: std::fs::File,
    pub superblock_hash_validity: Validity,
    pub hash_table_validity: Validity,
    pub is_exefs: bool,
    pub npdm: (),
    pub header: Pfs0Header
}
 */

impl Pfs0File {
    pub fn parse<P: AsRef<Path>>(pfs0_file: P) -> BinResult<Pfs0File> {
        let mut file = std::fs::File::open(pfs0_file.as_ref())?;

        file.read_le()
    }
}
