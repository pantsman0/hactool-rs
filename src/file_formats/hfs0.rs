use std::path::Path;

use binrw::FilePtr32;
use binrw::prelude::*;
use binrw::NullString;

use crate::file_formats::Validity;
use crate::utils::Placement;

const MAGIC_HFS0:u32 = 0x30534648;

#[binread]
#[derive(Debug)]
#[br(assert(magic == MAGIC_HFS0))]
pub struct Hfs0 {
    /// Embed current cursor position since the HFS0 structure is embedded in a file
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
    #[br(count = file_count, args { inner: (_cursor_position.0 /* HFS0 start position */ + 0x10 /* Offset of file entries */ + u64::from(file_count)*0x40 /* Size of file entry table */,)})]
    pub files: Vec<Hfs0FileEntry>,
}

#[binread]
#[derive(Debug)]
#[br(import(string_table_offset: u64))]
pub struct Hfs0FileEntry {
    /// Offset of file from HFS0 header start
    #[br(temp)] file_offset: u64,
    /// Size of the file in bytes
    #[br(temp)] file_size: u64,
    /// Embedded file path
    #[br(parse_with = FilePtr32::parse, offset = string_table_offset)]
    pub file_name: NullString,
    /// Length of the hashed region at the start of the embedded file
    pub hashed_prefix_len: u32,
    /// Padding
    #[br(temp)] _0x18: u32,
    /// SHA256 hash of the first `hashed_prefix_len` bytes of the embedded file
    pub file_prefix_hash: [u8;0x20],
    /// File Data
    #[br(parse_with = Placement::parse, offset = file_offset, count = file_size)]
    pub file_data: Vec<u8>,
}