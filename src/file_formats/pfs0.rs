use std::borrow::BorrowMut;
use std::fs::File;
use std::io::{Read, Seek};
use std::path::Path;

use binrw::prelude::*;
use binrw::FilePtr32;
use binrw::NullString;

use crate::file_formats::Validity;
use crate::utils::Placement;

const MAGIC_PFS0: u32 = 0x30534650;

pub struct Pfs0Reader<'reader, R: Read + Seek> {
    reader: &'reader mut R,
    pub pfs0: Pfs0,
}

#[binread]
#[derive(Debug)]
#[br(assert(magic == MAGIC_PFS0))]
pub struct Pfs0 {
    /// Embed current cursor position since the PFS0 may be embedded in an NCA file
    #[br(temp)]
    _cursor_position: crate::utils::CurPos,
    /// "PFS0" magic value
    #[br(temp)]
    magic: u32,
    /// number of embedded files
    #[br(temp)]
    file_count: u32,
    /// size of the file name string buffer in bytes
    #[br(temp)]
    string_table_byte_size: u32,
    /// Padding
    #[br(temp)]
    _0xc: u32,
    /// Embedded file entries
    #[br(count = file_count, args { inner: (_cursor_position.0 /* PFS0 start position */ + 0x10 /* Offset of file entries */ + u64::from(file_count)*0x18 /* Size of file entry table */,)})]
    pub files: Vec<Pfs0FileRecord>,
}

#[binread]
#[derive(Debug)]
#[br(import(string_table_offset: u64))]
pub struct Pfs0FileRecord {
    /// Offset of file from PFS0 header start
    #[br(temp)]
    file_offset: u64,
    /// Size of the file in bytes
    #[br(temp)]
    file_size: u64,
    /// Embedded file path
    #[br(parse_with = FilePtr32::parse, offset = string_table_offset)]
    pub file_name: NullString,
    /// Padding
    #[br(temp)]
    _0x14: u32,
    /// File Data
    #[br(parse_with = Placement::parse, offset = file_offset, count = file_size)]
    pub file_data: Vec<u8>,
}

#[binread]
#[derive(Debug)]
pub struct Pfs0File {
    
}

impl Pfs0Reader<'_, _> {
    pub fn parse_file<'file, P: AsRef<Path>>(pfs0_file: P) -> BinResult<Pfs0Reader<'file, File>> {
        let mut file: File = File::open(pfs0_file.as_ref())?;

        let pfs0 = file.borrow_mut().read_le()?;
        file.rewind();

        Ok(Pfs0Reader {
            reader: &mut file,
            pfs0,
        })
    }

    pub fn parse_file_mmap<'file, P: AsRef<Path>>(
        pfs0_file: P,
    ) -> BinResult<Pfs0Reader<'file, File>> {
        let &mut reader =
            unsafe { memmap::MmapOptions::new().map(File::open(pfs0_file.as_ref())?.as_ref()) };

        let pfs0 = reader.read_le()?;
        reader.rewind();

        Ok(Pfs0Reader { reader, pfs0 })
    }
}
