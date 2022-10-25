use std::fs::File;
use std::io::Cursor;
use std::io::Result;
use std::path::Path;

use binrw::prelude::*;
use binrw::BinReaderExt;
use binrw::FilePtr32;
use binrw::NullString;
use memmap::Mmap;

use crate::utils::CurPos;
use crate::utils::read_restore;

#[binread]
#[derive(Debug)]
pub struct Pfs0 {
    /// Embed current cursor position since the PFS0 may be embedded in an NCA file
    #[br(temp)] cursor_position: crate::utils::CurPos,
    /// Pfs0 header
    pub header: Pfs0Header,

    // Calculated fields
    #[br(temp, calc = cursor_position.0 /* PFS0 start position */ + 0x10 /* Offset of file entries */ + u64::from(header.file_count)*0x18 /* Size of file entry table */)]
    string_table_absolute_start: u64,
    #[br(temp, calc = string_table_absolute_start + u64::from(header.string_table_byte_size))]
    file_data_absolute_start: u64,

    /// Embedded file entries
    #[br(count = header.file_count, args { inner: (string_table_absolute_start, file_data_absolute_start)})]
    pub files: Vec<Pfs0FileRecord>,
}

#[binread]
#[derive(Debug, Clone, Copy)]
#[brw(little, magic = b"PFS0")]
pub struct Pfs0Header {
    /// number of embedded files
    pub file_count: u32,
    /// size of the file name string buffer in bytes
    #[brw(pad_after = 4)]
    pub string_table_byte_size: u32,
}

#[binread]
#[derive(Debug)]
#[br(little, import(string_table_absolute_start: u64, file_data_absolute_start: u64))]
pub struct Pfs0FileRecord {
    /// Offset and size of file from PFS0 header start
    #[br(temp)]
    pfs_file_relative_offset: u64,
    #[br(calc = pfs_file_relative_offset + file_data_absolute_start)]
    pub file_offset: u64,
    pub file_size: u64,
    /// Embedded file path
    #[br(parse_with = FilePtr32::parse, pad_after = 4, offset = string_table_absolute_start )]
    pub file_name: NullString,
}

#[derive(Debug)]
pub struct Pfs0Reader {
    reader: ReaderType,
    pub pfs: Pfs0
}

#[derive(Debug)]
enum ReaderType {
    Raw(File),
    Mapped(Mmap)
}

impl Pfs0Reader {
    pub fn parse_file<P: AsRef<Path>>(pfs0_file: P) -> BinResult<Pfs0Reader> {
        let mut file: File = File::open(pfs0_file.as_ref())?;
        let pfs = file.read_le()?;

        Ok(Pfs0Reader {
            reader: ReaderType::Raw(file),
            pfs,
        })
    }

    pub fn parse_file_mmap<P: AsRef<Path>>(
        pfs0_file: P,
    ) -> BinResult<Pfs0Reader> {
        let memmap =
            unsafe { memmap::MmapOptions::new().map(&File::open(pfs0_file.as_ref())?)? };
        let mut cursor = Cursor::new(&memmap[..]);

        let pfs0 = cursor.read_le()?;

        Ok(Pfs0Reader { reader: ReaderType::Mapped(memmap), pfs: pfs0 })
    }

    pub fn list_files(&self) -> Vec<String> {
        self.pfs.files.iter().map( |f: &Pfs0FileRecord| {
            f.file_name.to_string()
        })
        .collect()
    }

    pub fn get_file_data<S: std::string::ToString>(&mut self, file_name: S) -> Option<Result<Vec<u8>>> {
        let matched_files: Vec<&Pfs0FileRecord> = self.pfs.files.iter().filter(|f| f.file_name.to_string() == file_name.to_string()).collect();

        if matched_files.len() == 0 {
            return None;
        }

        let &Pfs0FileRecord { file_offset, file_size, file_name: _ } = matched_files[0];

        match self.reader {
            ReaderType::Mapped(ref map) =>  Some(read_restore(&mut Cursor::new(&map[..]), file_offset, file_size)),
            ReaderType::Raw(ref mut f) => Some(read_restore(f, file_offset, file_size))
        }
    }
}
