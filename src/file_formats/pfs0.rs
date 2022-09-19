
use crate::file_formats::Validity;

const MAGIC_PFS0:u32 = 0x30534650;

struct Pfs0Header {
    pub magic: u32,
    pub num_files: u32,
    pub string_table_size: u32,
    pub _reserved: u32
}

struct Pfs0FileEntry {
    pub offset: u64,
    pub size: u64,
    pub string_table_offset: u32,
    pub _reserved: u32
}

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