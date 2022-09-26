
use binrw::prelude::*;
use num_enum::{TryFromPrimitive, IntoPrimitive, FromPrimitive};

use proc_bitfield::bitfield;

use super::SHA256Hash;

#[repr(u32)]
#[binread]
#[br(repr = u32)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
pub enum NcaVersion {
    Nca0 = 0x3041434E,
    Nca1 = 0x3141434E,
    Nca2 = 0x3241434E
}

#[repr(u8)]
#[binread]
#[br(repr = u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
pub enum DistributionType {
    Download,
    GameCard
}

#[repr(u8)]
#[binread]
#[br(repr = u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
pub enum ContentType {
    Program,
    Meta,
    Control,
    Manual,
    Data,
    PublicData
} 

#[repr(u8)]
#[binread]
#[br(repr = u8)]
#[derive(Debug, Default, FromPrimitive, IntoPrimitive)]
pub enum KeyGeneration {
    OldOne = 0,
    Unused = 1,
    OldThree = 2,
    ThreeZeroOne = 3,
    Four = 4,
    Five = 5,
    Six = 6,
    SixTwo = 7,
    Seven = 8,
    EightOne = 9,
    Nine = 10,
    NineOne = 11,
    TwelveOne = 12,
    Thirteen = 13,
    Fourteen = 14,

    #[default]
    Invalid = 0xFF
}

#[repr(u8)]
#[binread]
#[br(repr = u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
pub enum KeyAreaIndex {
    Application,
    Ocean,
    System
}

bitfield! {
    #[binread]
    pub struct SdkAddonVersion(u64): Debug {
        pub raw: u64 @ ..,

        zero: u8 @ 0..8,
        pub sub_minor: u8 @ 8..16,
        pub minor: u8 @ 16..24,
        pub major: u8 @ 24..32
    }
}



#[binread]
#[derive(Debug)]
pub struct NcaFile {
    #[br(temp)]
    _cursor_position: crate::utils::CurPos,
    pub signature: [u8;0x100],
    pub modulus: [u8;0x100],
    pub file_version: NcaVersion,
    pub distribution_type: DistributionType,
    pub content_type: ContentType,
    pub key_generation_old: KeyGeneration,
    pub key_area_index: KeyAreaIndex,
    pub content_size: u64,
    pub program_id: u64,
    pub content_index: u32,
    pub sdk_addon_version: SdkAddonVersion,
    pub key_generation: KeyGeneration,
    pub signature_key_generation: u8, // TODO: need enum
    #[br(temp)] _0x222: [u8;0xE],
    pub fs_entries: [fs::FsEntry;4],
    pub file_hashes: [SHA256Hash;4],
    pub encrypted_key_area: [[u8;0x10];4]
}

pub mod fs {
    use binrw::{prelude::*};
    use num_enum::{TryFromPrimitive, IntoPrimitive};

    #[binread]
    #[derive(Debug)]
    pub struct FsEntry {
        pub start_block_offset: u32,
        pub end_block_offset: u32,
        #[br(temp)] _0x8: u64
    }

    #[repr(u8)]
    #[binread]
    #[br(repr = u8)]
    #[derive(Debug, TryFromPrimitive, IntoPrimitive)]
    pub enum FsType {
        RomFs,
        PartitionFs
    }

    #[repr(u8)]
    #[binread]
    #[derive(Debug, TryFromPrimitive, IntoPrimitive)]
    #[br(repr = u8)]
    pub enum FsType {
        Auto,
        None,
        AesXts,
        AesCtr,
        AesCtrEx,
        AesCtrSkipLayerHash,
        AesCtrExSkipLayerHash
    }

    #[repr(u8)]
    #[binread]
    #[derive(Debug, TryFromPrimitive, IntoPrimitive)]
    #[br(repr = u8)]
    pub enum MetadataHashType  {
        None,
        HierarchicalIntegrity
    }

    #[binread]
    #[derive(Debug)]
    pub struct PatchInfo {
        pub indirect_offset: u64,
        pub indirect_size: u64,
        pub indirect_header: BucketTreeHeader,
        pub aes_offset: u64,
        pub aes_size: u64,
        pub aes_header: AesCtrExHeader
    }

    #[binread]
    #[derive(Debug)]
    #[br(magic = b"BKTR")]
    pub struct BucketTreeHeader {
        pub version: u32,
        pub entry_count: u64,
        #[br(temp)] _0xc: u64
    }

    #[binread]
    #[derive(Debug)]
    //#[br(magic = 2u16)]
    pub struct FsHeader {
        pub version: u16,
        pub fs_type: FsType,
        pub metadata_hash_type: MetadataHashType,
        #[br(temp)] _0x6: u16,
        pub hash_data: [u8;0xF8], //TODO: struct
        pub patch_info: PatchInfo,

    }
}