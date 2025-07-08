use std::{
    fs::File,
    io::{Cursor, Read},
    path::Path,
};

use binrw::prelude::*;
use log::info;
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};

use proc_bitfield::bitfield;

use crate::{keys::NcaKeys, utils::ReaderType};

use aes::{Aes128, cipher::KeyInit, cipher::generic_array::GenericArray};
use xts_mode::Xts128;

use super::SHA256Hash;

#[repr(u32)]
#[binread]
#[br(little, repr = u32)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
pub enum NcaVersion {
    Nca0 = 0x3041434E,
    Nca1 = 0x3141434E,
    Nca2 = 0x3241434E,
    Nca3 = 0x3341434E,
}

#[repr(u8)]
#[binread]
#[br(little, repr = u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
pub enum DistributionType {
    Download,
    GameCard,
}

#[repr(u8)]
#[binread]
#[br(little, repr = u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
pub enum ContentType {
    Program,
    Meta,
    Control,
    Manual,
    Data,
    PublicData,
}

#[repr(u8)]
#[binread]
#[br(little, repr = u8)]
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
    Fifteen = 15,

    #[default]
    Invalid = 0xFF,
}

#[repr(u8)]
#[binread]
#[br(little, repr = u8)]
#[derive(Debug, TryFromPrimitive, IntoPrimitive)]
pub enum KeyAreaIndex {
    Application,
    Ocean,
    System,
}

bitfield! {
    #[binread]
    pub struct SdkAddonVersion(u32): Debug {
        pub raw: u32 @ ..,

        pub revision: u8 @ 0..8,
        pub micro: u8 @ 8..16,
        pub minor: u8 @ 16..24,
        pub major: u8 @ 24..32
    }
}

#[binread]
#[derive(Debug)]
#[repr(C)]
pub struct NcaFileCtx {
    pub signature: [u8; 0x100],
    pub modulus: [u8; 0x100],
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
    pub signature_key_generation: u8, // TODO: need enum?
    #[br(temp)]
    _0x222: [u8; 0xE],
    pub rights_id: [u8; 16],
    pub section_entries: [fs::FsEntry; 4],
    pub section_hashes: [SHA256Hash; 4],
    pub encrypted_key_area: [u8; 64],
    #[br(temp)]
    _0x340: [u8;0xC0],
    pub fs_headers: [fs::FsHeader;4],
}

#[derive(Debug)]
pub struct NcaFileReader {
    reader: ReaderType,
    pub nca_ctx: NcaFileCtx,
}

impl NcaFileReader {
    pub fn parse_file(nca_file: impl AsRef<Path>, key_set: &NcaKeys) -> BinResult<NcaFileReader> {
        let mut file: File = File::open(nca_file.as_ref())?;

        let mut maybe_encrypted_header = [0u8; 0xC00];
        let read_len = file.read(maybe_encrypted_header.as_mut_slice())?;
        if read_len != 0xC00 && read_len != 0xA00 {
            return Err(binrw::Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Failed to read NCA header",
            )));
        }

        let maybe_magic =
            u32::from_le_bytes(maybe_encrypted_header[0x200..0x204].try_into().unwrap());
        if !((maybe_magic == NcaVersion::Nca3.into() || maybe_magic == NcaVersion::Nca2.into())
            && maybe_encrypted_header[0x340..(0x340 + 0xC0)]
                .into_iter()
                .all(|&b| b == 0))
        {
            info!("Decrypting NCA Header");
            // the header is encrypted
            fn get_nintendo_tweak(sector_index: u128) -> [u8; 0x10] {
                sector_index.to_be_bytes()
            }
            let xts_context: Xts128<Aes128> = Xts128::new(
                Aes128::new(GenericArray::from_slice(&key_set.header_key[..0x10])),
                Aes128::new(GenericArray::from_slice(&key_set.header_key[0x10..])),
            );

            xts_context.decrypt_area(&mut maybe_encrypted_header, 0x200, 0, get_nintendo_tweak);
        }
        
        let nca_ctx = Cursor::new(maybe_encrypted_header.as_slice()).read_le()?;

        Ok(Self {
            reader: ReaderType::Raw(file),
            nca_ctx,
        })
    }

    pub fn parse_file_mmap(pfs0_file: impl AsRef<Path>, key_set: &NcaKeys) -> BinResult<Self> {
        let memmap = unsafe { memmap::MmapOptions::new().map(&File::open(pfs0_file.as_ref())?)? };
        let mut cursor = Cursor::new(&memmap[..]);

        let mut maybe_encrypted_header = [0u8; 0xC00];
        let read_len = cursor.read(maybe_encrypted_header.as_mut_slice())?;
        if read_len != 0xC00 && read_len != 0xA00 {
            return Err(binrw::Error::Io(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Failed to read NCA header",
            )));
        }

        let maybe_magic =
            u32::from_le_bytes(maybe_encrypted_header[0x200..0x204].try_into().unwrap());
        if !((maybe_magic == NcaVersion::Nca3.into() || maybe_magic == NcaVersion::Nca2.into())
            && maybe_encrypted_header[0x340..(0x340 + 0xC0)]
                .into_iter()
                .all(|&b| b == 0))
        {
            // the header is encrypted
            let tweak = move |sector: u128| sector.to_be_bytes();
            let xts_context: Xts128<Aes128> = Xts128::new(
                Aes128::new(GenericArray::from_slice(&key_set.header_key[..0x10])),
                Aes128::new(GenericArray::from_slice(&key_set.header_key[0x10..])),
            );

            xts_context.decrypt_area(maybe_encrypted_header.as_mut_slice(), 0x200, 0, tweak);
        }

        let nca_ctx = Cursor::new(maybe_encrypted_header.as_slice()).read_le()?;

        Ok(Self {
            reader: ReaderType::Mapped(memmap),
            nca_ctx,
        })
    }
}

pub mod fs {
    use binrw::{ prelude::*};
    use num_enum::{IntoPrimitive, TryFromPrimitive};

    #[binread]
    #[derive(Debug, Default)]
    pub struct FsEntry {
        pub start_block_offset: u32,
        pub end_block_offset: u32,
        pub hash_sectors: u32,
        #[br(temp)]
        _padding: [u8; 4],
    }

    #[repr(u8)]
    #[binread]
    #[br(little, repr = u8)]
    #[derive(Debug, TryFromPrimitive, IntoPrimitive)]
    pub enum PartitionType {
        RomFs,
        PartitionFs,
    }

    #[repr(u8)]
    #[binread]
    #[br(little, repr = u8)]
    #[derive(Clone, Copy, Debug, TryFromPrimitive, IntoPrimitive)]
    pub enum FsType {
        None = 0,
        Pfs0 = 2,
        RomFs = 3,
    }

    #[repr(u8)]
    #[binread]
    #[derive(Debug, TryFromPrimitive, IntoPrimitive)]
    #[br(little, repr = u8)]
    pub enum EncryptionType {
        Auto,
        None,
        AesXts,
        AesCtr,
        AesCtrEx,
        AesCtrSkipLayerHash,
        AesCtrExSkipLayerHash,
    }

    #[repr(u8)]
    #[binread]
    #[derive(Debug, TryFromPrimitive, IntoPrimitive)]
    #[br(little, repr = u8)]
    pub enum MetadataHashType {
        None,
        HierarchicalIntegrity,
    }

    #[repr(u32)]
    #[binread]
    #[derive(Debug, TryFromPrimitive, IntoPrimitive)]
    #[br(little, repr = u32)]
    pub enum SectionEcryptioType {
        None = 1,
        Xts = 2,
        Ctr = 3,
        Bktr = 4,
        Nca0 = super::NcaVersion::Nca0 as u32,
    }

    #[binread]
    #[derive(Debug)]
    #[br(little, magic = b"BKTR")]
    pub struct BucketTreeHeader {
        pub version: u32,
        pub entry_count: u64,
        #[br(temp)]
        _0xc: u64,
    }

    #[binread]
    #[derive(Debug)]
    pub struct SparseInfo {
        pub table_offset: u64,
        pub table_size: u64,
        pub table_header: BucketTreeHeader,
        pub physical_offset: u64,
        #[br(temp)]
        _0x20: [u8; 0x8],
    }

    #[binread]
    #[derive(Debug)]
    pub struct CompressionInfo {
        pub compression_table_offset: u64,
        pub compression_table_size: u64,
        pub container_header: BucketTreeHeader,
        #[br(temp)]
        _0xc: u64,
    }

    #[binread]
    #[derive(Debug)]
    pub struct MetadataHashInfo {
        pub table_offset: u64,
        pub table_size: u64,
        pub table_hash: [u8; 0x20], // SHA256?
    }

/*    #[binread]
    #[derive(Debug)]
    //#[br(magic = 2u16)]
    pub struct FsHeader {
        pub version: u16,
        pub partition_type: u8, // TODO: enum
        pub fs_type: FsType,
        pub encryption_type: EncryptionType,
        #[br(temp)]
        _0x6: u16,
        pub hash_data: [u8; 0xF8], //TODO: struct
        //pub patch_info: fs_patch::PatchInfoPtr,
        pub generation: u32,
        pub secure_value: u32,
        pub sparse_info: SparseInfo,
        pub compression_info: Option<CompressionInfo>,
        pub metadata_hash: MetadataHashInfo,
    }*/

    #[binread]
    #[derive(Debug)]
    //#[br(magic = 2u16)]
    pub struct FsHeader {
        #[br(temp)] _unknown: [u8;2],
        pub partition_type: u8, // TODO: enum
        pub fs_type: FsType,
        pub encryption_type: EncryptionType,
        #[br(temp)]
        _0x5: [u8;3],
        #[br(args(fs_type))]
        pub superblock: SuperBlock,
        pub section_ctr: [u8;0x8],
        #[br(temp)] _0x148: [u8;0xB8]
    }

    mod fs_patch {
        use binrw::prelude::*;
        use num_enum::{IntoPrimitive, TryFromPrimitive};

        use super::BucketTreeHeader;

        #[binread]
        #[derive(Debug)]
        pub struct RawPatchHeader {
            pub indirect_offset: u64,
            pub indirect_size: u64,
            pub indirect_header: BucketTreeHeader,
            pub aes_offset: u64,
            pub aes_size: u64,
            pub aes_header: BucketTreeHeader,
        }

        #[binread]
        #[derive(Debug)]
        struct PatchEntry {
            #[br(temp)]
            _0x0: u32,
            pub bucket_count: u32,
            pub vfs_image_size: u64,
            pub bucket_virtual_offsets: [u64; 0x7fe],
            #[br(count = bucket_count)]
            pub relocation_buckets: Vec<RelocationBucket>,
        }

        #[binread]
        #[derive(Debug)]
        struct RelocationBucket {
            #[br(temp)]
            _0x0: u32,
            pub entry_count: u32,
            pub bucket_end_offset: u64,
            #[br(count = entry_count)]
            pub relocation_entries: Vec<RelocationEntry>,
        }

        #[repr(u8)]
        #[binread]
        #[br(little, repr = u8)]
        #[derive(Debug, TryFromPrimitive, IntoPrimitive)]
        pub enum RelocationDirection {
            FromBase,
            FromPatch,
        }

        #[binread]
        #[derive(Debug)]
        struct RelocationEntry {
            pub dest_romfs_addr: u64,
            pub source_romfs_addr: u64,
            pub direction: RelocationDirection,
        }
    }

    #[derive(Debug)]
    pub enum SuperBlock {
        None,
        Pfs0(pfs0::Pfs0SuperBlock)
    }

    impl BinRead for SuperBlock {
        type Args<'a> = (FsType,);

        fn read_options<R: std::io::Read + std::io::Seek>(
                reader: &mut R,
                _endian: binrw::Endian,
                args: Self::Args<'_>,
            ) -> BinResult<Self> {
            if matches!(args.0, FsType::None){
                reader.seek(std::io::SeekFrom::Current(0x138))?;
                Ok(Self::None)
            }
            else if matches!(args.0, FsType::Pfs0) {
                Ok(Self::Pfs0(reader.read_le()?))
            } else {
                todo!()
            }
        }
    }
    pub mod pfs0 {
        use binrw::binread;

        #[binread]
        #[derive(Debug)]
        pub struct Pfs0SuperBlock {
            pub master_hash: crate::file_formats::SHA256Hash,
            pub block_size_bytes: u32,
            #[br(temp)] _always_2: u32,
            pub hash_table_offset: u64,
            pub hash_table_size: u64,
            pub pfs0_offset: u64,
            pub pfs0_size: u64,
            #[br(temp)] _0x48: [u8;0xF0]
        }
    }
}
