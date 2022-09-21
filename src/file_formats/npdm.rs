use std::{path::Path, io::{Read, Seek, SeekFrom}};

use anyhow::Result;
use binrw::{BinRead, BinReaderExt, FilePtr32, count, ReadOptions};
use proc_bitfield::bitfield;


//const MAGIC_META: u32 = 0x4154454D;
const MAGIC_ACID: u32 = 0x44494341;
const MAGIC_ACI0: u32 = 0x30494341;


bitfield! {
    #[derive(BinRead)]
    pub struct FsAccessFlags(u64): Debug {
        pub raw: u64 @ ..,

        pub application_info: bool @ 0,
        pub boot_mode_control: bool @ 1,
        pub calibration: bool @ 2,
        pub system_save_data: bool @ 3,
        pub game_card: bool @ 4,
        pub save_data_back_up: bool @ 5,
        pub save_data_management: bool @ 6,
        pub bis_all_raw: bool @ 7,
        pub game_card_raw: bool @ 8,
        pub game_card_private: bool @ 9,
        pub set_time: bool @ 10,
        pub content_manager: bool @ 11,
        pub image_manager: bool @ 12,
        pub create_save_data: bool @ 13,
        pub system_save_data_management: bool @ 14,
        pub bis_file_system: bool @ 15,
        pub system_update: bool @ 16,
        pub save_data_meta: bool @ 17,
        pub device_save_data: bool @ 18,
        pub settings_control: bool @ 19,
        pub system_data: bool @ 20,
        pub sd_card: bool @ 21,
        pub host: bool @ 22,
        pub fill_bis: bool @ 23,
        pub corrupt_save_data: bool @ 24,
        pub save_data_for_debug: bool @ 25,
        pub format_sd_card: bool @ 26,
        pub get_rights_id: bool @ 27,
        pub register_external_key: bool @ 28,
        pub register_update_partition: bool @ 29,
        pub save_data_transfer: bool @ 30,
        pub device_detection: bool @ 31,
        pub access_failure_resolution: bool @ 32,
        pub save_data_transfer_version2: bool @ 33,
        pub register_program_index_map_info: bool @ 34,
        pub create_own_save_data: bool @ 35,
        pub move_cache_storage: bool @ 36,
        //pub _reserved: bool @ 37..=61,
        pub debug: bool @ 62,
        pub full_permission : bool @ 63,
    }
}

#[derive(BinRead,Debug)]
pub struct ServiceRecord {
    pub header: ServiceRecordHeader,
    #[br(parse_with = count(usize::from(header.len() + 1u8)))]
    pub service_name: Vec<u8>
}
/* 
pub struct ServiceRecords(pub Vec<ServiceRecord>);
impl BinRead for ServiceRecords {
    type Args = u64;

    fn read_options<R: Read + Seek>(reader: &mut R, ro: &ReadOptions, args: Self::Args) -> BinResult<Self> {
        Ok(CurPos(reader.seek(SeekFrom::Current(0))?))
    }
}
*/
bitfield!{
    #[derive(BinRead)]
    pub struct ServiceRecordHeader(u8): Debug {
        pub raw: u8 @ ..,
        pub len: u8 @ 0..=2,
        pub is_server: bool @ 7
    }
}

mod aci0 {
    use std::io::Cursor;

    use super::{FsAccessFlags, ServiceRecord, MAGIC_ACI0};

    use binrw::{BinRead, FilePtr32, prelude::*, until_eof};

    #[binread]
    #[derive(Debug)]
    #[br(assert(magic == MAGIC_ACI0))]
    pub struct Aci0 {
        #[br(temp)]
        _cursor_position: crate::utils::CurPos,
        pub magic: u32,
        pub _0x4: [u8;0xC],
        pub title_id: u64,
        pub _0x18: u64,
        pub fah_offset: u32,
        pub fah_size: u32,
        #[br(temp, parse_with = FilePtr32::parse, offset = _cursor_position.0, count = sac_size)]
        pub sac_buf: Vec<u8>,
        #[br(temp)]
        pub sac_size: u32,
        #[br(temp, calc = Cursor::new(sac_buf))]
        pub sac_cusor: Cursor<Vec<u8>>,
        #[br(parse_with = until_eof)]
        pub services: Vec<ServiceRecord>,
        pub kac_offset: u32,
        pub kac_size: u32,
        pub _padding: u64
    }

    #[derive(Debug)]
    struct KacMmioRecord {
        pub address: u64,
        pub size: u64,
        pub is_ro: bool,
        pub is_norm: bool,
        //pub next: &KacMmioRecord,
    }

    #[derive(Debug)]
    struct KacIrqRecord {
        pub irq1: u32,
        pub irq2: u32,
    // pub next: &KacIrqRecord
    }

    #[derive(Debug)]
    struct KacRecord {
        pub has_kernel_flags: bool,
        pub lowest_thread_priority: u32,
        pub hightest_thread_priority: u32,
        pub lowest_cpu_id: u32,
        pub highest_cpu_id: u32,
        pub svc_allowed: [u8;0x80],
        pub mmios: Vec<KacMmioRecord>,
        pub irqs: Vec<KacIrqRecord>,
        pub has_application_type: bool,
        pub application_type: u32,
        pub has_kernel_version: bool,
        pub kernel_version: u32,
        pub has_handle_table_size: bool,
        pub handle_table_size: u32,
        pub has_debug_flags: bool,
        pub allow_debug: bool,
        pub force_debug: bool
    }

    #[derive(Debug)]
    struct Fah {
        pub version: u32,
        pub permissions: u32,
        pub _0xC: u32,
        pub _0x10: u32,
        pub _0x14: u32,
        pub _0x18: u32
    }
   
    #[derive(Debug)]
    struct FsPermission {
        pub name: String,
        pub mask: u64
    }
}
use aci0::*;

mod acid {
    use binrw::{BinRead, count, FilePtr32, prelude::*};

    use proc_bitfield::bitfield;

    use super::{ServiceRecord, MAGIC_ACID};

    #[binread]
    #[derive(Debug)]
    #[br(assert(magic == MAGIC_ACID))]
    pub struct Acid {
        #[br(temp)]
        _cursor_position: crate::utils::CurPos,
        pub signature: [u8;0x100],
        pub nca_pub_key: [u8;0x100],
        pub magic: u32,
        pub size: u32,
        pub version: u8,
        pub v14_plus: u8,
        pub _reserved: u16,
        pub flags: u32,
        pub title_id_range_min: u64,
        pub title_id_range_max: u64,
        pub fac_offset: u32,
        pub fac_size: u32,
        #[br(parse_with = FilePtr32::parse, offset = _cursor_position.0)]
        pub sac: ServiceRecord,
        //pub sac_offset: u32,
        pub sac_size: u32,
        pub kac_offset: u32,
        pub kac_size: u32,
        pub _padding: u64
    }

    #[derive(BinRead,Debug)]
    struct AcidFsAccessControlRecord {
        pub version: u8,
        pub content_owner_id_count: u8,
        pub save_data_owner_id_count: u8,
        pub _padding: u8,
        pub access_flags: super::FsAccessFlags,
        pub content_owner_id_min: u64,
        pub content_owner_id_max: u64,
        pub save_data_owner_min: u64,
        pub save_data_owner_max: u64,
        #[br(parse_with = count(content_owner_id_count as usize))]
        pub content_owner_ids: Vec<u64>,
        #[br(parse_with = count(save_data_owner_id_count as usize))]
        pub save_data_owner_ids: Vec<u64>
    }

    #[repr(u8)]
    #[derive(Debug)]
    pub enum MemoryRegion {
        Application,
        Applet,
        SecureSystem,
        NonSecureSystem,

        Reserved
    }
    impl From<u8> for MemoryRegion {
        fn from(val: u8) -> Self {
            match val {
                0 => MemoryRegion::Application,
                1 => MemoryRegion::Applet,
                2 => MemoryRegion::SecureSystem,
                3 => MemoryRegion::NonSecureSystem,
                _ => MemoryRegion::Reserved
            }
        }
    }

    bitfield! {
        pub struct NpdmHeaderFlags(u32): Debug {
            pub raw: u32 @ .., // access raw byte

            // flags
            pub is_production: bool @ 0,
            pub unqualified_approval: bool @ 1,

            // Process Address Space Value
            pub memory_region_raw: u8 @ 1..=3,
            pub memory_region: u8 [get MemoryRegion] @ 2..=5,
        }
    }

}
use acid::*;

#[derive(Debug)]
pub enum ProcessAddressSpace {
    Address32Bit,
    Address64BitOld,
    Address64BitNoReserved,
    Address64BitNew,

    Reserved
}
impl From<u8> for ProcessAddressSpace {
    fn from(val: u8) -> Self {
        match val {
            0 => ProcessAddressSpace::Address32Bit,
            1 => ProcessAddressSpace::Address64BitOld,
            2 => ProcessAddressSpace::Address64BitNoReserved,
            3 => ProcessAddressSpace::Address64BitNew,
            _ => ProcessAddressSpace::Reserved
        }
    }
}


bitfield! {
    #[derive(BinRead)]
    pub struct NpdmHeaderFlags(u8): Debug {
        pub raw: u8 @ .., // access raw byte

        // flags
        pub is_64bit: bool @ 0,
        pub optimize_memory_allocation: bool @ 4,
        pub disable_device_address_space_merge: bool @ 5,

        // Process Address Space Value
        pub address_space_raw: u8 @ 1..=3,
        pub address_space: u8 [get ProcessAddressSpace] @ 1..=3,
    }
}


#[derive(BinRead,Debug)]
#[br(magic = b"META")]
pub struct NpdmFile {
    pub acid_sign_key_index: u32,
    pub _0x8: u32,
    pub flags: NpdmHeaderFlags,
    pub _0x_d: u8,
    pub main_thread_priority: u8,
    pub default_cpu_core: u8,
    pub _0x10: u32,
    pub system_resource_size: u32,
    pub version:u32,
    pub main_stack_size: u32,
    pub title_name: [u8;0x10],
    pub product_code: [u8;0x10],
    pub _0x40: [u8;0x30],
    #[br(parse_with = FilePtr32::parse)]
    pub aci0: Aci0,
    pub aci0_size: u32,
    #[br(parse_with = FilePtr32::parse)]
    pub acid: Acid,
    pub acid_size: u32
}


impl NpdmFile {
    pub fn parse<P: AsRef<Path>>(npdm_file: P) -> Result<NpdmFile> {

        let mut file = std::fs::File::open(npdm_file.as_ref())?;

        let parsed: NpdmFile = file.read_ne()?;

        Ok(parsed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn parse_test_ndpm() {
        let path: std::path::PathBuf = vec!["test_files", "main.npdm"].iter().collect();
        let parsed = NpdmFile::parse(path);
        assert!(parsed.is_ok());
        let parsed = parsed.unwrap();

        println!("{:x?}", parsed.acid);
    }

}