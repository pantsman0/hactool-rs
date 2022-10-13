use std::{path::Path, io::Cursor};

use binrw::{BinRead, BinReaderExt, FilePtr32, BinResult, binread};
use num_enum::{FromPrimitive, IntoPrimitive};
use proc_bitfield::bitfield;
use rsa:: pss::{VerifyingKey, Signature};
use sha2::Sha256;
use signature::Verifier;

use crate::{utils::Placement, keys::KeysetType};
use super::Validity;


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
    #[br(count = header.len())]
    pub service_name: Vec<u8>
}
bitfield!{
    #[derive(BinRead)]
    pub struct ServiceRecordHeader(u8): Debug {
        pub raw: u8 @ ..,
        pub len: u8 @ 0..=2,
        pub is_server: bool @ 7
    }
}

mod kernel_capability {

    use binrw::BinRead;
    use num_enum::{IntoPrimitive, FromPrimitive};
    use proc_bitfield::bitfield;

    #[derive(Debug)]
    pub enum KernelCapability {
        ThreadInfo(ThreadInfo),
        EnableSystemCalls(SystemCalls),
        MemoryMap(MemoryMapAddrRo, MemoryMapSizeType),
        IoMemoryMap(IoMemoryMap),
        MemoryRegionMap(MemoryRegionMap),
        EnableInterrupts(Interrupts),
        MiscParams(MiscParams),
        KernelVersion(KernelVersion),
        HandleTableSize(HandleTableSize),
        MiscFlags(MiscFlags),
        Invalid(u32)
    }

    bitfield! {
        pub struct ThreadInfo(u32): Debug {
            pub raw: u32 @ ..,
            pub lowest_thread_priority: u8 @ 4..=9,
            pub hightest_thread_priority: u8@ 10..=15,
            pub lowest_cpu_id: u8 @ 16..=23,
            pub highest_cpu_id: u8 @ 24..=31,
        }
    }

    
    bitfield!{
        pub struct SystemCalls(u32): Debug {
            pub raw: u32 @ ..,
            pub syscall_id: i32 @ 5..=28,
            pub index: u8 @ 29..=31
        }
    }
    
    #[repr(u8)]
    #[derive(Debug,IntoPrimitive, FromPrimitive)]
    pub enum MemoryMapPermission {
        #[default]
        Rw = 0,
        Ro
    }
    #[repr(u8)]
    #[derive(Debug,IntoPrimitive, FromPrimitive)]
    pub enum MemoryMapType {
        #[default]
        Io,
        Static
    }
    bitfield!{
        pub struct MemoryMapAddrRo(u32): Debug {
            pub raw: u32 @ ..,
            pub start_address: u32 @ 7..=30,
            pub memory_permission: u8 [MemoryMapPermission] @ 31..=31
        }
    } 
    bitfield!{
        pub struct MemoryMapSizeType(u32): Debug {
            pub raw: u32 @ ..,
            pub size: u32 @ 7..=26,
            pub map_type: u8 [MemoryMapType] @ 31..=31
        }
    } 
    
    bitfield!{
        pub struct IoMemoryMap(u32): Debug{
            pub raw: u32 @ ..,
            pub start_address: u32 @ 8..=31
        }
    }

    #[repr(u8)]
    #[derive(Debug,IntoPrimitive, FromPrimitive)]
    pub enum MemoryRegionType {
        NoMapping = 0,
        KernelTraceBuffer,
        OnMemoryBootImage,
        DTB,

        #[default]
        Invalid
    }
    bitfield! {
        pub struct MemoryRegionMap(u32): Debug {
            pub raw: u32 @ ..,
            pub region0_type: u8 [MemoryRegionType] @ 11..=16,
            pub region0_is_ro: bool @ 17,
            pub region1_type: u8 [MemoryRegionType] @ 18..=23,
            pub region1_is_ro: bool @ 24,
            pub region2_type: u8 [MemoryRegionType] @ 25..=30,
            pub region2_is_ro: bool @ 31
        }
    }

    bitfield! {
        pub struct Interrupts(u32): Debug {
            pub raw: u32 @ ..,
            pub irq1: u16 @ 12..=21,
            pub irq2: u16 @ 22..=31
        }
    }

    #[repr(u8)]
    #[derive(Debug,IntoPrimitive, FromPrimitive)]
    pub enum ProgramType {
        System = 0,
        Application,
        Applet,

        #[default]
        Invalid
    }
    bitfield! {
        pub struct MiscParams(u32): Debug {
            pub raw: u32 @ ..,
            pub program_type: u8 [ProgramType] @ 14..=16,
        }
    }

    bitfield!{
        pub struct KernelVersion(u32): Debug {
            pub raw: u32 @ ..,
            pub minor_version: u8 @ 15..=18,
            pub major_version: u16 @ 19..=31 
        }
    }
    bitfield!{
        pub struct HandleTableSize(u32): Debug {
            pub raw: u32 @ ..,
            pub table_size: u16 @ 16..=25
        }
    }
    bitfield!{
        pub struct MiscFlags(u32): Debug {
            pub raw: u32 @ ..,
            pub enable_debug: bool @ 17,
            pub force_debug: bool @ 18
        }
    }

    impl BinRead for KernelCapability {
        type Args = ();
        fn read_options<R: std::io::Read + std::io::Seek>(
                reader: &mut R,
                options: &binrw::ReadOptions,
                args: Self::Args,
            ) -> binrw::BinResult<Self> {
                let raw_kc = u32::read_options(reader, options, args)?;
                match raw_kc.trailing_ones() {
                    3 => Ok(Self::ThreadInfo(ThreadInfo(raw_kc))),
                    4 => Ok(Self::EnableSystemCalls(SystemCalls(raw_kc))),
                    6 => {
                        //MemoryMaps come in pairs of 2 so the next one also needs to also have 6 trailing ones
                        let raw_kc2 = u32::read_options(reader, options, args)?;
                        if raw_kc2.trailing_ones() != 6 {
                            return Err(binrw::Error::AssertFail { pos: (reader.stream_position()?-4), message: String::from("Error: MemoryMap value found without surrogate value")})
                        }
                        Ok(Self::MemoryMap(MemoryMapAddrRo(raw_kc), MemoryMapSizeType(raw_kc2)))
                    },
                    7 => Ok(Self::IoMemoryMap(IoMemoryMap(raw_kc))),
                    10=> Ok(Self::MemoryRegionMap(MemoryRegionMap(raw_kc))),
                    11=> Ok(Self::EnableInterrupts(Interrupts(raw_kc))),
                    13=> Ok(Self::MiscParams(MiscParams(raw_kc))),
                    14=> Ok(Self::KernelVersion(KernelVersion(raw_kc))),
                    15=> Ok(Self::HandleTableSize(HandleTableSize(raw_kc))),
                    16=> Ok(Self::MiscFlags(MiscFlags(raw_kc))),
                    _ => Ok(Self::Invalid(raw_kc))
                }
        }
    }
}
mod aci0 {
    use core::mem::size_of;

    use crate::utils::{until_eob, Placement};

    use super::{FsAccessFlags, ServiceRecord, MAGIC_ACI0, kernel_capability::KernelCapability};

    use binrw::prelude::*;

    #[binread]
    #[derive(Debug)]
    #[br(little, assert(magic == MAGIC_ACI0))]
    pub struct Aci0 {
        #[br(temp)]
        _cursor_position: crate::utils::CurPos,
        pub magic: u32,
        pub _0x4: [u8;0xC],
        pub title_id: u64,
        pub _0x18: u64,
        pub fah_offset: u32,
        pub fah_size: u32,
        #[br(temp)] services_buffer_offset: u32,
        #[br(temp)] services_buffer_bytes: u32,
        #[br(temp, parse_with = Placement::parse, offset = _cursor_position.0 + services_buffer_offset as u64 , count = services_buffer_bytes)]
        services_buffer: Vec<u8>,
        #[br(parse_with = until_eob(services_buffer))]
        pub services: Vec<ServiceRecord>,
        #[br(temp)] kernel_capability_buffer_offset: u32,
        #[br(temp)] kernel_capability_buffer_size: u32,
        #[br(temp, parse_with = Placement::parse, offset = _cursor_position.0 + kernel_capability_buffer_offset as u64 , count = kernel_capability_buffer_size as usize)]
        kernel_capability_buffer: Vec<u8>,
        #[br(parse_with = until_eob(kernel_capability_buffer))]
        pub kernel_capabilities: Vec<KernelCapability>,
        pub _padding: u64
    }

    #[binread]
    #[derive(Debug)]
    pub struct Aci0FsAccessControlRecord {
        #[br(temp)]
        _cursor_position: crate::utils::CurPos,
        pub version: u8,
        #[br(temp, count = 3)]
        pub _padding: Vec<u8>,
        pub access_flags: FsAccessFlags,
        #[br(temp)] content_owner_id_buffer_offset: u32,
        #[br(temp)] content_owner_id_buffer_size: u32,
        #[br(parse_with = Placement::parse, offset = _cursor_position.0 + content_owner_id_buffer_offset as u64 , count = (content_owner_id_buffer_size as usize / size_of::<u64>()))]
        pub content_owner_ids: Vec<u64>,
        #[br(temp)] save_data_owner_id_buffer_offset: u32,
        #[br(temp)] save_data_owner_id_buffer_size: u32,
        #[br(parse_with = Placement::parse, offset = _cursor_position.0 + save_data_owner_id_buffer_offset as u64 , count = (save_data_owner_id_buffer_size as usize / size_of::<u64>()))]
        pub save_data_owner_ids: Vec<u64>,
        #[br(if(content_owner_id_buffer_offset != 0x1C))]
        pub save_data_owner_id_count: Option<u32>
    }
}
use aci0::*;

mod acid {

    use binrw::prelude::*;

    use num_enum::{FromPrimitive, IntoPrimitive};
    use proc_bitfield::bitfield;

    use crate::utils::{until_eob, Placement};

    use super::{ServiceRecord, MAGIC_ACID, kernel_capability::KernelCapability};

    #[binread]
    #[derive(Debug)]
    #[br(little, assert(magic == MAGIC_ACID))]
    pub struct Acid {
        #[br(temp)]
        _cursor_position: crate::utils::CurPos,
        pub signature: [u8;0x100],
        pub modulus: [u8;0x100],
        pub magic: u32,
        pub size: u32,
        pub version: u8,
        #[brw(pad_after = 2)]
        pub v14_plus: u8,
        pub flags: AcidFlags,
        pub title_id_range_min: u64,
        pub title_id_range_max: u64,
        #[br(temp)] fac_buffer_offset: u32,
        #[br(temp)] fac_buffer_size: u32,
        #[br(temp, parse_with = Placement::parse, offset = _cursor_position.0 + fac_buffer_offset as u64 , count = fac_buffer_size)]
        fac_buffer: Vec<u8>,
        #[br(parse_with = until_eob(fac_buffer))]
        pub file_access_control_entries: Vec<AcidFsAccessControlRecord>,
        #[br(temp)] services_buffer_offset: u32,
        #[br(temp)] services_buffer_bytes: u32,
        #[br(temp, parse_with = Placement::parse, offset = _cursor_position.0 + services_buffer_offset as u64 , count = services_buffer_bytes)]
        services_buffer: Vec<u8>,
        #[br(parse_with = until_eob(services_buffer))]
        pub services: Vec<ServiceRecord>,
        #[br(temp)] kernel_capability_buffer_offset: u32,
        #[br(temp)] kernel_capability_buffer_size: u32,
        #[br(temp, parse_with = Placement::parse, offset = _cursor_position.0 + kernel_capability_buffer_offset as u64 , count = kernel_capability_buffer_size as usize)]
        kernel_capability_buffer: Vec<u8>,
        #[br(parse_with = until_eob(kernel_capability_buffer), pad_after = 8)]
        pub kernel_capabilities: Vec<KernelCapability>
    }

    #[binread]
    #[derive(Debug)]
    pub struct AcidFsAccessControlRecord {
        pub version: u8,
        pub content_owner_id_count: u8,
        #[brw(pad_after = 1)]
        pub save_data_owner_id_count: u8,
        pub access_flags: super::FsAccessFlags,
        pub content_owner_id_min: u64,
        pub content_owner_id_max: u64,
        pub save_data_owner_min: u64,
        pub save_data_owner_max: u64,
        #[br(count = content_owner_id_count as usize)]
        pub content_owner_ids: Vec<u64>,
        #[br(count = save_data_owner_id_count as usize)]
        pub save_data_owner_ids: Vec<u64>
    }

    #[repr(u8)]
    #[derive(Debug, FromPrimitive, IntoPrimitive)]
    pub enum MemoryRegion {
        Application = 0,
        Applet,
        SecureSystem,
        NonSecureSystem,

        #[default]
        Reserved
    }

    bitfield! {
        #[derive(BinRead)]
        pub struct AcidFlags(u32): Debug {
            pub raw: u32 @ .., // access raw byte

            // flags
            pub is_production: bool @ 0,
            pub unqualified_approval: bool @ 1,

            // Process Address Space Value
            pub memory_region_raw: u8 @ 1..=3,
            pub memory_region: u8 [MemoryRegion] @ 2..=5,
        }
    }

}
use acid::*;

#[derive(Debug,FromPrimitive,IntoPrimitive)]
#[repr(u8)]
pub enum ProcessAddressSpace {
    Address32Bit,
    Address64BitOld,
    Address64BitNoReserved,
    Address64BitNew,

    #[default]
    Reserved
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
        pub address_space: u8 [ProcessAddressSpace] @ 1..=3,
    }
}

#[binread]
#[derive(Debug)]
#[br(little, magic = b"META")]
pub struct NpdmFile {
    #[brw(pad_after = 4)]
    pub acid_sign_key_index: u32,
    #[brw(pad_after = 1)]
    pub flags: NpdmHeaderFlags,
    pub main_thread_priority: u8,
    #[brw(pad_after = 4)]
    pub default_cpu_core: u8,
    pub system_resource_size: u32,
    pub version:u32,
    pub main_stack_size: u32,
    pub title_name: [u8;0x10],
    #[brw(pad_after = 0x30)]
    pub product_code: [u8;0x10],
    #[br(parse_with = FilePtr32::parse)]
    pub aci0: Aci0,
    pub aci0_size: u32,
    #[br(temp)]
    acid_ptr: u32,
    #[br(temp)]
    acid_size: u32,
    #[br(parse_with = Placement::parse, offset = acid_ptr as u64, count = acid_size)]
    acid_raw: Vec<u8>,
    #[br(calc = Cursor::new(acid_raw.clone()).read_le()?)]
    pub acid: Acid
}


impl NpdmFile {
    pub fn parse<P: AsRef<Path>>(npdm_file: P) -> BinResult<NpdmFile> {

        let mut file = std::fs::File::open(npdm_file.as_ref())?;

        file.read_le()
    }

    pub fn verify_with_hex_str(&self, verification_key_modulus: String) -> Result<Validity, Validity> {
        if let Some(modulus_bigint) = rsa::BigUint::from_radix_le(verification_key_modulus.as_bytes(), 16) {
            let exponent = rsa::BigUint::from_bytes_le([1u8,0, 1].as_slice());
            if let Ok(rsa_pubkey) = rsa::RsaPublicKey::new(modulus_bigint, exponent){
                let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(rsa_pubkey);
                let signature: Signature = Vec::from(self.acid.signature.as_slice()).into();
                let valid = verifying_key.verify(self.acid_raw.split_at(0x200).1 , &signature).is_ok();

                return if valid { Ok(Validity::Valid)} else {Ok(Validity::Invalid)};
            } else {
                return  Err(Validity::CheckError);
            }
        } 
        return Err(Validity::CheckError);
    }

    pub fn verify_acid(&self, key_type: KeysetType) -> Result<Validity, Validity> {
        if self.acid_sign_key_index > 1 { return Err(Validity::Invalid); }
        let acid_sign_key = match key_type {
            KeysetType::Retail => crate::keys::constants::retail_keys::ACID_FIXED_KEY_MODULI[self.acid_sign_key_index as usize],
            KeysetType::Dev => crate::keys::constants::development_keys::ACID_FIXED_KEY_MODULI[self.acid_sign_key_index as usize]
        };
        let modulus_bigint = rsa::BigUint::from_bytes_be(acid_sign_key.as_slice());
        let exponent = rsa::BigUint::from_bytes_be([1,0,1].as_slice());
        let rsa_pubkey = rsa::RsaPublicKey::new(modulus_bigint, exponent).map_err(|_| Validity::CheckError)?;
        let verifying_key: VerifyingKey<Sha256> = VerifyingKey::new(rsa_pubkey);
        let signature: Signature = Vec::from(self.acid.signature.as_slice()).into();
        let data = self.acid_raw.split_at(0x100).1;
        println!("{:?}",data.len());
        let validity = verifying_key.verify(data, &signature);

        println!("{:?}", validity);
        return if validity.is_ok() { 
            Ok(Validity::Valid)
        } else {
            Ok(Validity::Invalid)
        };
    }
}
