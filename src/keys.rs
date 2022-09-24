use std::{collections::{HashMap, hash_map::Entry}, io::{BufReader, BufRead}, fs::File, path::Path};

use hex::FromHexError;
use regex::Regex;

pub enum KeysetType {
    Dev,
    Retail
}

#[derive(Debug)]
pub struct NcaKeys {
    /// Secure boot key for use in key derivation. NOTE: CONSOLE UNIQUE.
    pub secure_boot_key: [u8; 0x10],
    /// TSEC key for use in key derivation. NOTE: CONSOLE UNIQUE.
    pub tsec_key: [u8; 0x10],
    /// Device key used to derive some FS keys. NOTE: CONSOLE UNIQUE.
    pub device_key: [u8; 0x10],
    /// Actual keys used to decrypt keyblobs. NOTE: CONSOLE UNIQUE.
    pub keyblob_keys: [[u8; 0x10]; 0x20],
    /// Keys used to validate keyblobs. NOTE: CONSOLE UNIQUE.
    pub keyblob_mac_keys: [[u8; 0x10]; 0x20],
    /// Actual encrypted keyblobs (EKS). NOTE: CONSOLE UNIQUE.
    pub encrypted_keyblobs: [[u8; 0xB0]; 0x20],
    /// AES Class Keys set by mariko bootrom.
    pub mariko_aes_class_keys: [[u8; 0x10]; 0xC],
    /// Key Encryption Key for mariko.
    pub mariko_kek: [u8; 0x10],
    /// Boot Encryption Key for mariko.
    pub mariko_bek: [u8; 0x10],
    /// Actual decrypted keyblobs (EKS).
    pub keyblobs: [[u8; 0x90]; 0x20],
    /// Seeds for keyblob keys.
    pub keyblob_key_sources: [[u8; 0x10]; 0x20],
    /// Seed for keyblob MAC key derivation.
    pub keyblob_mac_key_source: [u8; 0x10],
    /// Used to generate TSEC root keys.
    pub tsec_root_kek: [u8; 0x10],
    /// Used to generate Package1 MAC keys.
    pub package1_mac_kek: [u8; 0x10],
    /// Used to generate Package1 keys.
    pub package1_kek: [u8; 0x10],
    /// Auth signatures, seeds for tsec root key/package1 mac kek/package1 key on 6.2.0+.
    pub tsec_auth_signatures: [[u8; 0x10]; 0x20],
    /// Key for master kek decryption, from TSEC firmware on 6.2.0+.
    pub tsec_root_keys: [[u8; 0x10]; 0x20],
    /// Seeds for firmware master keks.
    pub master_kek_sources: [[u8; 0x10]; 0x20],
    /// Seeds for firmware master keks (Mariko).
    pub mariko_master_kek_sources: [[u8; 0x10]; 0x20],
    /// Firmware master keks, stored in keyblob prior to 6.2.0.
    pub master_keks: [[u8; 0x10]; 0x20],
    /// Seed for master key derivation.
    pub master_key_source: [u8; 0x10],
    /// Firmware master keys.
    pub master_keys: [[u8; 0x10]; 0x20],
    /// Package1 MAC keys.
    pub package1_mac_keys: [[u8; 0x10]; 0x20],
    /// Package1 keys.
    pub package1_keys: [[u8; 0x10]; 0x20],
    /// Package2 keys.
    pub package2_keys: [[u8; 0x10]; 0x20],
    /// Seed for Package2 key.
    pub package2_key_source: [u8; 0x10],
    /// Seed for Device key.
    pub per_console_key_source: [u8; 0x10],
    /// Seed for GenerateAesKek, usecase + generation 0.
    pub aes_kek_generation_source: [u8; 0x10],
    /// Seed for GenerateAesKey.
    pub aes_key_generation_source: [u8; 0x10],
    /// Seed for kaek 0.
    pub key_area_key_application_source: [u8; 0x10],
    /// Seed for kaek 1.
    pub key_area_key_ocean_source: [u8; 0x10],
    /// Seed for kaek 2.
    pub key_area_key_system_source: [u8; 0x10],
    /// Seed for titlekeks.
    pub titlekek_source: [u8; 0x10],
    /// Seed for header kek.
    pub header_kek_source: [u8; 0x10],
    /// Seed for SD card kek.
    pub sd_card_kek_source: [u8; 0x10],
    /// Seed for SD card encryption keys.
    pub sd_card_key_sources: [[u8; 0x20]; 2],
    /// Seed for save kek.
    pub save_mac_kek_source: [u8; 0x10],
    /// Seed for save key.
    pub save_mac_key_source: [u8; 0x10],
    /// Seed for NCA header key.
    pub header_key_source: [u8; 0x20],
    /// NCA header key.
    pub header_key: [u8; 0x20],
    /// Title key encryption keys.
    pub titlekeks: [[u8; 0x10]; 0x20],
    /// Key area encryption keys.
    pub key_area_keys: [[[u8;0x10];0x20];0x3],
    /// Key for XCI partially encrypted header.
    pub xci_header_key: [u8; 0x10],
    /// Key used to sign savedata.
    pub save_mac_key: [u8; 0x10],
    pub sd_card_keys: [[u8; 0x20]; 2],
    /// NCA header fixed key RSA pubk.
    pub nca_hdr_fixed_key_moduli: [[u8; 0x100]; 2],
    /// ACID fixed key RSA pubk.
    pub acid_fixed_key_moduli: [[u8; 0x100]; 2],
    /// Package2 Header RSA pubk.
    pub package2_fixed_key_modulus: [u8; 0x100],
}

impl NcaKeys {
    pub fn from_file<P: AsRef<Path>> (path: P) -> anyhow::Result<NcaKeys> {
        let file = File::open(path.as_ref())?;
        let regex = Regex::new("^([a-z0-9_]+) = ([a-fA-F0-9]+)").expect("Error building keyfile regex. Exiting...");
        
        let mut key_map: HashMap<String, String>= HashMap::new();
        for line in BufReader::new(file).lines() {
            match regex.captures(line?.as_ref()) {
                None => continue,
                Some(captures) => {
                    key_map.insert(captures[0].to_string(), captures[1].to_string());
                }
            }
        }

        // SAFETY: the pattern of all zeros is valid for all data types contained in `NcaKeys`
        let mut keys: NcaKeys = unsafe {std::mem::zeroed()};

        if let Some(key) = key_map.get("secure_boot_key") {
            keys.secure_boot_key = hex_to_array(key)?;
        }
        if let Some(key) = key_map.get("tsec_key") {
            keys.tsec_key = hex_to_array(key)?;
        }
        if let Some(key) = key_map.get("device_key") {
            keys.device_key = hex_to_array(key)?;
        }
        for index in 0..0x20u8 {
            let key_name = format!("keyblob_key_{:02x}", index);
            if let Some(key) = key_map.get(&key_name) {
                keys.keyblob_keys[index as usize] = hex_to_array(key)?;
            }
        }

        return Ok(keys);
    }
}

fn hex_to_array<const N: usize>(str: &str) -> Result<[u8;N], FromHexError> {
    assert_eq!(str.len(), N * 2 );

    let intermediate = hex::decode(str.as_bytes())?;
    let mut out = [0u8;N];
    out.as_mut_slice().copy_from_slice(&*intermediate);

    return Ok(out);
}