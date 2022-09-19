

pub enum KeysetType {
    Dev,
    Retail
}

pub enum SupportedFileTypes {
    Npdm,
    Pfs0
}

pub enum BaseFileType {
    Romfs,
    Nca,
    Nil
}

struct NcaKeys {
    pub secure_boot_key: [u8;0x10],
    pub tsec_key: [u8;0x10],
    pub device_key: [u8;0x10],
    pub keyblob_key: [[u8;0x10]; 0x20],
    pub keyblob_mac_key: [[u8;0xB0]; 0x20],
    pub mariko_aes_class_key: [[u8;0x10]; 0xC],
    pub mariko_kek: [u8;0x10],
    pub mariko_bek: [u8;0x10],
    pub keyblobs: [[u8;0x90]; 0x20]
    //... TODO: add the extra key types
}


struct TitleKeyEntry {
    pub rights_id: [u8;0x10],
    pub title_key: [u8;0x10],
    pub decrypted_title_key: [u8;0x10]
}

struct PathOverride {
    pub path: Box<std::path::Path>,
    pub enabled: bool
}

struct ProgramSettings {
    pub nca_keyset: NcaKeys,
    pub skip_key_warnings: bool
}