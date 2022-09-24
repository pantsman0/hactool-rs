



pub enum BaseFileType {
    Romfs,
    Nca,
    Nil
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
    pub nca_keyset: crate::keys::NcaKeys,
    pub skip_key_warnings: bool
}