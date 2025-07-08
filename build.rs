use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

fn main() {
    let path = Path::new(&env::var("OUT_DIR").unwrap()).join("codegen.rs");
    let mut file = BufWriter::new(File::create(&path).unwrap());

    let mut map = phf_codegen::Map::new();
    map.entry(
        "aes_kek_generation_source".to_string(),
        "|keys, key| {keys.aes_kek_generation_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "aes_key_generation_source".to_string(),
        "|keys, key| {keys.aes_key_generation_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "key_area_key_application_source".to_string(),
        "|keys, key| {keys.key_area_key_application_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "key_area_key_ocean_source".to_string(),
        "|keys, key| {keys.key_area_key_ocean_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "key_area_key_system_source".to_string(),
        "|keys, key| {keys.key_area_key_system_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "titlekek_source".to_string(),
        "|keys, key| {keys.titlekek_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "header_kek_source".to_string(),
        "|keys, key| {keys.header_kek_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "header_key_source".to_string(),
        "|keys, key| {keys.header_key_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "header_key".to_string(),
        "|keys, key| {keys.header_key= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "package2_key_source".to_string(),
        "|keys, key| {keys.package2_key_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "per_console_key_source".to_string(),
        "|keys, key| {keys.per_console_key_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "xci_header_key".to_string(),
        "|keys, key| {keys.xci_header_key= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "sd_card_kek_source".to_string(),
        "|keys, key| {keys.sd_card_kek_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "sd_card_nca_key_source".to_string(),
        "|keys, key| {keys.sd_card_key_sources[1]= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "sd_card_save_key_source".to_string(),
        "|keys, key| {keys.sd_card_key_sources[0]= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "save_mac_kek_source".to_string(),
        "|keys, key| {keys.save_mac_kek_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "save_mac_key_source".to_string(),
        "|keys, key| {keys.save_mac_key_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "master_key_source".to_string(),
        "|keys, key| {keys.master_key_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "keyblob_mac_key_source".to_string(),
        "|keys, key| {keys.keyblob_mac_key_source= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "secure_boot_key".to_string(),
        "|keys, key| {keys.secure_boot_key= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "tsec_key".to_string(),
        "|keys, key| {keys.tsec_key= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "mariko_kek".to_string(),
        "|keys, key| {keys.mariko_kek= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "mariko_bek".to_string(),
        "|keys, key| {keys.mariko_bek= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "tsec_root_kek".to_string(),
        "|keys, key| {keys.tsec_root_kek= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "package1_mac_kek".to_string(),
        "|keys, key| {keys.package1_mac_kek= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "package1_kek".to_string(),
        "|keys, key| {keys.package1_kek= hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "device_key".to_string(),
        "|keys, key| {keys.device_key = hex_to_array(key)?;Ok(())}".to_string(),
    );
    map.entry(
        "save_mac_key".to_string(),
        "|keys, key| {keys.save_mac_key = hex_to_array(key)?;Ok(())}".to_string(),
    );

    map.entry(
        "beta_nca0_exponent".to_string(),
        "|_keys, key| {/* TODO */ Ok(())}".to_string(),
    );

    map.entry(
        "xci_t1_titlekey_kek_00".to_string(),
        "|_keys, key| {/* TODO */ Ok(())}".to_string(),
    );

    for index in 0..0x6u8 {
        map.entry(
            format!("keyblob_key_source_{:02x}", index),
            format!(
                "|keys, key| {{keys.keyblob_key_sources[{index}] = hex_to_array(key)?;Ok(())}}"
            ),
        );
        map.entry(
            format!("keyblob_key_{:02x}", index),
            format!("|keys, key| {{keys.keyblob_keys[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
        map.entry(
            format!("encrypted_keyblob_{:02x}", index),
            format!("|keys, key| {{keys.encrypted_keyblobs[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
        map.entry(
            format!("mariko_master_kek_source_{:02x}", index),
            format!("|keys, key| {{keys.mariko_master_kek_sources[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
        map.entry(
            format!("keyblob_{:02x}", index),
            format!("|keys, key| {{keys.keyblobs[{index}] = hex_to_array(key)?;Ok(())}}"),
        );

        map.entry(
            format!("keyblob_mac_key_{:02x}", index),
            format!("|keys, key| {{keys.keyblob_mac_keys[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
    }

    for index in 0..(0x20u8 - 0x6) {
        map.entry(
            format!("tsec_auth_signature_{:02x}", index),
            format!(
                "|keys, key| {{keys.tsec_auth_signatures[{index}] = hex_to_array(key)?;Ok(())}}"
            ),
        );
        map.entry(
            format!("tsec_root_key_{:02x}", index),
            format!("|keys, key| {{keys.tsec_root_keys[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
    }

    for index in 6..0x20u8 {
        map.entry(
            format!("master_kek_source_{:02x}", index),
            format!("|keys, key| {{keys.master_kek_sources[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
        map.entry(
            format!("mariko_master_kek_source_{:02x}", index),
            format!("|keys, key| {{keys.mariko_master_kek_sources[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
        map.entry(
            format!("package1_mac_key_{:02x}", index),
            format!("|keys, key| {{keys.package1_mac_keys[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
    }

    for index in 0..0xCu8 {
        map.entry(
            format!("mariko_aes_class_key_{:02x}", index),
            format!(
                "|keys, key| {{keys.mariko_aes_class_keys[{index}] = hex_to_array(key)?;Ok(())}}"
            ),
        );
    }

    for index in 0..0x20u8 {
        map.entry(
            format!("master_kek_{:02x}", index),
            format!("|keys, key| {{keys.master_keks[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
        map.entry(
            format!("master_key_{:02x}", index),
            format!("|keys, key| {{keys.master_keys[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
        map.entry(
            format!("package1_key_{:02x}", index),
            format!("|keys, key| {{keys.package1_keys[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
        map.entry(
            format!("package2_key_{:02x}", index),
            format!("|keys, key| {{keys.package2_keys[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
        map.entry(
            format!("titlekek_{:02x}", index),
            format!("|keys, key| {{keys.titlekeks[{index}] = hex_to_array(key)?;Ok(())}}"),
        );
        map.entry(
            format!("key_area_key_application_{:02x}", index),
            format!("|keys, key| {{keys.key_area_keys[0][{index}] = hex_to_array(key)?;Ok(())}}"),
        );
        map.entry(
            format!("key_area_key_ocean_{:02x}", index),
            format!(
                "|keys, key| {{keys.key_area_keys[1][{index}] = hex_to_array(key)?;Ok(())}}"
            ),
        );
        map.entry(
            format!("key_area_key_system_{:02x}", index),
            format!(
                "|keys, key| {{keys.key_area_keys[2][{index}] = hex_to_array(key)?;Ok(())}}"
            ),
        );
    }

    write!(
        &mut file,
        "static KEY_HANDLERS: phf::Map<&'static str, fn(&mut NcaKeys, &str) -> anyhow::Result<()>> = {}",
        map
            .build()
    )
    .unwrap();
    write!(&mut file, ";\n").unwrap();
}
