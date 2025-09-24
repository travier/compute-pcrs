// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use crate::uefi::efivars::{EFIVarsLoader, SECURE_BOOT_ATTR_HEADER_LENGTH};
use crate::uefi::secureboot::{SecureBootdbLoader, collect_secure_boot_hashes};
use lief::generic::Section;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

use std::path::PathBuf;

pub mod certs;
mod esp;
mod linux;
mod mok;
pub mod pefile;
pub mod shim;
pub mod uefi;

#[derive(Clone, Serialize, Deserialize)]
pub struct Part {
    pub name: String,
    pub hash: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Pcr {
    pub id: u64,
    pub value: String,
    pub parts: Vec<Part>,
}

pub fn authentihash(binary: &PathBuf) -> Option<String> {
    let pe = pefile::PeFile::load_from_file(&binary.to_string_lossy(), false)?;
    Some(hex::encode(pe.authenticode()))
}

pub fn compute_pcr4(shim: &str, bootloader: &str, uki: &str, uki_addons: &Vec<String>) -> Pcr {
    let ev_efi_action_hash: Vec<u8> =
        Sha256::digest(b"Calling EFI Application from Boot Option").to_vec();
    let ev_separator_hash: Vec<u8> = Sha256::digest(hex::decode("00000000").unwrap()).to_vec();

    let mut hashes: Vec<(String, Vec<u8>)> = vec![];
    hashes.push(("EV_EFI_ACTION".into(), ev_efi_action_hash));
    hashes.push(("EV_SEPARATOR".into(), ev_separator_hash));

    let mut bins: Vec<PathBuf> = vec![shim.into(), bootloader.into(), uki.into()];
    for addon in uki_addons {
        bins.push(addon.into());
    }

    // println!("{bins:?}");

    let mut bin_hashes: Vec<(String, Vec<u8>)> = bins
        .iter()
        .map(|b| ("EV_EFI_BOOT_SERVICES_APPLICATION".into(), pefile::PeFile::load_from_file(&b.to_string_lossy(), false).expect("Can't open binary").authenticode()))
        .collect();
    hashes.append(&mut bin_hashes);

    // Start with 0
    let mut result =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .to_vec();

    for (_p, h) in &hashes {
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.update(h);
        result = hasher.finalize().to_vec();
    }

    Pcr {
        id: 4,
        value: hex::encode(result),
        parts: hashes
            .iter()
            .map(|(p, h)| Part {
                name: p.to_string(),
                hash: hex::encode(h),
            })
            .collect(),
    }
}

pub fn compute_pcr4_nouki(kernels_dir: &str, esp_path: &str, uki: bool, secureboot: bool) -> Pcr {
    let esp = esp::Esp::new(esp_path).unwrap();

    let ev_efi_action_hash: Vec<u8> =
        Sha256::digest(b"Calling EFI Application from Boot Option").to_vec();
    let ev_separator_hash: Vec<u8> = Sha256::digest(hex::decode("00000000").unwrap()).to_vec();

    let mut hashes: Vec<(String, Vec<u8>)> = vec![];
    hashes.push(("EV_EFI_ACTION".into(), ev_efi_action_hash));
    hashes.push(("EV_SEPARATOR".into(), ev_separator_hash));

    let mut bins = vec![esp.shim(), esp.grub()];

    if secureboot && !uki {
        bins.push(linux::load_vmlinuz(kernels_dir).unwrap())
    }
    // TODO: write condition for uki and implement logic

    let mut bin_hashes: Vec<(String, Vec<u8>)> = bins
        .iter()
        .map(|b| ("EV_EFI_BOOT_SERVICES_APPLICATION".into(), b.authenticode()))
        .collect();
    hashes.append(&mut bin_hashes);

    // Start with 0
    let mut result =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .to_vec();

    for (_p, h) in &hashes {
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.update(h);
        result = hasher.finalize().to_vec();
    }

    Pcr {
        id: 4,
        value: hex::encode(result),
        parts: hashes
            .iter()
            .map(|(p, h)| Part {
                name: p.to_string(),
                hash: hex::encode(h),
            })
            .collect(),
    }
}

pub fn compute_pcr11(uki: &str) -> Pcr {
    let sections: Vec<&str> = vec![".linux", ".osrel", ".cmdline", ".initrd", ".uname", ".sbat"];

    let pe: lief::pe::Binary = lief::pe::Binary::parse(uki).unwrap();
    let mut hashes: Vec<(String, Vec<u8>)> = vec![];
    sections.iter().for_each(|s| {
        let section = pe.section_by_name(s).unwrap();
        hashes.push(((*s).into(), Sha256::digest(format!("{s}\0")).to_vec()));
        hashes.push(((*s).into(), Sha256::digest(section.content()).to_vec()));
    });

    // Start with 0
    let mut result =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .to_vec();

    for (_s, h) in &hashes {
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.update(h);
        result = hasher.finalize().to_vec();
    }

    // println!("{}", hex::encode(&result));

    Pcr {
        id: 11,
        value: hex::encode(result),
        parts: hashes
            .iter()
            .map(|(s, h)| Part {
                name: s.into(),
                hash: hex::encode(h),
            })
            .collect(),
    }
}

/// PCR 7 contains the digests of the variables defining the Secure Boot
/// state. It's extended by the following events:
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: SecureBoot
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: PK
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: KEK
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: db
///    - EV_EFI_VARIABLE_DRIVER_CONFIG: dbx
///    - EV_SEPARATOR
///    - EV_EFI_VARIABLE_AUTHORITY: db
///    - EV_EFI_VARIABLE_AUTHORITY: SbatLevel
///    - EV_EFI_VARIABLE_AUTHORITY: MokListRT
///
/// EFI vars are needed to compute pcr7.
/// EFI vars can be loaded from
///     - efivars
///
pub fn compute_pcr7(efivars_path: Option<&str>, esp_path: &str, secureboot_enabled: bool) -> Pcr {
    let esp = esp::Esp::new(esp_path).unwrap();
    let mut hashes: Vec<(String, Vec<u8>)> = vec![(
        "EV_EFI_VARIABLE_DRIVER_CONFIG".into(),
        uefi::get_secureboot_state_event(secureboot_enabled).hash(),
    )];
    let sb_var_loader = EFIVarsLoader::new(
        efivars_path.expect("No efivars directory path provided"),
        SECURE_BOOT_ATTR_HEADER_LENGTH,
    );

    // Extend PCR7 with events for PK, KEK, db and dbx
    hashes.extend(collect_secure_boot_hashes(sb_var_loader.clone()));

    hashes.push((
        "EV_SEPARATOR".into(),
        Sha256::digest(hex::decode("00000000").unwrap()).to_vec(),
    ));

    let shim_bin = esp.shim();
    let sb_db = sb_var_loader.secureboot_db();
    let sb_db_certs = crate::certs::get_db_certs(&sb_db).unwrap();
    if secureboot_enabled {
        let shim_cert = shim_bin.find_cert_in_db(&sb_db_certs);
        match shim_cert {
            Some(cert) => hashes.push((
                "EV_EFI_VARIABLE_AUTHORITY".into(),
                uefi::UEFIVariableData::new(uefi::GUID_SECURITY_DATABASE, "db", cert).hash(),
            )),
            None => panic!("Can't find shim signature certificate in secure boot db"),
        }
    }

    let sbatlevel_raw = shim_bin.section(shim::SHIM_SBATLEVEL_SECTION);
    if sbatlevel_raw.is_none() || !secureboot_enabled {
        hashes.push((
            "EV_EFI_VARIABLE_AUTHORITY".into(),
            shim::get_sbat_var_original_uefivar().hash(),
        ));
    } else if let Some(data) = sbatlevel_raw {
        let sbatlevel = shim::get_sbatlevel_uefivar(&data, &shim::SbatLevelPolicyType::PREVIOUS);
        hashes.push(("EV_EFI_VARIABLE_AUTHORITY".into(), sbatlevel.hash()));
    }

    if secureboot_enabled {
        let mut logged_cert_hashes = HashSet::new();
        let shim_vendor_cert = shim_bin.vendor_cert();
        let shim_vendor_db = shim_bin.vendor_db();
        // In the case of UKI, the UKI and UKI addons should be processed
        let binaries = vec![esp.grub()];
        for bin in binaries {
            // look for cert in secureboot
            if let Some(sb_cert) = bin.find_cert_in_db(&sb_db_certs) {
                let hash =
                    uefi::UEFIVariableData::new(uefi::GUID_SECURITY_DATABASE, "db", sb_cert).hash();
                if !logged_cert_hashes.contains(&hash) {
                    logged_cert_hashes.insert(hash.clone());
                    hashes.push(("EV_EFI_VARIABLE_AUTHORITY".into(), hash));
                }
            }

            // look for cert in shim vendor db
            if let Some(vendor_db) = bin.find_cert_in_db(&shim_vendor_db) {
                let hash = uefi::UEFIVariableData::new(
                    uefi::GUID_SECURITY_DATABASE,
                    "vendor_db",
                    vendor_db,
                )
                .hash();
                if !logged_cert_hashes.contains(&hash) {
                    logged_cert_hashes.insert(hash.clone());
                    hashes.push(("EV_EFI_VARIABLE_AUTHORITY".into(), hash));
                }
            }

            // look for cert in shim vendor cert
            if let Some(vendor_cert) = bin.find_cert_in_db(&shim_vendor_cert) {
                let mut vendor_cert_data = uefi::guid_to_le_bytes(&uefi::GUID_SHIM_LOCK);
                vendor_cert_data.extend(&vendor_cert);
                let hash = uefi::UEFIVariableData::new(
                    uefi::GUID_SHIM_LOCK,
                    "MokListRT",
                    vendor_cert_data,
                )
                .hash();
                if !logged_cert_hashes.contains(&hash) {
                    logged_cert_hashes.insert(hash.clone());
                    hashes.push(("EV_EFI_VARIABLE_AUTHORITY".into(), hash));
                }
            }
        }
    }

    let mut result =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .to_vec();

    for (_s, h) in &hashes {
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.update(h);
        result = hasher.finalize().to_vec();
    }

    Pcr {
        id: 7,
        value: hex::encode(result),
        parts: hashes
            .iter()
            .map(|(s, h)| Part {
                name: s.into(),
                hash: hex::encode(h),
            })
            .collect(),
    }
}

pub fn compute_pcr14(mok_variables: &str) -> Pcr {
    let mok_event_loader = mok::MokEventHashes::new(mok_variables);

    let elems: Vec<(String, Vec<u8>)> = mok_event_loader.map(|h| ("EV_IPL".into(), h)).collect();

    let mut result =
        hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap()
            .to_vec();
    for (_, h) in &elems {
        let mut hasher = Sha256::new();
        hasher.update(result);
        hasher.update(h);
        result = hasher.finalize().to_vec();
    }

    Pcr {
        id: 14,
        value: hex::encode(result),
        parts: elems
            .iter()
            .map(|(e, h)| Part {
                name: e.clone(),
                hash: hex::encode(h),
            })
            .collect(),
    }
}
