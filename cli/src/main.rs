// SPDX-FileCopyrightText: Timothée Ravier <tim@siosm.fr>
// SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::result::Result::Ok;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use log::LevelFilter;
use serde::{Deserialize, Serialize};

use std::path::PathBuf;

use compute_pcrs_lib::*;

#[derive(Parser, Debug)]
#[command(
    version,
    about,
    long_about = "Pre-compute PCR values for Bootable Container systems"
)]
struct Cli {
    /// Log verbosity. Defaults to Warn, -v for Info, -vv for Debug, -vvv for Trace
    #[arg(short = 'v', long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    #[command(subcommand)]
    command: Command,
}

#[derive(Args, Debug)]
#[group(required = true, multiple = false)]
struct SecureBootVarStores {
    #[arg(long, help = "Path to the directory storing EFIVar files")]
    efivars: Option<String>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Compute the Authentihash of a PE binary
    Authentihash {
        /// Path to a PE binary
        binary: String,
    },
    /// Compute all possible PCR values from the binaries available in the current environment. Meant to be run inside a Bootable Container.
    All {
        #[arg(
            long,
            short,
            default_value = "/usr/lib/modules/",
            help = "Path to the kernel modules directory. This helps finding the vmlinuz image"
        )]
        kernels: String,
        #[arg(
            long,
            short,
            default_value = "/usr/lib/bootupd/updates/",
            help = "Path to the ESP directory"
        )]
        esp: String,
        #[command(flatten)]
        secureboot_variables: SecureBootVarStores,
        #[arg(
            long,
            default_value_t = false,
            help = "Indicates that the linux image is an UKI image (e.g. is not vmlinuz))"
        )]
        uki: bool,
        #[arg(
            long = "secureboot-disabled",
            default_value_t = false,
            help = "Compute PCRs as if secure boot was disabled in the system"
        )]
        no_secureboot: bool,
        #[arg(
            long = "mok-variables",
            required = true,
            help = "Path to directory storing MokListRT, MokListTrustedRT and MokListXRT"
        )]
        mok_variables: String,
    },
    /// Compute PCR 4 for the non UKI case
    Pcr4NoUki {
        #[arg(
            long,
            short,
            default_value = "/usr/lib/modules/",
            help = "Path to the kernel modules directory. This helps finding the vmlinuz image"
        )]
        kernels: String,
        #[arg(
            long,
            short,
            default_value = "/usr/lib/bootupd/updates/",
            help = "Path to the ESP directory"
        )]
        esp: String,
        #[arg(
            long,
            default_value_t = false,
            help = "Indicates that the linux image is an UKI image (e.g. is not vmlinuz))"
        )]
        uki: bool,
        #[arg(
            long = "secureboot-disabled",
            default_value_t = false,
            help = "Compute PCRs as if secure boot was disabled in the system"
        )]
        no_secureboot: bool,
    },
    /// Compute PCR 4 for the Bootable Container UKI case
    Pcr4 {
        #[arg(
            long,
            short,
            default_value = "/usr/lib/bootupd/updates/EFI/fedora/shimx64.efi",
            help = "Path to the shim binary"
        )]
        shim: String,
        #[arg(
            long,
            short,
            default_value = "/usr/lib/bootupd/updates/EFI/fedora/grubx64.efi",
            help = "Path to the bootloader binary"
        )]
        bootloader: String,
        #[arg(
            long,
            short,
            default_value = "/boot/EFI/Linux/uki.efi",
            help = "Path to the UKI binary"
        )]
        uki: String,
        #[arg(
            long,
            help = "Path to a UKI addon (can be passed multiple times)"
        )]
        uki_addon: Vec<String>,
    },
    /// Compute PCR 7
    Pcr7 {
        #[arg(
            long,
            short,
            default_value = "/usr/lib/bootupd/updates/",
            help = "Path to the ESP directory"
        )]
        esp: String,
        #[command(flatten)]
        secureboot_variables: SecureBootVarStores,
        #[arg(
            long = "secureboot-disabled",
            default_value_t = false,
            help = "Compute PCRs as if secure boot was disabled in the system"
        )]
        no_secureboot: bool,
    },
    /// Compute PCR 11
    Pcr11 {
        /// Path to a UKI
        uki: String,
    },
    /// Compute PCR 14
    Pcr14 {
        #[arg(
            long = "mok-variables",
            required = true,
            help = "Path to directory storing MokListRT, MokListTrustedRT and MokListXRT"
        )]
        mok_variables: String,
    },
}

#[derive(Serialize, Deserialize)]
struct Output {
    pcrs: Vec<Pcr>,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = match cli.verbose {
        0 => LevelFilter::Warn,
        1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    env_logger::Builder::new()
        .filter(None, level)
        .format_timestamp(None)
        .init();

    match &cli.command {
        Command::Authentihash { binary} => {
            let hash = authentihash(&PathBuf::from(binary)).unwrap();
            println!("{hash}");
            Ok(())
        },
        Command::All {
            kernels,
            esp,
            secureboot_variables,
            uki,
            no_secureboot,
            mok_variables,
        } => {
            let pcrs = vec![
                compute_pcr4_nouki(kernels, esp, *uki, !no_secureboot),
                compute_pcr7(secureboot_variables.efivars.as_deref(), esp, !no_secureboot),
                /* compute_pcr11(), */
                compute_pcr14(mok_variables),
            ];
            println!(
                "{}",
                serde_json::to_string_pretty(&Output { pcrs }).unwrap()
            );
            Ok(())
        }
        Command::Pcr4NoUki {
            kernels,
            esp,
            uki,
            no_secureboot,
        } => {
            let pcr = compute_pcr4_nouki(kernels, esp, *uki, !no_secureboot);
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
        Command::Pcr4 {
            shim,
            bootloader,
            uki,
            uki_addon,
        } => {
            log::debug!("{uki_addon:?}");
            let pcr = compute_pcr4(shim, bootloader, uki, uki_addon);
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
        Command::Pcr7 {
            esp,
            secureboot_variables,
            no_secureboot,
        } => {
            let pcr = compute_pcr7(secureboot_variables.efivars.as_deref(), esp, !no_secureboot);
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
        Command::Pcr11 { uki } => {
            let pcr = compute_pcr11(uki);
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
        Command::Pcr14 { mok_variables } => {
            let pcr = compute_pcr14(mok_variables);
            println!("{}", serde_json::to_string_pretty(&pcr).unwrap());
            Ok(())
        }
    }
}
