// Copyright © 2025 Cyberus Technology GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
#![cfg(all(
    target_arch = "x86_64",
    feature = "cpu_profile_generation",
    feature = "kvm"
))]

use anyhow::Context;
use clap::{Arg, Command};

fn main() -> anyhow::Result<()> {
    let cmd_arg = Command::new("generate-cpu-profile")
        .version(env!("CARGO_PKG_VERSION"))
        .arg_required_else_help(true)
        .arg(
            Arg::new("name")
                .help("The name to give the CPU profile")
                .num_args(1)
                .required(true),
        )
        .get_matches();

    let profile_name = cmd_arg.get_one::<String>("name").unwrap();

    let hypervisor = hypervisor::new().context("Could not obtain hypervisor")?;
    arch::x86_64::cpu_profile_generation::generate_profile_data(hypervisor.as_ref(), profile_name)
}
