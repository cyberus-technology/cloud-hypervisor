use std::io::BufWriter;

use anyhow::{Context, anyhow};
#[cfg(all(
    target_arch = "x86_64",
    feature = "cpu_profile_generation",
    feature = "kvm"
))]
fn main() -> anyhow::Result<()> {
    // TODO: Consider using clap for argument parsing and allow the user to specify it with --name
    let profile_name = std::env::args()
        .nth(1)
        .ok_or(anyhow!("A name for the profile needs to be provided"))?;

    let hypervisor = hypervisor::new().context("Could not obtain hypervisor")?;
    // TODO: Consider letting the user provide a file path as a target instead of writing to stdout.
    // The way it is now should be sufficient for a PoC however.
    let writer = BufWriter::new(std::io::stdout().lock());
    arch::x86_64::cpu_profile_generation::generate_profile_data(
        writer,
        hypervisor.as_ref(),
        profile_name,
    )
}
