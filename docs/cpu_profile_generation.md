# CPU Profile Generation

## Generating a CPU profile for a new target

To generate a new CPU profile you execute the following command

```shell
$ cargo run --release -p arch --bin generate-cpu-profile --features="cpu_profile_generation" "<Your chosen name for the CPU profile>"
```
on the machine you want to create a CPU profile for. This creates four new files in the `arch/src/x86_64/cpu_profiles` directory:
- `<chosen-name-in-kebab-case>.cpuid.json`
- `<chosen-name-in-kebab-case>.msr.json`
- one license file for each of the two files listed above

check them in to git and then simply rebuild cloud-hypervisor `cargo build --release --bin cloud-hypervisor`.

You can now use the new profile by adding `,profile=<chosen-name-in-kebab-case>` to the list of `--cpus` configuration
options on the command line.

## Can existing CPU profiles be updated?

More recent KVM versions may introduce more support for already existing hardware features. When this happens it is of course
tempting to run the CPU profile generation tool again with the new KVM version as we then get a profile supporting more CPU
functionality. Doing this without giving the CPU profile a new name is however a breaking change and thus not permitted.
Such PRs will **not be accepted**. Instead we encourage you add a `V2` (or higher number if `V<i>` already exists) suffix
when generating the profile.
