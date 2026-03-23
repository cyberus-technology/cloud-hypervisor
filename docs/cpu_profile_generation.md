# CPU Profile Generation

## Generating a CPU profile for a new target

To generate a new CPU profile you start by executing the following command

```shell
$ cargo run --release -p arch --bin generate-cpu-profile --features="cpu_profile_generation" "<Your chosen name for the CPU profile>"
```
on the machine you want to create a CPU profile for. This creates four new files in the `arch/src/x86_64/cpu_profiles` directory:
- `<chosen_name_in_snake_case>.cpuid.json`
- `<chosen_name_in_snake_case>.msr.json`
- one license file for each of the two files listed above

check them in to git and then extend the `arch::x86_64::CpuProfile` enum with a new variant for your freshly generated profile.

The final step is then to adapt `arch::x86_64::CpuProfile::cpuid_data` and `arch::x86_64::CpuProfile::msr_data` to load the
cpuid and msr JSON files we created above. After doing this you will of course have to rebuild cloud hypervisor in order to
use the new CPU profile.

## Can existing CPU profiles be updated?

More recent KVM versions may introduce more support for already existing hardware features. When this happens it is of course
tempting to run the CPU profile generation tool again with the new KVM version as we then get a profile supporting more CPU
functionality. Doing this without giving the CPU profile a new name is however a breaking change and thus not permitted.
Such PRs will **not be accepted**. Instead we encourage you add a `V2` (or higher number if `V<i>` already exists) suffix
when generating the profile.
