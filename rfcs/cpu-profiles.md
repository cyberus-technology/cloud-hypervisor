- Start Date: 2025-07-18

# Summary

Add a `CpuProfile` parameter to restrict the set of CPU features a VM may utilize.

# Motiviation

## More migration targets

A running VM can only be migrated to a different host if the target host supports every CPU feature that the
running VM may utilize. While cloud hypervisor already performs checks to ensure that this is indeed the case
(in order for the migration to be performed safely), there are few ways to restrict which CPU features a VM may
utilize at startup. This in turn limits the set of possible migration targets.

As an example a VM running on a host supporting the [x86-64-v4 microarchitecture level](https://en.wikipedia.org/w/index.php?title=X86-64&oldid=1301541626#Microarchitecture_levels)
cannot be migrated to one that only supports the x86-64-v3 level, even though the creator of the VM knows
all their workloads to also be compatible with the latter.

# Explanation

Recall the `CpusConfig` structure which is currently part of the `VmConfig` that users set when creating a new VM.
We propose extending it with an additional field `profile` of type `CpuProfile` which is an enum of the supported
profiles. It may look something like this and can be extended with more variants in the future:

```rust
#[derive(Default, Serialize, Deserialize)]
pub enum CpuProfile {
  /// The CPU features of the host are passed through to the virtual CPUs in the VM.
  #[default]
  Host,
  /// The CPU features supported by the first generation of Intel's Skylake server CPUs.
  SkylakeServerV1,
}
```
Note that the default is `Host` which corresponds to the current behaviour of passing as many of the
host's CPU features to guests as possible.

We propose that the initial implementation only focuses on the x86-64 arch, but may be extended to include
profiles of other architectures in the future.

Upon VM creation the `CpuProfile` is extracted (if set, otherwise the default `CpuProfile::Host` will be used)
and converted to an array of `CpuIdEntry` structs which are used internally to read and manipulate the available
CPU features/ feature flags. These entries will then in turn be combined with all other pre-existing cpu id entry
manipulations (such as `tdx` and `amx` configuration for instance) before they ultimately get passed to `KVM_SET_CPUID2`
thus restricting the CPU features the virtual CPUs may take advantage of.

The snapshot restoration and migration functionality will have to be adapted to also take the `CpuProfile` into account,
but note that they at least already do operate on the existing `VmConfig` hence this will not be a direct user facing change.

We re-emphasize that the addition proposed here does not bring any additional safety guarantees with regards to live migration
as the compatibility of CPU features is already checked. The main benefit of this addition is that one can increase the set
of compatible migration targets by restricting the virtual CPUs to only have access to common subsets of CPU features of the
known hosts.

## Interaction with related CPU configurations

Cpu configuration with their own parameters are not affected by the choice of `CpuProfile`. We acknowledge that
this may confuse some users, but consider it a necessary evil to 1) Not overcomplicate the `CpuProfile` concept
with all kinds of complex extension points, and 2) keep this RFC as a backward compatible stritcly additive
change.

### Interaction with `CpuFeatures`

The pre-existing [`CpuFeatues`](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/cpu.md#features)
will always take precedence over `CpuProfile`. This means that any feature that is disabled by default may
only be enabled via explicitly placing it in `CpuFeatures` (if possible), regardless of whether said feature is
supported by the CPU generation or CPU feature set selected in `CpuProfile`.

### Interaction with SGX and TDX

Similarly to the case with [`CpuFeatures`](#interaction-with-cpufeatures) the use of either SGX or TDX is
independent from whatever is set in the `CpuProfile` and continues to be enabled in exactly the same manner
as previously.

# Drawbacks

- Users are at risk of misunderstanding how this feature interacts with related features
such as for instance `CpuFeatures`, SGX and TDX support. 
- This feature requires more code, with non-trivial interactions with existing code thus
making the code base more complex.

# Rationale and alternatives

## Adapting the pre-existing `CpuFeatures` set

If users were to set the CPU features available for virtual CPUs via the [`CpuFeature set`](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/docs/cpu.md#features)
then this would first of all inevitably be a breaking change. Indeed, recall that this is currently defined
as CPU features that are disabled by default. Hence if we are to add more possible features to this set  then
they must all be disabled by default which is a breaking change (Recall that `amx` is the only feature that may
be specified in this set as of now). This approach will force users to write out a lot of features they might
want/need which is both unergonomic and also arguably error prone.

### Redefining `CpuFeatures`

Alternatively the `CpuFeatures` set can  be redefined to have a different default per CPU feature, rather than
only referring to features that are disabled for guests by default. Features that are enabled by default, but
not available on the host, are silently ignored unless explicitly set by the user.

This approach decreases the amount of CPU features one typically needs to manually set, but is still arguably
less ergonomic than simply declaring a CPU model/generation. An argument in favor of this approach is however
that one can then specify more precisely exactly which CPU features one wants the guest to have.

# Prior art

QEMU has the [CPU models concept](https://qemu-project.gitlab.io/qemu/system/qemu-cpu-models.html)
and permits more advanced specification in terms of [Libvirt guest XML](https://qemu-project.gitlab.io/qemu/system/qemu-cpu-models.html#libvirt-guest-xml).
This prior work is the main inspiration for this RFC.

# Future possibilities

- Excluding individual features via `CpuFeatures` (See [redefining CPU features](#redefining-cpufeatures)). This can be seen as a change that complements
`CpuProfiles`, by letting users ergonomically set a CPU profile and then letting them disable individual features that would otherwise be enabled.
- More CPU profiles by adding more variants to the `CpuProfile` enum. This may also include support for other architectures than x86-64.
