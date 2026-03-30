# AGENTS.md

## For Humans

This file defines the minimal working rules for LLMs/agents helping the
Cyberus Technology Cloud Team debug and modify this repository.

This repository is a Cyberus Technology fork of Cloud Hypervisor. It is
maintained independently from upstream, even if most changes will likely be
upstreamed later. We generally follow upstream contributing and code-quality
guidance, which also allows LLM contributions to
[some degree](https://github.com/cloud-hypervisor/cloud-hypervisor/pull/7884).
Exceptions and additions are listed below.

The goal is not to prescribe detailed style. The goal is to keep agent work
safe, correct, reviewable, and compatible with CI and normal engineering
practice. This leaves room for developer style preferences and opinions
to some extent.

## For Agents

Cloud Hypervisor is a Linux VMM. These rules are mandatory.

Priority:
- Correctness, safety, production readiness
- `x86_64` + `KVM`
- Live migration and vCPU lifecycle

Constraints:
- Do not break other architectures, backends, or features
- Check relevant work against upstream
  [CONTRIBUTING.md](https://github.com/cloud-hypervisor/cloud-hypervisor/blob/main/CONTRIBUTING.md)

Build:
- For `vmm` and some subcrates, you likely need `--features kvm`

```bash
cargo build -p vmm --features kvm
```

Core rules:
- Correctness > micro performance optimizations
- No speculative or unclear changes
- Keep patches minimal, scoped, and relevant
- No unrelated refactoring, though low-hanging fruits may be proposed
- Do not change behavior unless explicitly required
- Refactors must preserve behavior: Behavior changes are acceptable only for 
  severe bug fixes or explicit, documented requirements

Truthfulness and uncertainty:
- Do not invent information: no fake APIs, functions, behaviors, or
  assumptions
- If uncertain, state uncertainty explicitly and do not guess
- Do not present assumptions as facts
- Ask for clarification if requirements are incomplete
- If clarification is not possible, proceed with minimal, explicit
  assumptions

Safety and concurrency:
- UB is forbidden
- Minimize `unsafe`; keep it small and local
- Every `unsafe` needs a `SAFETY:` comment with invariants
- Assume concurrency by default
- Avoid races, unsynchronized shared state, and implicit ordering assumptions
- Prefer explicit synchronization, clear ownership, deterministic transitions

Domain constraints:
- Treat live migration as a first-class production feature
- Preserve deterministic state transfer, robust failure handling, correct
  device state, and correct memory state
- vCPU lifecycle must have explicit, well-defined, race-free transitions for
  init, run/pause, and teardown
- KVM code must handle all errors, follow the kernel API strictly, and avoid
  undocumented assumptions

Rust and errors:
- Prefer `Result` over panic for recoverable errors, especially on migration
  paths
- `unwrap()` / `expect()` are not for production paths except for unrecoverable
  errors or to catch programming errors
- Debug assertions are fine when they provide clear value
- Handle all errors explicitly
- Never ignore syscall or KVM ioctl return values
- Error messages should contain useful debugging context
- Avoid hidden allocations in hot paths

Docs and invariants:
- Keep docs short and focused
- Code should be self-explanatory where possible
- Document why something exists and its invariants/constraints
- Avoid redundant explanation
- Document non-trivial invariants at struct definitions and critical state
  transitions

Determinism, logging, compatibility:
- Be deterministic where required, especially for migration
- Do not rely on timing, scheduling, or non-deterministic iteration order
- Logging must be relevant, minimal, and high-signal
- Avoid excessive logging in hot paths
- Changes affecting migration must consider backward compatibility and state
  format stability
- Do not break migration compatibility without explicit intent
- Please add by default critical/high-value logging to the `info!` level as this
  is what we use in production. `debug!` level is fine for messages that we only
  need for focused debugging.

Testing and design:
- Add targeted unit tests for bug fixes and non-trivial logic where applicable
- Prefer minimal test scaffolding
- Prefer simple solutions over overly abstract or generic ones, unless the
  abstraction keeps cognitive complexity reasonable
- Avoid unnecessary traits, excessive indirection, and premature abstraction
- For testing, we use our external `libvirt-tests` suite (not in this repository).
  The suite contains comprehensive tests of Cloud Hypervisor in combination with
  libvirt, thus, transitively does expensive testing of Cloud Hypervisor.
- If a change likely requires relevant manual or integration validation against
  `libvirt-tests`, tell the developer that such a test may make sense
- In such cases, ask the developer whether that testing is needed, can be
  skipped, or can be performed manually by the developer
- The agent may perform such testing itself only if the developer has provided
  the necessary instructions and access details

Preferred agent work:
- Mechanical changes: renames, signature updates, consistency fixes
- Debugging support: logging, assertions, issue isolation
- Small, goal-directed refactors
- Prototyping possibly different designs
- Add logging and improved debugging support (these changes/commits are 
  typically not upstreamed and valid intermediate artifacts) when debugging
  certain issues

Avoid:
- UB
- Data races
- Implicit global state
- Arch-specific leakage into generic code
- Breaking non-`x86` / non-`KVM`
- Large or unfocused patches

Commits:
- Keep history reviewable and structured
- Show clear progression from A to B
- Avoid monolithic commits
- Every commit must be bisectable and should explain why if non-trivial
- To test changes, use the following commands.
- All non-prototyping commits must pass them.

```bash
cargo check --features \
  kvm,mshv,fw_cfg,guest_debug,pvmemcontrol,tracing,ivshmem,tdx,igvm \
  --all-targets

cargo build --features \
  kvm,mshv,fw_cfg,guest_debug,pvmemcontrol,tracing,ivshmem,tdx,igvm \
  --all-targets

cargo +nightly fmt --all -- --check

cargo clippy --all-targets --features \
  kvm,mshv,fw_cfg,guest_debug,pvmemcontrol,tracing,ivshmem,tdx,igvm

cargo test --all-targets --features \
  kvm,mshv,fw_cfg,guest_debug,pvmemcontrol,tracing,ivshmem,tdx,igvm
```

- Commit titles must use a component prefix from
  `./scripts/gitlint/rules/TitleStartsWithComponent.py`
- Commit message lines must not exceed 72 characters
- Temporary allowances such as `#[allow(unused)]` or ignored tests are only
  acceptable if resolved within the same commit series
- If in doubt, write commits tailored to the reviewers.
- Line width for commits is 72! Exceptions are defined in 
  `scripts/gitlint/rules/BodyMaxLineLengthEx.py`
