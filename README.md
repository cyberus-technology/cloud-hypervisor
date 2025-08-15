# Cloud Hypervisor Fork for SAP gardenlinux

The `gardenlinux` branch is the branch from that our SAP colleagues [build]
[sap-gl-ci] their Cloud Hypervisor packages.

## Development Model

- The `gardenlinux` branch is always what SAP builds. From SAPs side, we can
  force push or rewrite history on that branch.
- We use branch protection for `gradenlinux`, PRs, CI, and code reviews
- With every new CHV release, we rename `gardenlinux` to `gardenlinux-vXX` and
  create a new `gardenlinux` branch manually:
  - use release as base and push it into the repo
  - cherry-pick all commits from `gardenlinux-vXX` that are still relevant onto a
    new branch and create a pull request against this fork
  - adapt git commit history
- PoC Development:
  - happens here (in [cyberus-technology/cloud-hypervisor](https://github.com/cyberus-technology/cloud-hypervisor))
  - open PR against `gardenlinux`
  - Branch name patterns **must not** follow `gardenlinux-*` pattern
  - We recommend `cyberus-fork-*` as branch pattern to better keep the overview.
- Productization:
  - happens upstream (in [cloud-hypervisor/cloud-hypervisor](https://github.com/cloud-hypervisor/cloud-hypervisor))
  - We recommend `productize-*` as branch pattern to better keep the overview.


[sap-gl-ci]: https://github.com/gardenlinux/package-cloud-hypervisor-gl/blob/main/prepare_source#L1
