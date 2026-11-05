# Builds Cloud Hypervisor with using crane.
#
# Uses a pragmatic release profile with debug-ability and faster
# compilation times in mind without sacrificing too much performance.

{
  # helper from nixpkgs
  lib,
  openssl,
  pkg-config,
  # other helper
  craneLib,
  # other
  meta, # meta of pkgs.cloud-hypervisor
  src, # clean source
  chExtraVersion, # Additional information to be appended to the version string.
}:
let
  commonArgs = {
    inherit meta src;
    # Since Nov 2025 (v50), Cloud Hypervisor has a virtual manifest and the
    # main package was moved into a sub directory.
    cargoToml = "${src}/cloud-hypervisor/Cargo.toml";

    # Pragmatic release profile with debug-ability and faster
    # compilation times in mind.
    env = {
      CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS = "true";
      CARGO_PROFILE_RELEASE_OPT_LEVEL = 2;
      CARGO_PROFILE_RELEASE_OVERFLOW_CHECKS = "true";
      CARGO_PROFILE_RELEASE_LTO = "thin";

      # Fix build. Reference:
      # - https://github.com/sfackler/rust-openssl/issues/1430
      # - https://docs.rs/openssl/latest/openssl/
      OPENSSL_NO_VENDOR = true;

      # Sets additional information to be appended to the version string.
      CH_EXTRA_VERSION = chExtraVersion;
    };

    nativeBuildInputs = [
      pkg-config
    ];
    buildInputs = [
      openssl
    ];
  };

  # Downloaded and compiled dependencies.
  cargoArtifacts = craneLib.buildDepsOnly (
    commonArgs
    // {
      doCheck = false;
    }
  );

  cargoPackageKvm = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;
      # Don't execute tests here. Too expensive for local development with
      # frequent rebuilds + little benefit.
      doCheck = false;
      cargoExtraArgs = "--features 'kvm fw_cfg'";
    }
  );
in
cargoPackageKvm
