{
  # from nixpkgs
  crane,
  openssl,
  pkg-config,
  # other
  rustToolchain,
}:

let
  craneLib = crane.overrideToolchain rustToolchain;

  commonArgs = {
    src = craneLib.cleanCargoSource ./..;
    nativeBuildInputs = [
      pkg-config
    ];
    buildInputs = [
      openssl
    ];
    # Fix build. Reference:
    # - https://github.com/sfackler/rust-openssl/issues/1430
    # - https://docs.rs/openssl/latest/openssl/
    OPENSSL_NO_VENDOR = true;
  };

  # Downloaded and compiled dependencies.
  cargoArtifacts = craneLib.buildDepsOnly (
    commonArgs
    // {
      pname = "cloud-hypervisor-deps";
    }
  );

  cargoPackageKvm = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;
      pname = "cloud-hypervisor";
      # Don't execute tests here. We want this in a dedicated step.
      doCheck = false;
      cargoExtraArgs = "--features kvm";
    }
  );

  cargoPackageMshv = craneLib.buildPackage (
    commonArgs
    // {
      inherit cargoArtifacts;
      pname = "cloud-hypervisor";
      # Don't execute tests here. We want this in a dedicated step.
      doCheck = false;
      cargoExtraArgs = "--features mshv --no-default-features";
    }
  );
in
{
  default = cargoPackageKvm;
  chvKvm = cargoPackageKvm;
  chvMshv = cargoPackageMshv;
}
