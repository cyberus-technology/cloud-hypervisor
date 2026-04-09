{
  description = "Cyberus Hypervisor for SAP / Apeiro";

  inputs = {
    dried-nix-flakes.url = "github:cyberus-technology/dried-nix-flakes";
    nixpkgs.url = "github:nixos/nixpkgs?ref=nixos-25.11";
    # Convenient Nix tooling to build Rust projects.
    crane.url = "github:ipetkov/crane/master";
    # Get proper Rust toolchain, independent of pkgs.rustc.
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    let
      dnf = (inputs.dried-nix-flakes.for inputs).override {
        systems = [ "x86_64-linux" ];
      };
      inherit (dnf)
        exportOutputs
        ;
    in
    exportOutputs (
      {
        self,
        # Keep list sorted:
        crane,
        nixpkgs,
        rust-overlay,
        ...
      }:
      let
        pkgs = nixpkgs.legacyPackages;
        lib = pkgs.lib;
        rust-bin = (rust-overlay.lib.mkRustBin { }) pkgs;
      in
      {

        formatter = pkgs.nixfmt-tree;
        devShells.default = pkgs.mkShellNoCC {
          inputsFrom = builtins.attrValues self.packages;
          packages = with pkgs; [
            gitlint
            rustup
          ];
        };
        packages =
          let
            jsonFilter = path: _type: builtins.match ".*json$" path != null;
            sourceFilter = path: type: (jsonFilter path type) || (craneLib.filterCargoSources path type);
            src = lib.cleanSourceWith {
              src = self;
              filter = sourceFilter;
              name = "source";
            };

            rustToolchain = rust-bin.stable.latest.default;
            craneLib = crane.mkLib pkgs;
            craneLib' = craneLib.overrideToolchain rustToolchain;

            cloud-hypervisor = pkgs.callPackage ./chv.nix {
              inherit (pkgs.cloud-hypervisor) meta;
              inherit src;
              craneLib = craneLib';

              # Query the repo revision to pass the cloud-hypervisor to be printed in the version string.
              chExtraVersion = self.dirtyRev or self.rev or "unknown-revision";
            };
          in
          {
            default = cloud-hypervisor;
            inherit cloud-hypervisor;
          };
      }
    );
}
