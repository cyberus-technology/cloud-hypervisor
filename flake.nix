{
  description = "Cloud Hypervisor";

  inputs = {
    crane.url = "github:ipetkov/crane/master";
    # We follow the latest stable release of nixpkgs
    nixpkgs.url = "github:nixos/nixpkgs/nixos-25.05";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    inputs@{ self, nixpkgs, ... }:
    let
      # We only list supported targets here
      # (taken from nixpkgs.lib.systems.flakeExposed).
      systems = [
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems =
        function: nixpkgs.lib.genAttrs systems (system: function nixpkgs.legacyPackages.${system});

      # Rust toolchain (cargo, rustc, rustfmt, clippy)
      rustToolchain =
        pkgs:
        let
          # We directly instantiate the functionality, without using an
          # nixpkgs overlay.
          # https://github.com/oxalica/rust-overlay/blob/f4d5a693c18b389f0d58f55b6f7be6ef85af186f/docs/reference.md?plain=1#L26
          rustBin = (inputs.rust-overlay.lib.mkRustBin { }) pkgs;
        in
        rustBin.stable.latest.default;

      buildPackages =
        pkgs:
        import ./nix/build.nix {
          inherit (pkgs) pkg-config openssl;
          crane = inputs.crane.mkLib pkgs;
          rustToolchain = rustToolchain pkgs;
        };
    in
    {
      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = builtins.attrValues self.packages;
          packages = with pkgs; [
            nixfmt-rfc-style
            # Rust toolchain not exported from the crane-build packages:
            # -> not taken into account from inputsFrom
            # -> we specify it manually
            (rustToolchain pkgs)
            swtpm
          ];
        };
      });
      formatter = forAllSystems (pkgs: pkgs.nixfmt-rfc-style);
      packages = forAllSystems (pkgs: buildPackages pkgs);
    };
}
