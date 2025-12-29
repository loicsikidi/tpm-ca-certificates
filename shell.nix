{
  pkgs ?
    import (fetchTarball
      "https://github.com/NixOS/nixpkgs/archive/ebc94f855ef25347c314258c10393a92794e7ab9.tar.gz")
    {},
}: let
  helpers = import (builtins.fetchTarball
    "https://github.com/loicsikidi/nix-shell-toolbox/tarball/main") {
    inherit pkgs;
    hooksConfig = {
      tpmtb-format.enable = true;
      tpmtb-validate.enable = true;
      gotest.settings.flags = "-short -race";
    };
  };
  gos = pkgs.callPackage ./nix/gos.nix {};
in
  pkgs.mkShell {
    buildInputs = with pkgs;
      [
        delve
        goreleaser
        cosign
        syft
        gcc
        gos
      ]
      ++ helpers.packages;

    shellHook = ''
      ${helpers.shellHook}
      echo "Development environment ready!"
      echo "  - Go version: $(go version)"
    '';

    # to enable debugging with delve
    hardeningDisable = ["fortify"];

    env = {
      CGO_ENABLED = "1";
    };
  }
