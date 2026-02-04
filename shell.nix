{
  pkgs ?
    import (fetchTarball
      # go v1.25.5
      "https://github.com/NixOS/nixpkgs/archive/a1bab9e494f5f4939442a57a58d0449a109593fe.tar.gz")
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
