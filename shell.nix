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
      gotest.settings.flags = "-short -race";
    };
  };
in
  pkgs.mkShell {
    buildInputs = with pkgs; [goreleaser cosign syft gcc] ++ helpers.packages;

    shellHook = ''
      ${helpers.shellHook}
      echo "Development environment ready!"
      echo "  - Go version: $(go version)"
    '';

    env = {
      CGO_ENABLED = "1";
    };
  }
