{ pkgs ? import (fetchTarball
  "https://github.com/NixOS/nixpkgs/archive/ee09932cedcef15aaf476f9343d1dea2cb77e261.tar.gz")
  { }, }:
let
  helpers = import (builtins.fetchTarball
    "https://github.com/loicsikidi/nix-shell-toolbox/archive/main.tar.gz") {
      inherit pkgs;
    };
in pkgs.mkShell {
  buildInputs = with pkgs; [ goreleaser cosign syft gcc ] ++ helpers.packages;

  shellHook = ''
    ${helpers.shellHook}
    echo "Development environment ready!"
    echo "  - Go version: $(go version)"
  '';
}
