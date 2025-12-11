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

  # Import git-hooks.nix directly for local custom hooks
  nix-pre-commit-hooks = import (
    builtins.fetchTarball "https://github.com/cachix/git-hooks.nix/tarball/50b9238891e388c9fdc6a5c49e49c42533a1b5ce"
  );

  # Local custom hooks specific to this project
  localHooks = nix-pre-commit-hooks.run {
    src = ./.;
    hooks = {
      tpm-config-format = {
        enable = true;
        name = "TPM Config Format";
        description = "Check TPM config files formatting";
        files = "^\\.tpm-(roots|intermediates)\\.yaml$";
        entry = "${pkgs.go}/bin/go run ./ config format --dry-run --config";
        language = "system";
        pass_filenames = true;
      };

      tpm-config-validate = {
        enable = true;
        name = "TPM Config Validate";
        description = "Validate TPM config files";
        files = "^\\.tpm-(roots|intermediates)\\.yaml$";
        entry = "${pkgs.go}/bin/go run ./ config validate --quiet --config";
        language = "system";
        pass_filenames = true;
      };
    };
  };
in
  pkgs.mkShell {
    buildInputs = with pkgs; [goreleaser cosign syft gcc] ++ helpers.packages;

    shellHook = ''
      ${helpers.shellHook}
      ${localHooks.shellHook}
      echo "Development environment ready!"
      echo "  - Go version: $(go version)"
    '';

    env = {
      CGO_ENABLED = "1";
    };
  }
