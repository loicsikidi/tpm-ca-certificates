{
  lib,
  stdenv,
  buildGo125Module,
  fetchFromGitHub,
  installShellFiles,
  src ? null,
}: let
  version =
    if src != null
    then "unstable"
    else "0.7.0";
in
  buildGo125Module {
    pname = "tpmtb";
    inherit version;

    src =
      if src != null
      then src
      else
        fetchFromGitHub {
          owner = "loicsikidi";
          repo = "tpm-ca-certificates";
          tag = "v${version}";
          hash = "sha256-uCVKLW/nt1mJaKQ0pT3Golr/F3rnL2aICv0bX0JScp8=";
        };

    vendorHash = "sha256-LMG4bAvifEO4YGZSOzbuxmoJp4x7BvPCv4nAgcicUds=";

    # Build the main package (at the root)
    # subPackages defaults to [ "." ] if not specified

    ldflags = [
      "-s"
      "-w"
      "-X main.version=${version}"
      "-X main.builtBy=nix"
    ];

    doCheck = true;

    checkFlags = [
      "-v"
      "-timeout=30s"
      "-short" # Skip tests that require network access
    ];

    nativeBuildInputs = [installShellFiles];

    postInstall =
      ''
        # Rename binary from tpm-ca-certificates to tpmtb
        mv $out/bin/tpm-ca-certificates $out/bin/tpmtb
      ''
      + lib.optionalString
      (stdenv.buildPlatform.canExecute stdenv.hostPlatform) ''
        # Generate shell completions
        installShellCompletion --cmd tpmtb \
          --bash <($out/bin/tpmtb completion bash) \
          --zsh <($out/bin/tpmtb completion zsh) \
          --fish <($out/bin/tpmtb completion fish)
      '';

    meta = {
      description = "TPM Trust Bundle - manages TPM root certificates bundle";
      homepage = "https://github.com/loicsikidi/tpm-ca-certificates";
      license = lib.licenses.bsd3;
      maintainers = [];
      mainProgram = "tpmtb";
    };
  }
