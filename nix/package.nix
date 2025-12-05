{ lib, stdenv, buildGoModule, fetchFromGitHub, installShellFiles, src ? null, }:
let version = if src != null then "unstable" else "0.2.2";
in buildGoModule {
  pname = "tpmtb";
  inherit version;

  src = if src != null then
    src
  else
    fetchFromGitHub {
      owner = "loicsikidi";
      repo = "tpm-ca-certificates";
      tag = "v${version}";
      hash = "sha256-2OCoWZ+v55MK/INKSlteiIhOGuc0Fk6QKcG6gtwkX9Q=";
    };

  vendorHash = "sha256-yybHjGCo0vSSYi+vXZcEowFacifSTNALLpMkElFLhGc=";

  # Build the main package (at the root)
  # subPackages defaults to [ "." ] if not specified

  ldflags = [ "-s" "-w" ];

  doCheck = true;
  checkFlags = [ "-v" "-timeout=30s" "-short" ];

  nativeBuildInputs = [ installShellFiles ];

  postInstall = ''
    # Rename binary from tpm-ca-certificates to tpmtb
    mv $out/bin/tpm-ca-certificates $out/bin/tpmtb
  '' + lib.optionalString
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
    maintainers = [ ];
    mainProgram = "tpmtb";
  };
}
