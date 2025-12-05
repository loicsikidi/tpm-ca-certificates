# Installation

`tpmtb` (TPM Trust Bundle) is the official CLI tool for working with TPM root certificate bundles. It simplifies downloading, verifying, and managing trust bundles with built-in integrity and provenance checks powered by Sigstore.

This guide covers the different ways to install `tpmtb` on your system.

## Prerequisites

Before installing `tpmtb`, ensure you have one of the following:

- **Go 1.23+** (for installation via `go install`)
- **Docker** (for containerized usage)
- **Nix** (for declarative installation)

## Installation Methods

### Using Go

The simplest way to install `tpmtb` is via Go's built-in package manager:

```bash
go install github.com/loicsikidi/tpm-ca-certificates/cmd/tpmtb@latest
```

This downloads, compiles, and installs the latest version of `tpmtb` to your `$GOPATH/bin` directory (typically `~/go/bin`).

**Verify the installation:**

```bash
tpmtb version
```

**Install a specific version:**

```bash
go install github.com/loicsikidi/tpm-ca-certificates/cmd/tpmtb@v0.2.0
```

### Using Docker

For containerized environments or to avoid installing Go, use the official Docker image:

**Pull the image:**

```bash
docker pull ghcr.io/loicsikidi/tpm-ca-certificates/tpmtb:latest
```

**Run directly:**

```bash
docker run --rm ghcr.io/loicsikidi/tpm-ca-certificates/tpmtb:latest --help
```

**Create an alias for convenience:**

```bash
alias tpmtb='docker run --rm -v $(pwd):/tmp -w /tmp ghcr.io/loicsikidi/tpm-ca-certificates/tpmtb:latest'
```

Now you can use `tpmtb` as if it were installed locally:

```bash
tpmtb bundle download
```

**Use a specific version:**

```bash
docker pull ghcr.io/loicsikidi/tpm-ca-certificates/tpmtb:v0.2.0
```

### Using Nix

For reproducible, declarative installations, use Nix with the provided `shell.nix`:

**Enter a Nix shell with tpmtb:**

```bash
nix-shell -p '(import (fetchTarball "https://github.com/loicsikidi/tpm-ca-certificates/archive/main.tar.gz") {}).tpmtb'
```

**Or create a `shell.nix` file in your project:**

```nix
{ pkgs ? import <nixpkgs> {} }:

let
  tpm-ca-certs = import (fetchTarball "https://github.com/loicsikidi/tpm-ca-certificates/archive/main.tar.gz") {};
in
pkgs.mkShell {
  buildInputs = [
    tpm-ca-certs.tpmtb
  ];
}
```

Then run:

```bash
nix-shell
tpmtb version
```

## Verifying the Installation

Regardless of your installation method, verify that `tpmtb` is correctly installed:

```bash
tpmtb version
```

You should see output similar to:

```bash
tpmtb version
# output:
Revision: 0b85df93edbe5d54cf34483423b86b2d978ca928
Version: v0.2.0
BuildTime: 2025-12-04T22:12:49Z
Dirty: false
```

> [!WARNING]
> When nix you will see `unknown` for everything due to sandboxed builds.
> We are working on improving this experience.

## Shell Completion

`tpmtb` provides shell completion for bash, zsh, and fish. To enable it, use the `completion` subcommand:

**For bash:**
```bash
# Load completion for the current session
source <(tpmtb completion bash)

# Add to your ~/.bashrc for persistent completion
echo 'source <(tpmtb completion bash)' >> ~/.bashrc
```

**For zsh:**
```bash
# Load completion for the current session
source <(tpmtb completion zsh)

# Add to your ~/.zshrc for persistent completion
echo 'source <(tpmtb completion zsh)' >> ~/.zshrc
```

**For fish:**
```bash
# Load completion for the current session
tpmtb completion fish | source

# Add to your fish config for persistent completion
tpmtb completion fish > ~/.config/fish/completions/tpmtb.fish
```

> [!NOTE]
> When installing via Nix, shell completions are automatically installed to the appropriate directories and should work out of the box.

## Next Steps

Now that you have `tpmtb` installed, learn how to:

- [Retrieve and Verify Trust Bundles](./02-retrieve-and-verify-bundle.md) - Download and verify TPM root certificate bundles
