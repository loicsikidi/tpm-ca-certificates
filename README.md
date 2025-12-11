# TPM CA Certificates

## Motivation

This project is the TPM equivalent of [ca-certificates](https://salsa.debian.org/debian/ca-certificates), centralizing and standardizing the management of root certificates used by Trusted Platform Modules (TPMs) to facilitate their integration across systems and applications.

### *Why it's important?*

Validating the Endorsement Key Certificate's chain allows you to verify that a TPM is genuine by confirming it was manufactured by a **trusted vendor**. Once the device's nature has been verified (and typically added to an inventory), you can leverage advanced security capabilities such as:
- **Provisioning**: securely add secrets or keys to the TPM
- **Remote Attestation**: verify the integrity and configuration of a remote system
- **HMAC Salted Sessions**: establish secure, authenticated communication channels with the TPM

Without a trusted root certificate bundle, there's no reliable way to validate the provenance of a TPM device.

## The Problem

Today, information about TPM root certificates is scattered across manufacturer websites and documentation, making it difficult to find and collect — a paradox given their critical importance for security. This fragmentation has a counterproductive effect: most open-source tools that interact with TPMs skip certificate verification entirely 🫠. This is the equivalent of running `curl -sS --insecure https://letsencrypt.org` — accepting any certificate without validation.

This repository aims to correct this situation through a collective community effort to centralize, standardize, and make TPM root certificates easily accessible and verifiable.

## Primitives

### 📖 Human-readable Configuration

The bundle is generated from [`.tpm-roots.yaml`](.tpm-roots.yaml), a human-readable configuration file. Anyone can see and understand how the bundle is built. Additionally, git provides a history of changes.

> [!IMPORTANT]
> The configuration file only points to public resources (URLs) and does not include any certificates directly. This ensures that the certificates used in the bundle are accessible to everyone and can be independently verified.

### 🧑‍⚖️ Certificate Acceptance

The repository implements a strict validation process for adding certificates to the bundle. Each certificate addition requires concrete evidence (e.g., PDFs, official documentation links) proving that the certificate URL is publicly published by the TPM manufacturer. Once validated, these sources are added to the repository's `src/` directory for transparency and future reference.

### 🔄 Reproducibility

The repository provides a CLI tool (`tpmtb`) designed to enable users to locally reproduce any released bundle. Simply clone the repository, checkout a specific tag, and run a single command to regenerate the exact same bundle.

This deterministic generation process ensures transparency and verifiability — two generation processes executed under the same conditions must produce identical results.

> [!NOTE]
> See [Bundle Generation Backward Compatibility](./docs/specifications/03-bundle-generation-backward-compatibility.md) for more details on how we maintain reproducibility across versions.

### 🔐 Integrity

Users and systems must be able to verify that a bundle release is authentic and originates from the expected pipeline. To achieve this, the project leverages a public transparency log ([Rekor](https://docs.sigstore.dev/logging/overview/)) to store signatures and attestations that can be verified by anyone.

This allows verification that:
1. The bundle is indeed the product of the repository's pipeline
2. The bundle has not been altered since its publication

> [!NOTE]
> This verification capability also applies to the `tpmtb` CLI binary and its OCI image.

## Quick Start

The easiest way to use this bundle is through the `tpmtb` (TPM Trust Bundle) CLI tool, which handles downloading, verification, and validation automatically.

<details>
<summary><b>Installation</b></summary>

### Using Go

```bash
go install github.com/loicsikidi/tpm-ca-certificates/cmd/tpmtb@latest
```

### Using Docker

```bash
docker pull ghcr.io/loicsikidi/tpm-ca-certificates/tpmtb:latest
```

Or use it directly:

```bash
docker run --rm -v $(pwd):/tmp -w /tmp ghcr.io/loicsikidi/tpm-ca-certificates/tpmtb:latest --help
```

</details>

### Download the Bundle

Download the latest trust bundle with automatic integrity and provenance verification:

```bash
tpmtb bundle download
```

> [!TIP]
> This command:
> 1. 📥 Downloads the latest bundle from GitHub releases
> 2. 🔐 Verifies the bundle's integrity against the public transparency log (Rekor)
> 3. 🔐 Validates the provenance attestation against the public transparency log (Rekor)
>
> The verification ensures that the bundle was genuinely produced by this repository's CI pipeline and hasn't been tampered with since publication.

Now you can use `tpm-ca-certificates.pem` as the trusted root certificate bundle for your TPM interactions 💫.

## Documentation

Go to [documentation index](docs/README.md) to explore concepts, guides, and specifications.

## Roadmap

- [ ] Improve certificate catalog
  - ***We are actively looking to expand the number of root certificates included in the bundle. Contributions are welcome!*** Please refer to the [Contributing Guide](docs/guides/getting-started/05-contributing.md) for details on how you could help.
- [ ] Gather feedback from early adopters to improve usability and address real-world needs
   - Please open discussions or issues on GitHub to share your thoughts!applications
- [ ] Support offline verification mode for air-gapped or restricted environments 
  - References:
    - [GitHub doc: Verify Attestation offline](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/verify-attestations-offline)
    - [Article: Verifying Cosign signatures offline](https://some-natalie.dev/blog/cosign-disconnected/)
- [ ] Add `tpmtb` in nixpkgs for easy installation via Nix
- [x] Enhance CI/CD pipeline
  - Monitor certificate links for availability and integrity
  - Monitor when a root CA is about to expire
  - Monitor release verification process to ensure it continues to work as expected
- [x] Provide a golang-sdk to ease integration in Go 

## License

BSD-3-Clause License. See the [LICENSE](LICENSE) file for detail
