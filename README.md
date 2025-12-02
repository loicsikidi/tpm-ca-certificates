# TPM Certificate Authority Certificates

## Motivation

This project aims to be the TPM equivalent of the [Mozilla CA Certificate Store](https://salsa.debian.org/debian/ca-certificates). In other words, it centralizes and standardizes the management of root certificates used by Trusted Platform Modules (TPMs) to facilitate their integration and use across various systems and applications.

> [!NOTE]
> ***Why it's important?***
>
> Validating the Endorsement Key Certificate allows you to **verify** that a TPM is genuine by confirming its manufacturer and authenticity. Once the device's nature has been verified (and typically added to an inventory), you can leverage advanced security capabilities such as:
> - **Provisioning**: securely add secrets or keys to the TPM
> - **Remote Attestation**: verify the integrity and configuration of a remote system
> - **HMAC Salted Sessions**: establish secure, authenticated communication channels with the TPM
>
> Without a trusted root certificate bundle, there's no reliable way to validate the provenance of a TPM device.

## The Problem

Today, information about TPM root certificates is scattered across manufacturer websites and documentation, making it difficult to find and verify — a paradox given its critical importance for security. This fragmentation has a counterproductive effect: most open-source tools that interact with TPMs skip certificate verification entirely. This is the equivalent of running `curl -sS --insecure https://letsencrypt.org` — accepting any certificate without validation.

This repository aims to correct this situation through a collective community effort to centralize, standardize, and make TPM root certificates easily accessible and verifiable.

## Primitives

### Human-readable Configuration

The bundle is generated from [`.tpm-roots.yaml`](.tpm-roots.yaml), a human-readable configuration file. Anyone can see and understand how the bundle is built. Additionally, git provides a history of changes.

> [!IMPORTANT]
> The configuration file only points to public resources (URLs) and does not include any certificates directly. This ensures that the certificates used in the bundle are accessible to everyone and can be independently verified.

### Certificate Acceptance

The repository implements a strict validation process for adding certificates to the bundle. Each certificate addition requires concrete evidence (e.g., PDFs, official documentation links) proving that the certificate URL is publicly published by the TPM manufacturer. Once validated, these sources are added to the repository's `src/` directory for transparency and future reference.

### Reproducibility

The repository provides a CLI tool (`tpmtb`) designed to enable users to locally reproduce any released bundle. Simply clone the repository, checkout a specific tag, and run a single command to regenerate the exact same bundle.

This deterministic generation process ensures transparency and verifiability — two generation processes executed under the same conditions must produce identical results.

<!-- TODO: add link to user guide -->

### Integrity

Users and systems must be able to verify that a bundle release is authentic and originates from the expected pipeline. To achieve this, the project leverages a public transparency log (Rekor) to store signatures and attestations that can be verified by anyone.

This allows verification that:
1. The bundle is indeed the product of the repository's pipeline
2. The bundle has not been altered since its publication

> [!NOTE]
> This verification capability also applies to the `tpmtb` CLI binary and its OCI image.

<!-- TODO: add link to artifact verification specification -->

## Quick Start

<!-- TODO: add an example of how to download and verify trust bundle -->

## Documentation

- 

## License

BSD-3-Clause License. See the [LICENSE](LICENSE) file for detail

## See Also

- [Trust Model](doc/01-trust_model.md)
- [Threat Model & Supply Chain Attack Mitigations](doc/02-threat_model.md)
- [Configuration File Format & Rules](doc/03-configuration.md)
