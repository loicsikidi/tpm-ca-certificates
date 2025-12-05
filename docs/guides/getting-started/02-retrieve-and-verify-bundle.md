# Retrieve and Verify Trust Bundles

## Who This Guide Is For

This guide is for system administrators, security engineers, and developers who need to securely retrieve a bundle of TPM root CA endorsement key (EK) certificates to use as a root of trust in their systems.

**Your goal:** Obtain a verified, authentic bundle of TPM manufacturer root certificates that you can trust for validating TPM endorsement keys in your infrastructure.

**What you'll learn:** How to download and cryptographically verify that the bundle:
- Hasn't been tampered with (integrity)
- Was built by the official workflow from the correct source code (provenance)
- Can be trusted as a root of trust for your TPM-based security systems

---

This guide explains how to download and verify TPM root certificate bundles using both `tpmtb` and alternative verification tools.

## Prerequisites

- ✅ `tpmtb` installed ([see Installation guide](./01-installation.md))
- 🔧 For alternative verification methods:
  - GitHub CLI (`gh`) - for attestation verification
  - Cosign (`>= v2.4.3`) - for signature verification
  - Git and Go - for reproducibility verification

## Quick Start with tpmtb ⚡

The simplest way to retrieve and verify a bundle is using `tpmtb`:

```bash
# Download and verify the latest bundle
tpmtb bundle download

# List available releases
tpmtb bundle list
# Example output:
Available TPM trust bundle releases (2):
  2025-12-04
  2025-12-03

# Download and verify a specific date release
tpmtb bundle download --date 2025-12-03
```

**What happens under the hood:**
1. 📥 Downloads `tpm-ca-certificates.pem` from GitHub release
2. 📋 Downloads `checksums.txt` and `checksums.txt.sigstore.json`
3. 🔐 Verifies both **integrity** (Cosign signature) and **provenance** (SLSA attestation)
4. 🗑️ Clean the current directory by removing checksum files

## Understanding Bundle Verification 🔍

> [!IMPORTANT]
> If you are not familiar with the concepts around software supply chain security,
> (eg. build provenance attestation, keyless signature, etc.), please read the following resources first:
> - [Cosign Signing Overview](https://docs.sigstore.dev/cosign/signing/overview/)
> - [SLSA provenance attestation](https://slsa.dev/spec/v1.2/provenance)
> - [GitHub attest-build-provenance action](https://github.com/actions/attest-build-provenance)

### Understanding Keyless Signatures 🔑

All verification methods rely on **keyless signatures** provided by Sigstore:

- ⏱️ **No long-lived keys**: Signatures use ephemeral certificates bound to GitHub Actions OIDC tokens
- 🆔 **Identity verification**: Certificates contain workflow identity, repository, commit, and tag information
- 📜 **Transparency**: All signatures are recorded in Rekor transparency log with timestamps
- 🔍 **Auditability**: Anyone can verify that signatures came from the expected workflow

`tpmtb` performs comprehensive verification to ensure the bundle is authentic and untampered. The verification process includes two main components:

### 1. Integrity Verification (Cosign Signature) 🛡️

Verifies that the bundle hasn't been modified since it was generated:

- ✅ Validates the Cosign keyless signature of `checksums.txt`
- ✅ Ensures the signature was created by the correct GitHub Actions workflow
- ✅ Checks that the bundle's checksum matches the signed checksum
- ✅ Verifies the signature is recorded in Rekor transparency log

### 2. Provenance Verification (SLSA Attestation) 📦

Verifies that the bundle was built by the expected workflow from the correct repository state:

- ✅ Queries GitHub API for SLSA build provenance attestations
- ✅ Validates the attestation signature
- ✅ Ensures the build occurred from the expected Git commit
- ✅ Verifies all metadata is consistent (date, commit, repository)

> [!NOTE]
> For detailed technical information about the verification process, see the [Bundle Verification Specification](../../specifications/05-bundle-verification.md).

## Manual Verification 🔧

If you already have the bundle, you can verify it manually:

```bash
# Verify bundle with smart auto-detection of checksum files
tpmtb bundle verify tpm-ca-certificates.pem

# Verify with explicit file paths
tpmtb bundle verify tpm-ca-certificates.pem \
  --checksums-file checksums.txt \
  --checksums-signature checksums.txt.sigstore.json
```

## Alternative Verification Methods 🔬

While `tpmtb` provides the most comprehensive verification, you can use alternative tools:

### Manual Verification with Cosign and GitHub CLI

For complete security verification, follow this two-step process:

#### Step 1: Verify Integrity with Cosign

First, verify the **integrity** of the checksums file using Cosign:

> [!IMPORTANT]
> Make sure to use **`cosign >= v2.4.3`** to support the [Sigstore bundle format](https://docs.sigstore.dev/about/bundle/).

> [!TIP]
> Replace `$DATE` with the actual release date (e.g., `2025-12-03`) when running the command.
>
> You can find it with the following command:
> ```bash
>  grep "Date:" tpm-ca-certificates.pem
> ```

```bash
# Verify the checksums signature
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/loicsikidi/tpm-ca-certificates/.github/workflows/release-bundle.yaml@refs/tags/$DATE' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# Verify the bundle matches the checksum
sha256sum -c checksums.txt
```

> [!NOTE]
> This step establishes a trusted checksum by verifying that:
> - The checksum file was signed by the correct GitHub Actions workflow
> - The bundle's digest matches the verified checksum
> - The signature is recorded in Rekor transparency log

#### Step 2: Verify Provenance with GitHub CLI

Once the checksum integrity is established, verify the **provenance** using GitHub's attestation system:

```bash
gh attestation verify tpm-ca-certificates.pem --owner loicsikidi
```

### Reproducibility Verification

Verify the **integrity** by rebuilding the bundle from source:

> [!TIP]
> Replace `$DATE` with the actual release date (e.g., `2025-12-03`) when running the command.

```bash
# Clone and checkout the specific release
git clone https://github.com/loicsikidi/tpm-ca-certificates
cd tpm-ca-certificates
git checkout $DATE

# Regenerate the bundle
tpmtb bunde generate --workers 10 --output tpm-ca-certificates.pem

# Compare checksums
sha256sum tpm-ca-certificates.pem
```

Compare the output with the checksum in `checksums.txt` from the release.

> [!WARNING]
> This method only verifies integrity. To be fully secure, it MUST be combined with provenance verification (Option 1 or `tpmtb`).

### Troubleshooting 🔧

#### Verification Fails ❌

If verification fails, check:

1. **Network connectivity**: Ensure you can access GitHub API and Rekor
1. **Version compatibility**: Use `cosign >= v2.4.3` for Sigstore bundle format
1. **Metadata override**: If bundle metadata is missing, provide `--date` and `--commit` flags

> [!WARNING]
> If integrity verification fails for an official release from the repository, please create [an issue](https://github.com/loicsikidi/tpm-ca-certificates/issues/new) in the repository. This could indicate a supply chain attack or an error in the release process.

#### GitHub API Rate Limits ⏱️

GitHub API allows 60 requests per hour per IP address without authentication. In normal use cases, you should not reach this threshold, but if you do, you will see an explicit error message in the CLI.

Currently, `tpmtb` does not support GitHub credentials, but this functionality may be added in the future if needed.

As a workaround, you can use GitHub CLI for attestation verification:

```bash
# Authenticate with GitHub CLI
gh auth login

# Then use gh for attestation verification
gh attestation verify tpm-ca-certificates.pem --owner loicsikidi
```

## Understanding the Bundle Format 📄

Once you've downloaded a bundle, you can inspect its contents to understand what certificates it contains.

### Bundle Structure 🗂️

The bundle uses PEM format with embedded metadata. Each certificate includes human-readable information:

```bash
# Quick preview of bundle contents
head -n 40 tpm-ca-certificates.pem
```

Example output:

```
##
## tpm-ca-certificates.pem
##
## Date: 2025-12-03
## Commit: 7422b99b8b097ba8d80b4b7d3f27c13b78e35a7f
##
## This file has been auto-generated by tpmtb (TPM Trust Bundle)
## and contains a list of verified TPM Root Endorsement Certificates.
##

#
# Certificate: NPCTxxx ECC521 RootCA
# Owner: NTC
#
# Issuer: CN=NPCTxxx ECC521 RootCA,O=Nuvoton Technology Corporation,C=TW
# Serial Number: 2 (0x2)
# Subject: CN=NPCTxxx ECC521 RootCA,O=Nuvoton Technology Corporation,C=TW
# Not Valid Before: Thu Apr 27 16:36:58 2023
# Not Valid After : Sun Apr 27 16:36:58 2053
# Fingerprint (SHA-256): 08:3E:7B:D1:3E:8F:E0:BB:9B:0C:64:DB:9E:0C:83:56:68:1D:F6:57:14:D2:D5:C4:92:5E:B9:8A:E1:36:9D:40
# Fingerprint (SHA1): 7C:7B:3C:8A:46:5E:67:D2:8F:4D:B0:F3:5C:E1:20:C4:BB:4A:AC:CC
-----BEGIN CERTIFICATE-----
MIICaTCCAcugAwIBAgIBAjAKBggqhkjOPQQDBDBWMR4wHAYDVQQDExVOUENUeHh4
...
-----END CERTIFICATE-----
```

### Key Information in the Bundle

**Global Metadata** (marked with `##`):
- **Date**: Bundle generation date (matches release tag)
- **Commit**: Git commit hash identifying the exact source code version

**Certificate Metadata** (marked with `#`):
- **Certificate**: Human-readable certificate name
- **Owner**: Vendor ID from TCG registry (e.g., NTC, IFX, STM, INTC)
- **Issuer/Subject**: Certificate distinguished names
- **Validity Period**: Certificate expiration dates
- **Fingerprints**: SHA-256 and SHA-1 hashes for verification

### Quick Bundle Inspection 🔎

```bash
# Count certificates in the bundle
grep -c "BEGIN CERTIFICATE" tpm-ca-certificates.pem

# List all certificate owners
grep "^# Owner:" tpm-ca-certificates.pem | sort | uniq

# Find certificates from a specific vendor (e.g., Nuvoton)
grep -A 10 "# Owner: NTC" tpm-ca-certificates.pem

# Check bundle generation date and commit
head -n 10 tpm-ca-certificates.pem | grep -E "^## (Date|Commit):"
```

> [!TIP]
> The bundle format is designed to be both machine-parseable and human-readable. You can use standard text tools (grep, awk, sed) to extract specific certificates or information.

## Next Steps 🚀

Now that you can retrieve and verify trust bundles:

- 📖 [Bundle Generation Guide](./03-generate-bundle.md) - Learn how the bundle is created

## Additional Resources 📚

- 📄 [Bundle Format Specification](../../specifications/04-tpm-trust-bundle-format.md) - Bundle structure
- 🔐 [Bundle Verification Specification](../../specifications/05-bundle-verification.md) - Technical details
