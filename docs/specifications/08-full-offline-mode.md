# Full Offline Mode Specification

## Document History

| Version |    Date    |   Author    |   Description    |
|---------|------------|-------------|------------------|
| alpha   | 2025-12-15 | Loïc Sikidi | Initial version  |

## Overview

This specification defines the **full offline mode** capability of the `tpm-ca-certificates` API, enabling complete validation of TPM Endorsement Key (EK) certificate trust chains without any network access.

### Motivation

In enterprise environments, it is common to have air-gapped systems or strict network restrictions that prevent external connectivity. The full offline mode enables these environments to:

1. **Validate EK certificate trust chains** without network access
2. **Build complete certificate chains** from EK certificate to trusted root
3. **Operate in regulated environments** where internet access is prohibited or restricted

### Requirements

To achieve full offline verification, the following components are required:

1. **TPM Root CA bundle** - Already supported (see [Bundle Format](04-tpm-trust-bundle-format.md))
2. **TPM Intermediate CA bundle** - New requirement (detailed in this specification)
3. **Local cache with verification artifacts** - See [Local Cache](07-local-cache.md)

## TPM Intermediate Certificate Bundle

The TPM Intermediate CA bundle follows the same principles and processes as the TPM Root CA bundle, ensuring consistency and reliability.

### Configuration File

A new configuration file `.tpm-intermediates.yaml` will be added to the repository, following the same structure as `.tpm-roots.yaml` (see [Configuration File](01-configuration-file.md)).

### Certificate Addition Process

The process for adding intermediate certificates is identical to root certificates (see [Security Model](../concepts/01-security_model.md)).

### Bundle Generation

The intermediate bundle is generated using the same `tpmtb` CLI command with a different configuration file:

```bash
# Generate intermediate certificate bundle
tpmtb bundle generate \
  --config .tpm-intermediates.yaml \
  --output tpm-intermediate-ca-certificates.pem
```

### Release Process

Both bundles (roots and intermediates) are generated and released together (see [Release Management](02-release-management.md)):

1. Update `.tpm-roots.yaml` and/or `.tpm-intermediates.yaml`
2. Run `tpmtb config format` for both configurations
3. Run `tpmtb config validate` for both configurations
4. Commit changes
5. Create date-based tag (e.g., `2025-12-15`)
6. CI/CD pipeline generates both bundles and publishes release artifacts:
   - `tpm-ca-certificates.pem` (roots)
   - `tpm-intermediate-ca-certificates.pem` (intermediates)
   - `checksums.txt` (contains hashes of both bundles)
   - `checksums.txt.sigstore.json`

> [!NOTE]
> Both bundles are generated during every release, even if only one configuration file has been modified.

### Verification Process

The intermediate bundle follows the same verification process as the root bundle (see [Bundle Verification](05-bundle-verification.md)). Local cache will include both bundles and their respective provenance files, required for offline verification.

## API Changes

### New Method: GetIntermediates

The `TrustedBundle` interface will be extended with a new method to access intermediate certificates:

```go
type TrustedBundle interface {
    // GetRoots returns the root CA certificate pool
    GetRoots() *x509.CertPool

    // GetIntermediates returns the intermediate CA certificate pool
    GetIntermediates() *x509.CertPool
}
```
