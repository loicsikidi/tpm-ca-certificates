# Local Cache Specification

## Document History

| Version |    Date    |   Author    |   Description    |
|---------|------------|-------------|------------------|
| alpha   | 2025-12-15 | Loïc Sikidi | Initial version  |

## Overview

This specification defines the local cache system for the TPM CA Certificates project. The local cache aims to:

1. Improve performance and efficiency by reducing latency when accessing frequently used data
2. Reduce the impact of rate-limiting applied by the GitHub API
3. Serve as the foundation for implementing offline verification of TPM bundle integrity and provenance

## Cache Structure

The local cache directory has the following structure:

```
$HOME/.tpmtb/
├── checksums.txt
├── checksums.txt.sigstore.json
├── tpm-ca-certificates.pem
├── roots.provenance.json
├── trusted-root.json
├── tpm-intermediate-ca-certificates.pem # reserved for future use
├── intermediates.provenance.json        # reserved for future use
└── .sigstore/roots/**                   # cache directory used by 'sigstore-go'
```

### Default Location

By default, the local cache MUST be located in the `$HOME/.tpmtb` directory.

## Use Cases

### Online Mode

The `GetTrustedRoots()` method MUST first check if a local cache exists for the requested version:
  * If yes, the local cache MUST be used for the bundle and all resources needed for the verification phase
  * If no, resources MUST be fetched online, then stored in the local cache for future use (see [TrustedBundle.Persist](#trustdbundlepersist-method))

> [!NOTE]
> Since the watcher uses the `GetTrustedRoots()` method internally, the local cache will also be used in this context.

This behavior will reduce the impact of GitHub API rate-limiting while ensuring that resources are always up-to-date.

#### Required Assets

* `tpm-ca-certificates.pem`: The TPM certificate bundle
* `checksums.txt` and `checksums.txt.sigstore.json`: For TPM bundle integrity and provenance verification
* `roots.provenance.json`: For TPM bundle provenance verification

> [!NOTE]
> The files `tpm-intermediate-ca-certificates.pem` and `intermediates.provenance.json` are reserved for future use.

#### Special Case: Read-Only Filesystem

When the filesystem is read-only (for example, when using the OCI Docker image), the local cache cannot be used to store resources fetched online.

Rule: `GetTrustedRoots()` MUST return an explicit error indicating to use `DisableLocalCache` in the config. This attribute will indicate to the API that the cache should not be used, avoiding any write attempts to a read-only filesystem.

> [!NOTE]
> `DisableLocalCache` will also be propagated to `go-tuf/v2` to disable the local TUF cache.

### Offline Mode

The API MUST allow offline verification of the TPM bundle using only resources stored in the local cache.

To achieve this, in addition to the assets used in online mode, the TUF trust chains from Rekor are needed (see `trusted-root.json`).

The API will introduce a new method to produce a local cache eligible for offline verification:

```go
func Save(ctx context.Context, cfg SaveConfig) (SaveResponse, error)
```

This API will be used by the `tpmtb` CLI tool via a new command:

```bash
tpmtb bundle save --output-dir <path> <path-to-bundle> [--local-cache]
```

Now, to load a TPM bundle in offline mode, the user can use the existing `Load` method:

```go
func Load(ctx context.Context, cfg LoadConfig) (TrustedBundle, error)
```

However, `LoadConfig` will have a new attribute `OfflineMode bool` that will indicate to the API that the cache has all the necessary resources for offline verification.

## API Methods

### GetTrustedRoots Method

```go
func GetTrustedRoots(ctx context.Context, cfg GetTrustedRootsConfig) (TrustedBundle, error)
```

**Behavior:**
1. Check if local cache exists for the requested version
2. If cache exists:
   - Load bundle and verification resources from cache
   - Return TrustedBundle
3. If cache does not exist:
   - Fetch resources from GitHub
   - Verify bundle integrity and provenance (see [Bundle Verification](05-bundle-verification.md))
   - Call `TrustedBundle.Persist()` to store in local cache
   - Return TrustedBundle

**Configuration:**

```go
type GetTrustedRootsConfig struct {
    Version           string  // Bundle version (YYYY-MM-DD format or "latest")
    DisableLocalCache bool    // Disable local cache usage
    // ... other fields
}
```

### TrustedBundle.Persist Method

```go
func (tb *TrustedBundle) Persist(ctx context.Context) error
```

**Behavior:**
1. Create cache directory if it does not exist (`$HOME/.tpmtb`)
2. Write all required assets to cache:
   - `tpm-ca-certificates.pem`
   - `checksums.txt`
   - `checksums.txt.sigstore.json`
   - `roots.provenance.json`
3. Return error if filesystem is read-only

### Save Method

```go
func Save(ctx context.Context, cfg SaveConfig) (SaveResponse, error)
```

**Purpose:** Create a local cache eligible for offline verification.

**Behavior:**
1. Verify bundle integrity and provenance (see [Bundle Verification](05-bundle-verification.md))
2. Fetch TUF trust chains from Rekor
3. Write all assets to output directory:
   - `tpm-ca-certificates.pem`
   - `checksums.txt`
   - `checksums.txt.sigstore.json`
   - `roots.provenance.json`
   - `trusted-root.json`
4. Optionally copy to local cache if `--local-cache` flag is set

**Configuration:**

```go
type SaveConfig struct {
   BundlePath       string  // Path to bundle file
   OutputDir        string  // Output directory for cache
   // ... other fields
}

type SaveResponse struct {
   RootBundle             []byte
   RootProvenance         []byte
   IntermediateBundle     []byte
   IntermediateProvenance []byte
   Checksum               []byte
   ChecksumSignature      []byte
   TrustedRoot            []byte
}
```

### Load Method (Updated)

```go
func Load(ctx context.Context, cfg LoadConfig) (TrustedBundle, error)
```

**Behavior:**
1. Load bundle from provided path or local cache
2. If `OfflineMode` is enabled:
   - Use only local resources for verification
   - Load `trusted-root.json` from cache
   - Perform verification without network access
   - **Automatically disable auto-update**: Auto-update is disabled because `trusted-root.json` may not work with future bundles due to Sigstore instance rotates its key material (happens a few times per year) between the cached version and newer releases
3. If `OfflineMode` is disabled:
   - Perform standard online verification (see [Bundle Verification](05-bundle-verification.md))

**Configuration (Updated):**

```go
type LoadConfig struct {
    BundlePath        string  // Path to bundle file (optional if using cache)
    OfflineMode       bool    // Enable offline verification mode
    DisableLocalCache bool    // Disable local cache usage
    // ... other fields
}
```

## CLI Commands

### Save Command

```bash
# Save bundle with offline verification support
tpmtb bundle save --output-dir /path/to/cache /path/to/bundle.pem

# Save bundle with offline verification directly to local cache
tpmtb bundle save /path/to/bundle.pem --local-cache
```

### Verify Command (Updated)

```bash
# Load bundle in online mode (default)
tpmtb bundle verify /path/to/bundle.pem

# Load bundle in offline mode (requires offline-capable cache)
tpmtb bundle verify /path/to/bundle.pem --offline
```
