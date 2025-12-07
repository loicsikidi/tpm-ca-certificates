# pkg/api - TPM Trust Bundle API

Package `api` provides a public Go API for fetching and verifying TPM trust bundles from GitHub releases.

## Overview

This package exposes the trust bundle download and verification logic used by the `tpmtb` CLI tool. It allows external developers to programmatically fetch verified TPM trust bundles without requiring file I/O - all operations are performed in memory.

## Features

- **In-memory operations**: No disk writes required - bundles are downloaded and verified entirely in memory
- **Automatic verification**: By default, bundles are cryptographically verified using:
  - Cosign keyless signatures (OIDC + Transparency Log)
  - GitHub Attestations (SLSA provenance)
- **Flexible configuration**: Fetch latest or specific dated releases
- **Zero dependencies on CLI**: Pure Go API suitable for integration into other tools
- **Standalone verification**: Verify bundles independently with `VerifyTrustedBundle`

## Usage

### Recommended: Using TrustedBundle (High-level API)

The `GetTrustedBundle` function provides a parsed certificate catalog with thread-safe access and optional auto-update support.

```go
package main

import (
    "context"
    "log"

    "github.com/loicsikidi/tpm-ca-certificates/pkg/api"
)

func main() {
    ctx := context.Background()

    // Fetch and parse the latest verified bundle
    tb, err := api.GetTrustedBundle(ctx, api.GetConfig{})
    if err != nil {
        log.Fatal(err)
    }
    defer tb.Stop()

    // Get certificates as an x509.CertPool for verification
    certPool := tb.GetRoots()

    // Access metadata
    metadata := tb.GetMetadata()
    log.Printf("Bundle date: %s, commit: %s\n", metadata.Date, metadata.Commit)

    // Get list of vendors
    vendors := tb.GetVendors()
    log.Printf("Vendors: %v\n", vendors)
}
```

### Legacy: Fetch Latest Verified Bundle (Raw Data)

**Note:** `GetRawTrustedBundle` is deprecated. Use `GetTrustedBundle` instead.

```go
package main

import (
    "context"
    "log"

    "github.com/loicsikidi/tpm-ca-certificates/pkg/api"
)

func main() {
    ctx := context.Background()

    // Fetch latest verified bundle
    bundleData, err := api.GetRawTrustedBundle(ctx, api.GetConfig{})
    if err != nil {
        log.Fatal(err)
    }

    // bundleData contains the PEM-encoded trust bundle
    log.Printf("Downloaded %d bytes\n", len(bundleData))
}
```

### Filter by Vendor IDs

```go
// Only include certificates from specific vendors (using constants)
tb, err := api.GetTrustedBundle(ctx, api.GetConfig{
    VendorIDs: []api.VendorID{api.VendorIFX, api.VendorINTC},
})
if err != nil {
    log.Fatal(err)
}
defer tb.Stop()

// GetRoots() will only return certificates from IFX and INTC
certPool := tb.GetRoots()
```

### Enable Auto-Update

```go
import "time"

// Bundle will automatically check for updates every 6 hours
tb, err := api.GetTrustedBundle(ctx, api.GetConfig{
    AutoUpdate: api.AutoUpdateConfig{
        Interval: 6 * time.Hour,
    },
})
if err != nil {
    log.Fatal(err)
}
defer tb.Stop()

// The bundle will automatically update itself when a newer version is available
// All GetRoots(), GetMetadata(), etc. calls are thread-safe during updates
```

### Fetch Specific Date Without Verification

```go
tb, err := api.GetTrustedBundle(ctx, api.GetConfig{
    Date:       "2025-12-05",
    SkipVerify: true,
    AutoUpdate: api.AutoUpdateConfig{
        DisableAutoUpdate: true,
    },
})
```

### Custom HTTP Client

```go
import "net/http"

httpClient := &http.Client{
    Timeout: 30 * time.Second,
}

tb, err := api.GetTrustedBundle(ctx, api.GetConfig{
    HTTPClient: httpClient,
})
```

### Verify Bundle Independently

```go
// Verify a bundle you already have
result, err := api.VerifyTrustedBundle(ctx, api.VerifyConfig{
    Bundle: bundleData,
})
if err != nil {
    log.Fatal(err)
}

// Access verification details
log.Printf("Bundle verified: %s (commit: %s)\n",
    result.BundleMetadata.Date,
    result.BundleMetadata.Commit)
```

### Verify with Explicit Artifacts

```go
// Verify with explicit checksums (useful if you cached them)
result, err := api.VerifyTrustedBundle(ctx, api.VerifyConfig{
    Bundle:            bundleData,
    Checksum:          checksumData,
    ChecksumSignature: checksumSigData,
})
```

## API Reference

### `GetTrustedBundle(ctx context.Context, cfg GetConfig) (TrustedBundle, error)`

Retrieves, verifies, and parses a TPM trust bundle from GitHub releases.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `cfg`: Configuration for the bundle retrieval

**Returns:**
- `TrustedBundle`: Interface providing thread-safe access to the bundle
- `error`: Any error that occurred during download, verification, or parsing

### `TrustedBundle` Interface

Provides thread-safe access to bundle data:

```go
type TrustedBundle interface {
    // GetRaw returns the raw PEM-encoded bundle.
    GetRaw() []byte

    // GetMetadata returns the bundle metadata (date and commit).
    GetMetadata() *bundle.Metadata

    // GetVendors returns the list of vendor IDs in the bundle.
    GetVendors() []VendorID

    // GetRoots returns an x509.CertPool containing certificates.
    // If VendorIDs filter was specified, only those certificates are included.
    GetRoots() *x509.CertPool

    // Stop stops the auto-update watcher if enabled.
    // Safe to call multiple times.
    Stop() error
}
```

### `GetRawTrustedBundle(ctx context.Context, cfg GetConfig) ([]byte, error)` (Deprecated)

**Deprecated:** Use `GetTrustedBundle` instead.

Retrieves and optionally verifies a TPM trust bundle from GitHub releases.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `cfg`: Configuration for the bundle retrieval

**Returns:**
- `[]byte`: The PEM-encoded trust bundle
- `error`: Any error that occurred during download or verification

### `GetConfig`

Configuration struct for bundle retrieval:

```go
type GetConfig struct {
    // Date specifies the bundle release date in YYYY-MM-DD format.
    // If empty, the latest release will be fetched.
    Date string

    // SkipVerify disables bundle verification.
    // When false (default), the bundle will be verified using Cosign and GitHub Attestations.
    SkipVerify bool

    // HTTPClient is the HTTP client to use for requests.
    // If nil, http.DefaultClient will be used.
    HTTPClient *http.Client

    // VendorIDs specifies the list of vendor IDs to filter when calling TrustedBundle.GetRoots().
    // If empty, all certificates from the bundle are included.
    // Only used by GetTrustedBundle.
    VendorIDs []VendorID

    // AutoUpdate configures automatic updates of the bundle.
    // Only used by GetTrustedBundle.
    AutoUpdate AutoUpdateConfig
}
```

### `AutoUpdateConfig`

Configuration for automatic bundle updates:

```go
type AutoUpdateConfig struct {
    // DisableAutoUpdate disables automatic updates of the bundle.
    DisableAutoUpdate bool

    // Interval specifies how often the bundle should be updated.
    // If zero, the default interval of 24 hours is used.
    Interval time.Duration
}
```

### `VendorID`

Type alias for vendor IDs with validation:

```go
type VendorID = vendors.ID

// Vendor ID constants from the TCG registry
const (
    VendorAMD  VendorID = "AMD"
    VendorANT  VendorID = "ANT"
    VendorATML VendorID = "ATML"
    VendorBRCM VendorID = "BRCM"
    VendorCSCO VendorID = "CSCO"
    VendorFLYS VendorID = "FLYS"
    VendorGOOG VendorID = "GOOG"
    VendorHPI  VendorID = "HPI"
    VendorHPE  VendorID = "HPE"
    VendorHISI VendorID = "HISI"
    VendorIBM  VendorID = "IBM"
    VendorIFX  VendorID = "IFX"
    VendorINTC VendorID = "INTC"
    VendorLEN  VendorID = "LEN"
    VendorMSFT VendorID = "MSFT"
    VendorNSG  VendorID = "NSG"
    VendorNSM  VendorID = "NSM"
    VendorNTC  VendorID = "NTC"
    VendorNTZ  VendorID = "NTZ"
    VendorQCOM VendorID = "QCOM"
    VendorROCC VendorID = "ROCC"
    VendorSEAL VendorID = "SEAL"
    VendorSECE VendorID = "SECE"
    VendorSMSN VendorID = "SMSN"
    VendorSMSC VendorID = "SMSC"
    VendorSNS  VendorID = "SNS"
    VendorSTM  VendorID = "STM"
    VendorTXN  VendorID = "TXN"
    VendorWEC  VendorID = "WEC"
)

// Valid vendor IDs list
var ValidVendorIDs []VendorID
```

### `VerifyTrustedBundle(ctx context.Context, cfg VerifyConfig) (*VerifyResult, error)`

Verifies the authenticity and integrity of a TPM trust bundle.

**Parameters:**
- `ctx`: Context for cancellation and timeouts
- `cfg`: Configuration for the bundle verification

**Returns:**
- `*VerifyResult`: Verification details (metadata, attestations, Cosign info)
- `error`: Any error that occurred during verification

### `VerifyConfig`

Configuration struct for bundle verification:

```go
type VerifyConfig struct {
    // Bundle is the content of the trusted bundle to verify.
    //
    // Required.
    Bundle []byte

    // BundleMetadata is the metadata of the bundle to verify.
    //
    // Optional. If not provided, the metadata will be extracted from the bundle content.
    BundleMetadata *bundle.Metadata

    // Checksum is the content of the checksums.txt file to use for verification.
    //
    // Optional. If not provided, the checksum file will be downloaded from the release
    // matching the bundle date.
    Checksum []byte

    // ChecksumSignature is the content of the checksums.txt.sigstore.json file to use for verification.
    //
    // Optional. If not provided, the checksum signature file will be downloaded from the release
    // matching the bundle date.
    ChecksumSignature []byte

    // HTTPClient is the HTTP client to use for requests.
    //
    // Optional. If nil, http.DefaultClient will be used.
    HTTPClient *http.Client
}
```

### `VerifyResult`

```go
type VerifyResult struct {
    BundleMetadata        *bundle.Metadata
    GithubAttestations    []github.Attestation
    CosignVerifyOutput    *cosign.VerifyOutput
}
```

### Global HTTP Client Configuration

```go
// HttpClient returns the current HTTP client used for requests.
func HttpClient() *http.Client

// SetHttpClient sets a custom HTTP client for all requests.
// This is useful for configuring a shared client with custom timeouts, transport, etc.
func SetHttpClient(client *http.Client)
```

## Verification

When verification is enabled (default), the bundle undergoes the following checks:

1. **Cosign Signature Verification**:
   - Verifies keyless signature using Sigstore
   - Validates certificate identity matches expected GitHub Actions workflow
   - Checks SCT (Signed Certificate Timestamp)
   - Verifies transparency log entry

2. **Checksum Validation**:
   - Computes SHA256 hash of bundle
   - Compares against signed checksums file

3. **GitHub Attestations**:
   - Fetches SLSA provenance attestations from GitHub API
   - Verifies attestation signatures
   - Validates build metadata (commit hash, timestamp, workflow)

4. **Metadata Validation**:
   - Ensures bundle metadata (date, commit) matches attestations
   - Verifies Rekor timestamp matches release date

## Error Handling

The package defines specific error types for common failure scenarios:

```go
var (
    // ErrBundleNotFound is returned when the requested bundle is not found.
    ErrBundleNotFound = errors.New("trusted bundle not found for the specified date")

    // ErrBundleVerificationFailed is returned when the bundle verification fails.
    ErrBundleVerificationFailed = errors.New("trusted bundle verification failed")
)
```

All errors are wrapped with context, making it easy to identify the failure point:

```go
bundleData, err := api.GetRawTrustedBundle(ctx, cfg)
if err != nil {
    // Error messages include full context, e.g.:
    // "failed to download bundle: asset not found"
    // "verification failed: checksum mismatch"
    log.Fatal(err)
}
```

## Bundle Format

The returned bundle is a PEM-encoded file containing:

- Global metadata (date, commit)
- Per-vendor sections with CA certificates
- Each certificate includes:
  - Subject, Issuer
  - SHA256 fingerprint
  - Validity period
  - Serial number

Example:

```
##
## tpm-ca-certificates.pem
##
## Date: 2025-12-05
## Commit: abc123...
##

##
## Vendor: INTC (Intel Corporation)
##

## Subject: CN=Intel TPM Root CA
## ...
-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
```
