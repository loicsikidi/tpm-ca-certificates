# Using the SDK in Go

## Who This Guide Is For

This guide is for Go developers who want to integrate TPM trust bundle retrieval into their applications programmatically.

**Your goal:** Use the `pkg/apiv1beta` package to fetch, verify, and use TPM root certificates in your Go code.

**What you'll learn:**
- How to fetch and verify trust bundles programmatically
- How to use the bundle in your application
- How to enable automatic updates
- How to filter certificates by vendor

---

## Prerequisites

- ✅ Go 1.25+
- 📦 Basic understanding of Go modules

## Installation

Add the library to your project:

```bash
go get github.com/loicsikidi/tpm-ca-certificates@latest
```

## Quick Start ⚡

### Basic Usage

The simplest way to get started is to fetch the latest verified bundle:

```go
package main

import (
	"context"
	"log"

	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
)

func main() {
	ctx := context.Background()

	// Get the latest verified bundle
	tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{})
	if err != nil {
		log.Fatalf("Failed to get bundle: %v", err)
	}
	defer tb.Stop()

	// Get certificate pool with all TPM root certificates
	certPool := tb.GetRoots()

	// Use certPool in your TPM verification logic
	_ = certPool
}
```

> [!NOTE]
> By default, the bundle is automatically verified using Cosign signatures and GitHub Attestations. See the [verification specification](../../specifications/05-bundle-verification.md) for details.

### Using Bundle Metadata

Access bundle metadata to understand which version you're using:

```go
metadata := tb.GetMetadata()
log.Printf("Bundle date: %s", metadata.Date)
log.Printf("Bundle commit: %s", metadata.Commit)

// Get raw PEM-encoded bundle
rawBundle := tb.GetRaw()
```

## Advanced Usage 🔧

### Filtering by Vendor

If your TPM chips come from specific vendors, you can filter certificates for a least-privilege approach:

```go
// Only include certificates from Infineon and Nuvoton
tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{
	VendorIDs: []apiv1beta.VendorID{
		apiv1beta.IFX, // Infineon
		apiv1beta.NTC, // Nuvoton
	},
})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop()

// GetRoots() will only return certificates from specified vendors
certPool := tb.GetRoots()

// Check which vendors are in the bundle
vendors := tb.GetVendors()
for _, vendor := range vendors {
	log.Printf("Vendor: %s", vendor)
}
```

**Available Vendor IDs:**

```go
apiv1beta.IFX  // Infineon Technologies
apiv1beta.INTC // Intel
apiv1beta.NTC  // Nuvoton Technology Corporation
apiv1beta.STM  // STMicroelectronics
```

### Using a Specific Release

Fetch a bundle from a specific date:

```go
tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{
	Date: "2025-12-03",
})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop()
```

### Automatic Updates

Enable automatic updates to keep your bundle fresh:

```go
import "time"

// Check for updates every 6 hours
tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{
	AutoUpdate: apiv1beta.AutoUpdateConfig{
		Interval: 6 * time.Hour,
	},
})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop() // Important: Stop the background watcher when done
```

> [!WARNING]
> When auto-update is enabled, always call `tb.Stop()` before your application exits to cleanly shutdown the background watcher.

**How Auto-Update Works:**
- 🔄 Background goroutine checks for new releases at the specified interval
- ✅ New bundles are verified before updating
- 🔒 Updates are atomic and thread-safe
- 📅 Only updates if a newer release date is available

### Disabling Auto-Update

If you prefer to control bundle updates manually, disable auto-update:

```go
tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{
	AutoUpdate: apiv1beta.AutoUpdateConfig{
		DisableAutoUpdate: true,
	},
})
if err != nil {
	log.Fatal(err)
}
// No need to call tb.Stop() when auto-update is disabled
```

> [!TIP]
> Disabling auto-update is useful when:
> - You want to control update timing explicitly (e.g., during maintenance windows)
> - You prefer to restart your application to pick up new bundles

### Disabling Verification

> [!CAUTION]
> Skipping verification defeats the purpose of supply chain security. Only use this for testing or if you have an alternative verification mechanism.

```go
tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{
	SkipVerify: true, // Not recommended for production
})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop()
```

### Custom HTTP Client

Use a custom HTTP client for proxies or custom transport:

```go
import "net/http"

client := &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		Proxy: http.ProxyFromEnvironment,
	},
}

tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{
	HTTPClient: client,
})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop()
```

## Manual Verification

Verify a bundle that you've already downloaded:

```go
import "os"

// Read bundle from file
bundleData, err := os.ReadFile("tpm-ca-certificates.pem")
if err != nil {
	log.Fatal(err)
}

// Verify with auto-detected metadata and auto-downloaded checksums
result, err := apiv1beta.VerifyTrustedBundle(ctx, apiv1beta.VerifyConfig{
	Bundle: bundleData,
})
if err != nil {
	log.Fatalf("Verification failed: %v", err)
}

log.Printf("Bundle verified successfully!")
log.Printf("Integrity verified: %v", result.IntegrityVerified)
log.Printf("Provenance verified: %v", result.ProvenanceVerified)
```

**With explicit checksums:**

```go
checksumData, _ := os.ReadFile("checksums.txt")
checksumSigData, _ := os.ReadFile("checksums.txt.sigstore.json")

result, err := apiv1beta.VerifyTrustedBundle(ctx, apiv1beta.VerifyConfig{
	Bundle:            bundleData,
	Checksum:          checksumData,
	ChecksumSignature: checksumSigData,
})
```

## Complete Example 🎯

Here's a complete example showing best practices:

```go
package main

import (
	"context"
	"crypto/x509"
	"log"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
)

func main() {
	ctx := context.Background()

	// Configure bundle retrieval
	config := apiv1beta.GetConfig{
		// Filter by vendors if known
		VendorIDs: []apiv1beta.VendorID{
			apiv1beta.IFX,
			apiv1beta.NTC,
		},
		// Enable auto-update every 12 hours
		AutoUpdate: apiv1beta.AutoUpdateConfig{
			Interval: 12 * time.Hour,
		},
	}

	// Get verified bundle
	tb, err := apiv1beta.GetTrustedBundle(ctx, config)
	if err != nil {
		log.Fatalf("Failed to get bundle: %v", err)
	}
	defer tb.Stop()

	// Log bundle information
	metadata := tb.GetMetadata()
	log.Printf("Using bundle from %s (commit: %s)", metadata.Date, metadata.Commit)

	vendors := tb.GetVendors()
	log.Printf("Bundle contains certificates from %d vendor(s)", len(vendors))

	// Get certificate pool
	certPool := tb.GetRoots()

	// Use in your application
	verifyTPMEndorsementKey(certPool)
}

func verifyTPMEndorsementKey(roots *x509.CertPool) {
	// Your TPM verification logic here
	_ = roots
}
```

## Error Handling

The API returns specific errors for common cases:

```go
import "errors"

tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{
	Date: "2025-01-01", // Non-existent release
})
if errors.Is(err, apiv1beta.ErrBundleNotFound) {
	log.Println("Bundle not found for specified date")
}

// Verification errors
_, err = apiv1beta.VerifyTrustedBundle(ctx, apiv1beta.VerifyConfig{
	Bundle: maliciousData,
})
if errors.Is(err, apiv1beta.ErrBundleVerificationFailed) {
	log.Println("Bundle verification failed - possible tampering!")
}
```

## API Stability ⚠️

> [!IMPORTANT]
> The `pkg/apiv1beta` package is in **beta** and subject to breaking changes without notice. See the [API Versioning specification](../../specifications/06-api-versioning.md) for details.
>
> - Use this API for experimentation and feedback
> - Pin to a specific version in production: `go get github.com/loicsikidi/tpm-ca-certificates@v0.x.x`
> - Watch for announcements about `pkg/apiv1` (stable API) in future releases

## Next Steps 🚀

- 🤝 Want to contribute? Check the [Contributing Guide](./05-contributing.md)

## Additional Resources 📚

- 📦 [pkg.go.dev documentation](https://pkg.go.dev/github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta) - Full API reference
- 📖 [API Versioning Specification](../../specifications/06-api-versioning.md) - Understand API stability guarantees
- 🔐 [Bundle Verification Specification](../../specifications/05-bundle-verification.md) - Learn about the verification process
- 💬 [GitHub Discussions](https://github.com/loicsikidi/tpm-ca-certificates/discussions) - Ask questions
- 🐛 [GitHub Issues](https://github.com/loicsikidi/tpm-ca-certificates/issues) - Report bugs
