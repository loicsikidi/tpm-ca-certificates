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

### Basic Usage: Verifying TPM Endorsement Keys

The most common use case is verifying TPM Endorsement Key (EK) certificates:

```go
package main

import (
	"context"
	"crypto/x509"
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

	// Load your TPM EK certificate (from TPM or external source)
	ekCert := loadEKCertificate() // Your implementation

	// Verify the EK certificate against the trusted bundle
	if err := tb.VerifyCertificate(ekCert); err != nil {
		log.Fatalf("EK certificate verification failed: %v", err)
	}

	log.Println("EK certificate verified successfully!")
}
```

> [!NOTE]
> `VerifyCertificate` automatically handles TPM-specific certificate quirks, including non-standard OIDs and key usages.

### Alternative: Using Certificate Pools

If you prefer working with `x509.CertPool` directly:

```go
// Use certPool in your TPM verification logic
opts := x509.VerifyOptions{
	Roots: tb.GetRoots(),
	Intermediates: tb.GetIntermediates(),
	// ... other options
}
```

> [!TIP]
> The bundle is automatically verified using Cosign signatures and GitHub Attestations. See the [verification specification](../../specifications/05-bundle-verification.md) for details.

## Default Behavior 🎯

The SDK is designed with **security and resilience** in mind. By default:

### Auto-Update and Local Cache

**Enabled by default** to ensure your bundle stays fresh and survives restarts:

- **Auto-update:** Checks for new bundles every **24 hours**
- **Local cache:** Stores bundle in **`$HOME/.tpmtb`** (filesystem)

**Why these defaults?**

1. **Security first:** Automatic updates ensure you get the latest CA certificates
2. **Restart resilience:** Cached bundles survive application restarts without re-downloading

### Disabling Auto-Update

For environments where you want manual control over bundle updates:

```go
tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{
    Date: "YYYY-MM-DD", // Fixed date
	AutoUpdate: apiv1beta.AutoUpdateConfig{
		DisableAutoUpdate: true,
	},
})
if err != nil {
	log.Fatal(err)
}
```

### In-Memory Mode (Read-Only Filesystems)

For containerized or restricted environments with read-only filesystems:

```go
tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{
    DisableLocalCache: true, // No filesystem access,
})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop()
```

> [!WARNING]
> With `DisableLocalCache: true`, the `Persist()` method will return an error. This mode is purely in-memory.

### Using Bundle Metadata

Access bundle metadata to understand which version you're using:

```go
metadata := tb.GetRootMetadata()
log.Printf("Bundle date: %s", metadata.Date)
log.Printf("Bundle commit: %s", metadata.Commit)

metadata = tb.GetIntermediateMetadata()
log.Printf("Intermediate bundle date: %s", metadata.Date)
log.Printf("Intermediate bundle commit: %s", metadata.Commit)
```

## Working with TPM Certificates 🔐

### Verifying EK Certificates

The `VerifyCertificate` method is the recommended way to verify TPM Endorsement Key certificates:

```go
// Verify an EK certificate
if err := tb.VerifyCertificate(ekCert); err != nil {
	log.Fatalf("Verification failed: %v", err)
}
```

**Why use `VerifyCertificate`?**

- ✅ Automatically handles TPM-specific OIDs that `x509` doesn't recognize
- ✅ Clears `UnhandledCriticalExtensions` to work around TPM quirks
- ✅ Uses appropriate key usages (`ExtKeyUsageAny`) for TPM certificates
- ✅ Thread-safe and ready for concurrent use

### Advanced Verification with GetVerifyOptions

For custom verification scenarios, use `GetVerifyOptions`:

```go
// Get pre-configured verify options for TPM certificates
opts := tb.GetVerifyOptions()

// Customize if needed
opts.CurrentTime = customTime
opts.DNSName = "example.com" // Usually not needed for EK certs

// Copy and modify the certificate to handle TPM-specific extensions
ekCopy := *ekCert
ekCopy.UnhandledCriticalExtensions = nil

// Verify manually
chains, err := ekCopy.Verify(opts)
if err != nil {
	log.Fatalf("Verification failed: %v", err)
}

log.Printf("Certificate verified with %d chain(s)", len(chains))
```

**What `GetVerifyOptions` provides:**

- **Roots**: All root certificates from the bundle (filtered by vendor if configured)
- **Intermediates**: All intermediate certificates (if available in the bundle)
- **KeyUsages**: Set to `x509.ExtKeyUsageAny` for TPM compatibility

### Checking Certificate Presence

Check if a certificate is already in the bundle:

```go
// Check if a certificate is in the root or intermediate catalog
if tb.Contains(cert) {
	log.Println("Certificate is a trusted root or intermediate")
} else {
	log.Println("Certificate is not in the bundle")
}
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
	AutoUpdate: apiv1beta.AutoUpdateConfig{ // To prevent updates
		DisableAutoUpdate: true,
	},
})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop()
```

### Customizing Auto-Update Interval

Change the default 24-hour interval to suit your needs:

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

### Custom Cache Path

Override the default cache location (`$HOME/.tpmtb`):

```go
tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{
	CachePath: "/custom/cache/path",
})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop()
```

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

#### Global HTTP Client Configuration

Set a custom HTTP client globally for all API calls:

```go
import (
	"net/http"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
)

func init() {
	// Configure custom client with timeouts and proxy
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			Proxy:                 http.ProxyFromEnvironment,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		},
	}

	// Set global HTTP client
	apiv1beta.SetHTTPClient(client)
}

func main() {
	ctx := context.Background()

	// This will use the global HTTP client
	tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{})
	if err != nil {
		log.Fatal(err)
	}
	defer tb.Stop()
}
```

#### Per-Request Configuration

Use a custom HTTP client for specific requests:

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

> [!NOTE]
> Per-request HTTP client configuration takes precedence over the global setting.

## Persisting and Loading Bundles 💾

### Persist to Disk

Save a bundle and its verification assets to disk for later use:

```go
// Get and verify a bundle
tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop()

// Persist to default location ($HOME/.tpmtb)
if err := tb.Persist(); err != nil {
	log.Fatalf("Failed to persist bundle: %v", err)
}

// Or persist to a custom location
if err := tb.Persist("/custom/cache/path"); err != nil {
	log.Fatalf("Failed to persist bundle: %v", err)
}
```

**What gets persisted:**
- `tpm-ca-certificates.pem` - The bundle itself
- `checksums.txt` - SHA256 checksums
- `checksums.txt.sigstore.json` - Cosign signature
- `provenance.json` - GitHub attestation
- `config.json` - Bundle configuration (vendor filter, auto-update settings)

### Load from Disk

Load a previously persisted bundle:

```go
// Load from default location ($HOME/.tpmtb)
tb, err := apiv1beta.LoadTrustedBundle(ctx, apiv1beta.LoadConfig{})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop()

// Or load from a custom location
tb, err = apiv1beta.LoadTrustedBundle(ctx, apiv1beta.LoadConfig{
	CachePath: "/custom/cache/path",
})
if err != nil {
	log.Fatal(err)
}

// Bundle is automatically verified on load
certPool := tb.GetRoots()
```

> [!NOTE]
> When loading a bundle, verification is performed automatically using the persisted verification assets. If verification fails, `Load` returns an error.

### Persist and Load with Auto-Update

When you persist a bundle with auto-update enabled, the configuration is saved and restored on load:

```go
// First run: Get bundle with auto-update and persist
tb, err := apiv1beta.GetTrustedBundle(ctx, apiv1beta.GetConfig{
	AutoUpdate: apiv1beta.AutoUpdateConfig{
		Interval: 6 * time.Hour,
	},
})
if err != nil {
	log.Fatal(err)
}

if err := tb.Persist(); err != nil {
	log.Fatal(err)
}
tb.Stop()

// Later run: Load persisted bundle - auto-update resumes automatically
tb, err = apiv1beta.LoadTrustedBundle(ctx, apiv1beta.LoadConfig{})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop() // Still needed to stop the watcher

// Bundle will auto-update every 6 hours
certPool := tb.GetRoots()
```

> [!TIP]
> This pattern is useful for long-running services that restart occasionally. The bundle persists across restarts and auto-update resumes seamlessly.

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

Here's a complete example showing best practices for TPM EK verification:

```go
package main

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
)

func main() {
	ctx := context.Background()

	// Configure bundle retrieval
	config := apiv1beta.GetConfig{
		// Filter by vendors if known
		VendorIDs: []apiv1beta.VendorID{
			apiv1beta.IFX,  // Infineon
			apiv1beta.NTC,  // Nuvoton
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
	metadata := tb.GetRootMetadata()
	log.Printf("Using bundle from %s (commit: %s)", metadata.Date, metadata.Commit)

	vendors := tb.GetVendors()
	log.Printf("Bundle contains certificates from %d vendor(s)", len(vendors))

	// Load and verify TPM EK certificate
	ekCert, err := loadEKCertificate("ek-certificate.pem")
	if err != nil {
		log.Fatalf("Failed to load EK certificate: %v", err)
	}

	if err := tb.VerifyCertificate(ekCert); err != nil {
		log.Fatalf("EK verification failed: %v", err)
	}

	log.Printf("✅ EK certificate verified successfully!")
	log.Printf("   Subject: %s", ekCert.Subject)
	log.Printf("   Issuer: %s", ekCert.Issuer)
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

- 🔒 Working in secure environments? Learn about [Offline Mode](./05-offline-mode.md)
- 🤝 Want to contribute? Check the [Contributing Guide](./06-contributing.md)

## Additional Resources 📚

- 📦 [pkg.go.dev documentation](https://pkg.go.dev/github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta) - Full API reference
- 📖 [API Versioning Specification](../../specifications/06-api-versioning.md) - Understand API stability guarantees
- 🔐 [Bundle Verification Specification](../../specifications/05-bundle-verification.md) - Learn about the verification process
- 💬 [GitHub Discussions](https://github.com/loicsikidi/tpm-ca-certificates/discussions) - Ask questions
- 🐛 [GitHub Issues](https://github.com/loicsikidi/tpm-ca-certificates/issues) - Report bugs
