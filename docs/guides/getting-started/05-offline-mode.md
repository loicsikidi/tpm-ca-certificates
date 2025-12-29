# Working in Offline Mode

## Who This Guide Is For

This guide is for users working in secure or restricted environments with limited or no Internet access.

**Your goal:** Set up and use TPM trust bundles completely offline.

**What you'll learn:**
- How to save bundles and verification artifacts for offline use
- How to verify bundles without Internet access
- How to use the SDK in offline mode
- How to work in air-gapped environments

---

## Prerequisites

- ✅ `tpmtb` installed ([Installation Guide](./01-installation.md))
- ✅ Access to a machine with Internet (for initial download)

> [!NOTE]
>  Requests are performed to the following domains:
>   - `https://api.github.com`
>   - `https://github.com/loicsikidi/tpm-ca-certificates/releases/download/*`
>   - `https://tuf-repo-cdn.sigstore.dev`

## Why Offline Mode? 🔒

Offline mode is essential for:

- **Secure environments:** Air-gapped systems that cannot access the Internet
- **Compliance requirements:** Environments where Internet access is restricted
- **Network reliability:** Situations where Internet connectivity is unreliable

## How It Works 📦

Offline mode works by saving all necessary artifacts locally:

1. **Bundles:** The TPM CA certificates
   - Root certificates: `tpm-ca-certificates.pem`
   - Intermediate certificates: `tpm-intermediate-ca-certificates.pem`
2. **Checksums:** SHA256 checksums for integrity verification (`checksums.txt`)
3. **Signatures:** Cosign signature for authenticity (`checksums.txt.sigstore.json`)
4. **Provenance:** GitHub attestation for supply chain verification (`provenance.json`)
5. **Trust root:** Sigstore trusted root (`trusted-root.json`) - enables offline verification of the transparency log

Once saved, these artifacts can be transferred to offline systems and used without Internet access.

> [!NOTE]
> The cached artifacts do not contain any private or sensitive data. They can be safely committed to version control systems (e.g., Git) for distribution or historization purposes.

## CLI Usage 💻

### Step 1: Save Bundle and Artifacts (Online System)

On a machine with Internet access, download and save all artifacts:

```bash
# Save to a specific directory
tpmtb bundle save --output-dir /path/to/cache

# Example: Save to a USB drive
tpmtb bundle save --output-dir /media/usb/tpm-bundles
```

**What gets saved:**
```
/path/to/cache/
├── tpm-ca-certificates.pem                 # Root certificates bundle
├── tpm-intermediate-ca-certificates.pem    # Intermediate certificates bundle
├── checksums.txt                           # SHA256 checksums
├── checksums.txt.sigstore.json             # Cosign signature
├── provenance.json                         # GitHub attestation
└── trusted-root.json                       # Sigstore Trust Root
```

> [!IMPORTANT]
> The `trusted-root.json` (aka Sigstore Trust Root) contains trusted keys and certificates used to verify artifacts produced by the Sigstore ecosystem. With it, we can verify:
> - Certificates issued by Fulcio
> - Entries in the Rekor transparency log

> [!TIP]
> The `save` command automatically downloads the latest bundle and all verification artifacts. You can also specify a specific date with `--date YYYY-MM-DD`.

### Step 2: Transfer to Offline System

Transfer the cache directory to your offline system using:
- USB drive
- Shared network drive
- Approved file transfer mechanism

### Step 3: Verify Bundle (Offline System)

On the offline system, verify the bundle using the cached artifacts:

```bash
# Verify using cached artifacts
tpmtb bundle verify --cache-dir /path/to/cache --offline

# Example: Verify from transferred cache
tpmtb bundle verify --cache-dir /media/usb/tpm-bundles --offline
```

**Verification in offline mode:**
- ✅ Verifies bundle integrity using checksums
- ✅ Verifies Cosign signature (keyless verification)
- ✅ Verifies GitHub attestation (SLSA provenance)
- ❌ **Does not** fetch artifacts from the Internet

> [!IMPORTANT]
> The `--offline` flag is crucial! Without it, the CLI will attempt to download missing artifacts from the Internet.

## SDK Usage (Go) 🔧

### Saving Artifacts for Offline Use

On a system with Internet access, save the bundle and artifacts:

```go
package main

import (
	"context"
	"log"

	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
)

func main() {
	ctx := context.Background()

	// Get and verify the latest bundle
	resp, err := apiv1beta.Save(ctx, apiv1beta.SaveConfig{})
	if err != nil {
		log.Fatalf("Failed to get bundle: %v", err)
	}

	// Save all artifacts for offline use
	if err := resp.Persist("/path/to/cache"); err != nil {
		log.Fatalf("Failed to persist cache: %v", err)
	}

	log.Println("Bundle and verification artifacts saved successfully")
}
```

**What gets persisted:**
- `tpm-ca-certificates.pem` - Root certificates bundle
- `tpm-intermediate-ca-certificates.pem` - Intermediate certificates bundle
- `checksums.txt` - SHA256 checksums
- `checksums.txt.sigstore.json` - Cosign signature
- `provenance.json` - GitHub attestation
- `trusted-root.json` - Sigstore trust root (read-only, mode `0600`)
- `config.json` - Cache configuration

> [!NOTE]
> All artifacts except `trusted-root.json` can be safely committed to version control for distribution purposes.

### Loading Bundle in Offline Mode

On the offline system, load and verify the bundle:

```go
package main

import (
	"context"
	"fmt"
	"log"

	"github.com/loicsikidi/tpm-ca-certificates/pkg/apiv1beta"
)

func main() {
	ctx := context.Background()

	// Load bundle in offline mode
	tb, err := apiv1beta.Load(ctx, apiv1beta.LoadConfig{
		OfflineMode: true,
		CachePath:   "/path/to/cache",
	})
	if err != nil {
		log.Fatalf("Failed to load bundle: %v", err)
	}
	defer tb.Stop()

	// Bundle is verified and ready to use
	metadata := tb.GetRootMetadata()
	fmt.Printf("Bundle date: %s\n", metadata.Date)
	fmt.Printf("Bundle commit: %s\n", metadata.Commit)

	// Get raw PEM-encoded bundle
	rawBundle := tb.GetRawRoot()
}
```

> [!WARNING]
> When `OfflineMode: true`, the SDK will **fail** if any verification artifacts are missing. Ensure all artifacts were properly saved using `Persist()`.
>
> In addition, for obvious reasons, auto-updates are disabled in offline mode.

## Advanced Scenarios 🎯

### Using Specific Bundle Versions Offline

Save a specific version for offline use:

```bash
# CLI: Save specific date
tpmtb bundle save --date 2025-12-27 --output-dir /path/to/cache

# Then verify offline
tpmtb bundle verify --cache-dir /path/to/cache --offline
```

```go
// SDK: Save specific date
tb, err := apiv1beta.Save(ctx, apiv1beta.SaveConfig{
	Date: "2025-12-27",
})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop()

if err := tb.Persist("/path/to/cache"); err != nil {
	log.Fatal(err)
}
```

### Vendor Filtering in Offline Mode

Filter by vendor when saving for offline use:

```go
// Save only specific vendors
tb, err := apiv1beta.Save(ctx, apiv1beta.SaveConfig{
	VendorIDs: []apiv1beta.VendorID{
		apiv1beta.IFX, // Infineon
		apiv1beta.NTC, // Nuvoton
	},
})
if err != nil {
	log.Fatal(err)
}
defer tb.Stop()

// Persist filtered bundle
if err := tb.Persist("/path/to/cache"); err != nil {
	log.Fatal(err)
}

// On offline system, load with vendor filter preserved
tb, err = apiv1beta.Load(ctx, apiv1beta.LoadConfig{
	OfflineMode: true,
	CachePath:   "/path/to/cache",
})
// Bundle only contains IFX and NTC certificates
```

## Security Considerations 🔒

> [!IMPORTANT]
> Offline mode maintains the same security guarantees as online mode:
> - Bundle integrity is verified using checksums
> - Authenticity is verified using Cosign signatures
> - Provenance is verified using GitHub attestations
>
> The only difference: artifacts are loaded from local cache instead of being downloaded.

## Additional Resources 📚

For more details about offline capabilities:
- 📖 [Local Cache Specification](../../specifications/07-local-cache.md) - Cache system details
- 📖 [Full Offline Mode Specification](../../specifications/08-full-offline-mode.md) - Complete offline verification
- 📖 [Bundle Verification Specification](../../specifications/05-bundle-verification.md) - Verification process

## Next Steps 🚀

- 🤝 Want to contribute? Check the [Contributing Guide](./06-contributing.md)

## Need Help? 🆘

- 💬 [GitHub Discussions](https://github.com/loicsikidi/tpm-ca-certificates/discussions) - Ask questions
- 🐛 [GitHub Issues](https://github.com/loicsikidi/tpm-ca-certificates/issues) - Report bugs

---

**Stay secure, even offline!** 🔐
