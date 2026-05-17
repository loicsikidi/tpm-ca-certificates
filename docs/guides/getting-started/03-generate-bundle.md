# Bundle Generation

## Who This Guide Is For

This guide is for anyone who wants to understand how TPM trust bundles are generated from configuration.

**Your goal:** Learn the bundle generation workflow and the trust model behind it.

**What you'll learn:**
- How `.tpm-roots.yaml` and `.tpm-intermediates.yaml` drive bundle generation
- The difference between root and intermediate certificates
- The role of evidence in the `src/` directory
- The automated verification process

---

## The Two Pillars of Trust

### 1. Configuration Files - The Source of Truth

This project manages two types of TPM certificates, each with its own configuration file:

#### Root Certificates (`.tpm-roots.yaml`)
- **Purpose:** Self-signed root certificates that serve as trust anchors
- **Format:** Human-readable YAML

```yaml
---
version: "alpha"
vendors:
    - id: "NTC"
      name: "Nuvoton Technology"
      certificates:
        - name: "Nuvoton TPM Root CA 1110"
          uri: "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%201110.cer"
          validation:
            fingerprint:
                sha1: "65:5E:44:5E:96:54:5C:F3:E4:84:82:94:9B:35:A7:CE:B3:46:58:CC"
```

#### Intermediate Certificates (`.tpm-intermediates.yaml`)
- **Purpose:** Certificates issued by root CAs to sign end-entity certificates
- **Format:** Same structure as `.tpm-roots.yaml`

Both files are designed to be:
- ✅ **Human-readable:** Anyone can understand what certificates are included
- ✅ **Verifiable:** Clear provenance for every certificate URI
- ✅ **Auditable:** Git history tracks every change

**Key principle:** Certificate source URIs must use HTTPS by default, with a documented exception for local certificates using `file:///{local}/`.

#### Exception: Local Certificates (`file:///{local}/`)

The `file:///{local}/` scheme allows referencing certificates stored in the repository when they are no longer publicly available:

```yaml
certificates:
  - name: "Example TPM Root CA"
    uri: "file:///{local}/certificates/$VENDOR_ID/certificate.cer"
    validation:
      fingerprint:
        sha256: "AB:CD:EF:..."
```

**When to use this exception:**
- The certificate was previously available via HTTPS and included in the bundle
- The vendor has not announced the certificate as compromised or untrusted
- The certificate is still valid and used by deployed TPM devices

**Security note:** Fingerprint validation remains mandatory for local certificates - only the source location changes, the cryptographic verification is identical.

> [!INFO]
> See the [certificates](../../../certificates) directory for more details.

> [!TIP]
> See the [Configuration File Specification](../../specifications/01-configuration-file.md) for complete format details.

### 2. `src/` - The Evidence Archive

Saying "I found this URI on the vendor website" isn't enough. Prove it!

The `src/` directory contains receipts:
- 📄 **PDFs** from vendor documentation
- 🖼️ **Screenshots** of official vendor pages
- 📝 **README files** documenting the discovery process

```
src/
├── NTC/
│   ├── README.md                                    # Discovery documentation
│   ├── Nuvoton_TPM_EK_Certificate_Chain_Rev2.2.pdf  # Official vendor PDF
│   └── nuvoton_website.png                          # Screenshot proof
├── ... # Other vendors
└── README.md  # Index of all vendors
```

**Why this matters:**
- 🔍 **Transparency:** Anyone can verify how URIs were discovered
- 📜 **History:** Future auditors can understand past decisions

> [!NOTE]
> Check out [src/README.md](../../../src/README.md) for the complete vendor evidence index.

## How Bundle Generation Works

The project generates **two separate bundles**:
1. **Root bundle** from `.tpm-roots.yaml` - Contains trust anchors
2. **Intermediate bundle** from `.tpm-intermediates.yaml` - Contains intermediate certificates

> [!NOTE]
> The intermediate bundle is a convenience tool that allows trust verification without downloading certificates from the internet. It is essential for **offline validation** scenarios.

### Step 1: Configuration Validation

```bash
# Validate root certificates
tpmtb config validate --config .tpm-roots.yaml

# Validate intermediate certificates
tpmtb config validate --config .tpm-intermediates.yaml
```

The CLI checks:
- ✅ YAML syntax is correct
- ✅ Vendor IDs exist in TCG registry
- ✅ All URIs use HTTPS (or `file:///{local}/` for local certificates)
- ✅ Fingerprints are properly formatted

> [!IMPORTANT]
> Only valid configurations can generate bundles. This prevents accidental inclusion of malformed data.

### Step 2: Generate the Bundles

```bash
# Generate root bundle (uses .tpm-roots.yaml)
tpmtb generate --config .tpm-roots.yaml --workers 10 --output tpm-ca-certificates.pem

# Generate intermediate bundle (uses .tpm-intermediates.yaml)
tpmtb generate --config .tpm-intermediates.yaml --workers 10 --output tpm-intermediate-certificates.pem
```

For each certificate (root or intermediate):
1. **Fetch** from the vendor URI (HTTPS) or read from local path (`file:///{local}/`)
2. **Verify** fingerprint matches the configuration
3. **Extract** certificate metadata (issuer, subject, validity, etc.)
4. **Format** with human-readable comments

### Step 3: Bundle Assembly

The tool assembles certificates into PEM files:

```
##
## tpm-ca-certificates.pem
##
## Date: 2025-12-04
## Commit: abc123...
##

#
# Certificate: Nuvoton TPM Root CA 1110
# Owner: NTC
#
# Issuer: CN=Nuvoton TPM Root CA 1110,O=Nuvoton Technology Corporation,C=TW
# Not Valid After: Sun Apr 27 16:36:58 2053
# Fingerprint (SHA-256): 65:5E:44:5E:96:54:...
-----BEGIN CERTIFICATE-----
MIICaTCCAcugAwIBAgIBAjAKBggqhkjOPQQDBDBW...
-----END CERTIFICATE-----
```

**Human-readable + machine-parseable = Best of both worlds!**

### The Two Bundles Explained

**Root Bundle (`tpm-ca-certificates.pem`)**
- Contains self-signed root certificates (trust anchors)
- Used to establish the root of trust in verification chains

**Intermediate Bundle (`tpm-intermediate-certificates.pem`)**
- Contains intermediate certificates issued by root CAs
- Provides offline verification capability without fetching certificates from the internet
- Convenience tool that speeds up validation by having all intermediates locally available
- Essential for scenarios where internet access is restricted or not available

Both bundles share the same format and structure, only differing in the type of certificates they contain.

## Why This Process Exists

**The Problem:** TPM root/intermediate certificates are scattered across vendor websites, PDFs, and various channels. There's no central registry.

**The Solution:**
- 🔓 **Open Source:** All data is public and auditable
- 🧑‍⚖️ **Human Review:** Maintainers validate every addition
- 📚 **Evidence-Based:** Every claim requires proof
- 🤖 **Automated Checks:** CLI enforces formatting and validation rules

**The Result:** A trust bundle you can actually trust.

## Daily Monitoring

A scheduled job runs daily to:

- 🔄 **Regenerate** the bundle from scratch
- 🔐 **Verify** all certificate fingerprints still match
- 🌐 **Check** vendor URIs are still accessible
- ⏰ **Monitor** certificate expiration dates
- 🛡️ **Test** the latest release verification workflow

If something breaks (compromised vendor site, expired certificate, etc.), the team gets alerted immediately.

> [!TIP]
> This continuous monitoring provides early warning of supply chain attacks.

## Next Steps

Now that you understand bundle generation:

- 💻 Learn [Using the SDK in Go](./04-using-sdk-in-go.md) to integrate bundle retrieval in your applications

## Additional Resources

- 📖 [Configuration File Specification](../../specifications/01-configuration-file.md) - Complete YAML format details
- 🔒 [Security Model](../../concepts/01-security_model.md) - Trust principles and mechanisms
