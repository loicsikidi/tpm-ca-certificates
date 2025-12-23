# Bundle Generation

## Who This Guide Is For

This guide is for anyone who wants to understand how TPM trust bundles are generated from configuration.

**Your goal:** Learn the bundle generation workflow and the trust model behind it.

**What you'll learn:**
- How `.tpm-roots.yaml` drives bundle generation
- The role of evidence in the `src/` directory
- The automated verification process

---

## The Three Pillars of Trust

### 1. `.tpm-roots.yaml` - The Source of Truth

This YAML file is the heart of the system. It's designed to be:

- ✅ **Human-readable:** Anyone can understand what certificates are included
- ✅ **Verifiable:** Clear provenance for every certificate URL
- ✅ **Auditable:** Git history tracks every change

```yaml
---
version: "alpha"
vendors:
    - id: "NTC"
      name: "Nuvoton Technology"
      certificates:
        - name: "Nuvoton TPM Root CA 1110"
          url: "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%201110.cer"
          validation:
            fingerprint:
                sha1: "65:5E:44:5E:96:54:5C:F3:E4:84:82:94:9B:35:A7:CE:B3:46:58:CC"
```

**Key principle:** Every certificate must have a publicly accessible URL.

> [!TIP]
> See the [Configuration File Specification](../../specifications/01-configuration-file.md) for complete format details.

### 2. `src/` - The Evidence Archive

Saying "I found this URL on the vendor website" isn't enough. Prove it!

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
- 🔍 **Transparency:** Anyone can verify how URLs were discovered
- 🛡️ **Protection:** Guards against malicious URL injections
- 📜 **History:** Future auditors can understand past decisions

> [!NOTE]
> Check out [src/README.md](../../../src/README.md) for the complete vendor evidence index.

### 3. Pull Request + Evidence = Trust

Want to add a new certificate? Here's the deal:

1. **Modify** `.tpm-roots.yaml` with the new certificate
2. **Provide evidence** in `src/VENDOR_ID/`
3. **Submit a PR** for review

**No evidence = No merge.** It's that simple.

The human review process ensures:
- ✅ URLs point to legitimate vendor sources
- ✅ Evidence is credible and properly archived
- ✅ Fingerprints match vendor documentation (when available)

## How Bundle Generation Works

### Step 1: Configuration Validation

```bash
# Validate the configuration file
tpmtb config validate
```

The CLI checks:
- ✅ YAML syntax is correct
- ✅ Vendor IDs exist in TCG registry
- ✅ All URLs use HTTPS
- ✅ Fingerprints are properly formatted

> [!IMPORTANT]
> Only valid configurations can generate bundles. This prevents accidental inclusion of malformed data.

### Step 2: Certificate Download & Verification

```bash
# Generate bundle with parallel downloads
tpmtb generate --workers 10 --output tpm-ca-certificates.pem
```

For each certificate:
1. **Download** from the vendor URL (HTTPS only)
2. **Verify** fingerprint matches the configuration
3. **Extract** certificate metadata (issuer, subject, validity, etc.)
4. **Format** with human-readable comments

### Step 3: Bundle Assembly

The tool assembles everything into a single PEM file:

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

## Why This Process Exists

**The Problem:** TPM root certificates are scattered across vendor websites, PDFs, and various channels. There's no central registry.

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
- 🌐 **Check** vendor URLs are still accessible
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
