# Contributing TPM Root Certificates

## Who This Guide Is For

This guide is for contributors who want to add new TPM root certificates to the bundle.

**Your goal:** Successfully contribute a new certificate with proper evidence and documentation.

**What you'll learn:**
- How to add certificates to new or existing vendors
- The evidence requirements for contributions
- The pull request workflow

---

## Before You Start 📋

Make sure you have:

- ✅ `tpmtb` installed ([Installation Guide](./01-installation.md))
- ✅ Found the vendor's official certificate documentation
- ✅ Located the certificate URL(s) and fingerprints (if available)
- ✅ Downloaded evidence files (PDFs, screenshots)

> [!IMPORTANT]
> **Evidence is mandatory!** Every URL must be backed by proof (PDF, screenshot, etc.) showing how you found it on the vendor's official channels.

## Two Contribution Workflows

### Workflow 1: Adding a Certificate to an Existing Vendor 📝

**Use this when:** The vendor already exists in `.tpm-roots.yaml`

**Steps:**

1. **Add the certificate(s)** using the CLI:

```bash
# Single certificate
tpmtb config certificates add --vendor-id VENDOR_ID \
  --url "https://vendor.com/path/to/cert.cer" \
  --fingerprint "sha256:AA:BB:CC:DD:..."

# Multiple certificates at once
tpmtb config certificates add --vendor-id VENDOR_ID \
  --url "https://vendor.com/cert1.cer,https://vendor.com/cert2.cer"  
```

> [!TIP]
> The `--fingerprint` flag is optional but recommended! It provides an extra layer of verification when vendors publish fingerprints in their documentation.

2. **Update the vendor's README** in `src/VENDOR_ID/README.md`:

Add the new certificate(s) to the certificate inventory table:

```markdown
| Certificate Name | Source Document | Does the source references a fingerprint? |
|------------------|-----------------|:-----------------------------------------:|
| Existing Cert 1 | [doc.pdf](doc.pdf) | No |
| **New Cert Name** | **[doc.pdf](doc.pdf)** | **No** |
```

3. **Add evidence files** to `src/VENDOR_ID/`:

```bash
# Example structure
src/NTC/
├── README.md                      # Updated with new cert
├── vendor_doc_v2.3.pdf           # New version with the cert
└── vendor_website_2025.png       # Screenshot showing the URL
```

4. **Format and validate:**

```bash
# Format the configuration
tpmtb config format

# Validate everything is correct
tpmtb config validate

# Generate bundle to test
tpmtb generate
```

5. **Submit a pull request** with:
   - Modified `.tpm-roots.yaml`
   - Updated `src/VENDOR_ID/README.md`
   - New evidence files
   - Clear commit message: `rot(VENDOR_ID): add <Certificate Name>`

> [!NOTE]
> `rot` stands for "root of trust" and is the conventional prefix for certificate addition commits.

---

### Workflow 2: Adding a New Vendor + Certificates 🆕

**Use this when:** The vendor doesn't exist yet in `.tpm-roots.yaml`

**Steps:**

1. **Verify the vendor ID** is in the TCG registry:

Check the [TCG TPM Vendor ID Registry](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf) for the official vendor ID.

> [!NOTE]
> The CLI will automatically validate vendor IDs against the TCG registry.

2. **Create the vendor directory structure:**

```bash
mkdir -p src/VENDOR_ID
```

3. **Add the vendor with certificates:**

```bash
# add the vendor to the config
tpmtb onfig vendors add VENDOR_ID VENDOR_NAME
# add the certificates
tpmtb config certificates add --vendor-id VENDOR_ID \
  --url "https://vendor.com/cert1.cer,https://vendor.com/cert2.cer"
```

4. **Create the vendor README** at `src/VENDOR_ID/README.md`:

Use this template:

```markdown
# Vendor Full Name (VENDOR_ID) TPM Root Certificates

## Certificate Inventory

| Certificate Name | Source Document | Does the source references a fingerprint? |
|------------------|-----------------|:-----------------------------------------:|
| Certificate 1 | [vendor_doc.pdf](vendor_doc.pdf) | No |
| Certificate 2 | [vendor_doc.pdf](vendor_doc.pdf) | No |

## References

Brief description of what the certificates are for.

### Source Information

The certificate details were retrieved from the official vendor documentation:
- **Web Page**: https://vendor.com/tpm/certificates
- **Documentation PDF**: https://vendor.com/docs/tpm_guide.pdf
- **Screenshot Reference**: [vendor_website.png](vendor_website.png)

Optional: Any additional context about the vendor's certificate infrastructure.
```

5. **Add evidence files** to `src/VENDOR_ID/`:

```bash
src/VENDOR_ID/
├── README.md                    # Vendor documentation
├── vendor_doc.pdf              # Official PDF with cert info
└── vendor_website.png          # Screenshot of the web page
```

6. **Update the main index** at `src/README.md`:

Add the new vendor to the Vendor Index table:

```markdown
| Vendor ID | Vendor Name | Documentation | Accessibility Score |
|-----------|-------------|---------------|:-------------------:|
| [VENDOR_ID](VENDOR_ID/) | Vendor Full Name | [README](VENDOR_ID/README.md) | A/B/C |
```

And add a section in Additional Resources:

```markdown
### VENDOR_ID (Vendor Full Name)
* https://vendor.com/tpm/certificates
```

7. **Format, validate, and test:**

```bash
tpmtb config format
tpmtb config validate
tpmtb generate
```

8. **Submit a pull request** with:
   - Modified `.tpm-roots.yaml`
   - New `src/VENDOR_ID/` directory with README and evidence
   - Updated `src/README.md`
   - Clear commit message: `rot(VENDOR_ID): add vendor with N certificates`

---

## Evidence Requirements 🔍

Your contribution **must** include proof of how you discovered the certificate URLs:

### Required Evidence

- 📄 **PDFs:** Official vendor documentation mentioning the certificates
- 🖼️ **Screenshots:** Capture of the vendor's web page showing the URL
- 📝 **README:** Clear explanation of the discovery process

### Good Evidence Examples

✅ **PDF from vendor website** with certificate URLs listed
✅ **Link** leading to the the official vendor TPM webpage giving access to the certificates (eg. pdf, download page, documentation, etc.)
✅ **Screenshot** showing the context of the link above, including the URL in the browser address bar

### Insufficient Evidence

❌ Just saying "I found it on the vendor website"
❌ URLs without any source documentation
❌ Screenshots that don't clearly show the URL
❌ Third-party documentation (not from the vendor)

> [!WARNING]
> Pull requests without proper evidence will be rejected. This is non-negotiable for security reasons.

## What Reviewers Look For 👀

When your PR is reviewed, maintainers check:

- ✅ **Valid vendor ID:** Exists in TCG registry
- ✅ **HTTPS URLs only:** No HTTP allowed
- ✅ **Legitimate source:** URLs point to official vendor infrastructure
- ✅ **Complete evidence:** PDFs/screenshots prove authenticity
- ✅ **Proper documentation:** README explains the discovery process
- ✅ **Fingerprint accuracy:** Matches vendor-published data (when available)
- ✅ **Formatting:** Configuration passes `tpmtb config validate`
- ✅ **Tests pass:** Bundle generation succeeds

## Tips for Success 💡

### Finding Certificate URLs

1. **Start with the vendor's official website** - Look for:
   - TPM support pages
   - Security/Certificate sections
   - Developer documentation
   - Product manuals

2. **Search for technical documentation:**
   - PDFs about TPM implementation
   - Integration guides
   - API documentation

3. **Check official repositories:**
   - GitHub organizations
   - Support portals
   - Developer resources

### Taking Good Screenshots

- 📸 Capture the **full browser window** (including URL bar)
- 📸 Show the **certificate download links** clearly
- 📸 Use **PNG format** for clarity

## Testing Your Changes Locally 🧪

Before submitting your PR:

```bash
# 1. Format the config
tpmtb config format

# 2. Validate everything
tpmtb config validate

# 3. Generate a test bundle
tpmtb generate --workers 10 --output test-bundle.pem

# 4. Verify the bundle contains your certificates
grep "Certificate: Your Certificate Name" test-bundle.pem

# 5. Count total certificates
grep -c "BEGIN CERTIFICATE" test-bundle.pem
```

## After You Submit 🚀

1. **CI checks will run** - Ensure they pass
2. **Reviewer(s) will examine** your evidence and changes
3. **Feedback may be requested** - Be responsive to comments
4. **Once approved** - Changes will be merged
5. **Next release** - Your certificates will be included in the bundle!

## Need Help? 🆘

- 📖 Read the [Configuration File Specification](../../specifications/01-configuration-file.md)
- 🔒 Understand the [Security Model](../../concepts/01-security_model.md)
- 💬 Open a [discussion](https://github.com/loicsikidi/tpm-ca-certificates/discussions) if you have questions
- 🐛 Report issues via [GitHub Issues](https://github.com/loicsikidi/tpm-ca-certificates/issues)

## Next Steps

- 🔍 Browse existing examples in [src/](../../../src/)
- 📚 Read the [Security Model](../../concepts/01-security_model.md) to understand the trust model
- 🎯 Check the [Threat Model](../../concepts/02-threat_model.md) to see what we protect against

---

**Thank you for contributing to a more secure TPM ecosystem!** 🙏
