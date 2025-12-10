# Configuration File

## Document History

| Version |    Date    |   Author    |   Description                                 |
|---------|------------|-------------|-----------------------------------------------|
| alpha   | 2025-11-26 | Loïc Sikidi | Initial version                               |
| alpha   | 2025-12-10 | Loïc Sikidi | Add duplicate validation rules                |

The TPM Trust Bundle is generated from a human-readable YAML configuration file named `.tpm-roots.yaml`. This file defines the root certificates for various TPM vendors and must follow strict formatting and validation rules to ensure consistency and integrity.

> [!IMPORTANT]
> The configuration specification is currently in `alpha` version. Once stabilized, it will be promoted to `v1`.

## File Structure

The configuration file must start with the YAML document marker `---` on the first line, followed by the configuration structure:

```yaml
---
version: "alpha"
vendors:
    - name: "Vendor Name"
      id: "VENDOR_ID"
      certificates:
        - name: "Certificate Name"
          url: "https://vendor.com/path/to/certificate.cer"
          validation:
            fingerprint:
                sha1: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD"
                sha256: "AA:BB:CC:..."  # Optional
                sha384: "AA:BB:CC:..."  # Optional
                sha512: "AA:BB:CC:..."  # Optional
```

### Fields

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `version` | string | Yes | Configuration file format version. Before v1 (stable API), uses `alpha`, `beta`, `gamma`. Starting from v1, uses incrementing integers: `1`, `2`, `3`, etc. | `"alpha"` |
| `vendors` | array | Yes | List of TPM vendors | - |
| `vendors[].name` | string | Yes | Full vendor name | `"Nuvoton Technology"` |
| `vendors[].id` | string | Yes | Short vendor identifier (must be from [TCG TPM Vendor ID Registry](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf)) | `"NTC"` |
| `vendors[].certificates` | array | No | List of root certificates for this vendor (can be empty) | - |
| `vendors[].certificates[].name` | string | Yes | Human-readable certificate name | `"Nuvoton TPM Root CA 1110"` |
| `vendors[].certificates[].url` | string | Yes | Public URL where the certificate can be downloaded | `"https://www.nuvoton.com/..."` |
| `vendors[].certificates[].validation` | object | Yes | Validation information for the certificate | - |
| `vendors[].certificates[].validation.fingerprint` | object | Yes | Hash fingerprints of the certificate | - |
| `vendors[].certificates[].validation.fingerprint.sha1` | string | No | SHA-1 fingerprint | `"65:5E:44:5E:96:54:..."` |
| `vendors[].certificates[].validation.fingerprint.sha256` | string | No | SHA-256 fingerprint | `"FD:1E:7B:68:AC:CD:..."` |
| `vendors[].certificates[].validation.fingerprint.sha384` | string | No | SHA-384 fingerprint | `"AA:BB:CC:..."` |
| `vendors[].certificates[].validation.fingerprint.sha512` | string | No | SHA-512 fingerprint | `"AA:BB:CC:..."` |

> [!IMPORTANT]
> At least one hash algorithm (sha1, sha256, sha384, or sha512) must be defined for each certificate's fingerprint validation.
>
> Default hash algorithm used for validation is `SHA-256`

## Validation Rules

The configuration file must follow these validation rules:

### 1. YAML Document Marker

The file must start with the YAML document marker `---` on the first line.

```yaml
# ✓ Correct
---
version: "alpha"
vendors: []

# ✗ Incorrect - missing document marker
version: "alpha"
vendors: []

# ✗ Incorrect - comment before document marker
# This is a comment
---
version: "alpha"
```

> [!IMPORTANT]
> The `validate` command will reject files that do not start with `---`. The `format` command will automatically add it if missing.

### 2. Vendor ID Registry

All vendor IDs must be valid according to the **TCG TPM Vendor ID Registry**.

The list of valid vendor IDs is maintained in the CLI tool and sourced from:
**[TCG TPM Vendor ID Registry Family 1.2 and 2.0, Version 1.07, Revision 0.02](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf)**

```yaml
# ✓ Correct - NTC is in the TCG registry
vendors:
    - id: "NTC"

# ✗ Incorrect - UNKNOWN is not in the TCG registry
vendors:
    - id: "UNKNOWN"
```

> [!IMPORTANT]
> The `validate` and `certificates add` commands will reject any vendor ID not present in the TCG registry.

### 3. No Duplicate Vendor IDs

Each vendor ID must appear only once in the configuration file.

```yaml
# ✓ Correct - each vendor ID appears once
vendors:
    - id: "INTC"
      name: "Intel"
      certificates: []
    - id: "NTC"
      name: "Nuvoton Technology"
      certificates: []

# ✗ Incorrect - "NTC" appears twice
vendors:
    - id: "NTC"
      name: "Nuvoton Technology"
      certificates: []
    - id: "NTC"
      name: "Nuvoton Duplicate"
      certificates: []
```

> [!IMPORTANT]
> The `validate` command will reject files with duplicate vendor IDs.

### 4. No Duplicate Certificates

Within each vendor, certificates must be unique. A certificate is considered a duplicate if any of the following match:

- **Name**: Certificate name must be unique within the vendor
- **URL**: Certificate URL must be unique within the vendor
- **Fingerprint**: Certificate fingerprint must be unique within the vendor

```yaml
# ✓ Correct - all certificates are unique
vendors:
    - id: "NTC"
      name: "Nuvoton Technology"
      certificates:
        - name: "NuvotonTPMRootCA1110"
          url: "https://example.com/cert1.cer"
          validation:
            fingerprint:
              sha256: "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"
        - name: "NuvotonTPMRootCA1111"
          url: "https://example.com/cert2.cer"
          validation:
            fingerprint:
              sha256: "11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF"

# ✗ Incorrect - duplicate name
vendors:
    - id: "NTC"
      certificates:
        - name: "NuvotonTPMRootCA1110"
          url: "https://example.com/cert1.cer"
          validation:
            fingerprint:
              sha256: "AA:BB:..."
        - name: "NuvotonTPMRootCA1110"  # Duplicate name
          url: "https://example.com/cert2.cer"
          validation:
            fingerprint:
              sha256: "11:22:..."

# ✗ Incorrect - duplicate URL
vendors:
    - id: "NTC"
      certificates:
        - name: "Cert A"
          url: "https://example.com/cert.cer"
          validation:
            fingerprint:
              sha256: "AA:BB:..."
        - name: "Cert B"
          url: "https://example.com/cert.cer"  # Duplicate URL
          validation:
            fingerprint:
              sha256: "11:22:..."

# ✗ Incorrect - duplicate fingerprint
vendors:
    - id: "NTC"
      certificates:
        - name: "Cert A"
          url: "https://example.com/cert1.cer"
          validation:
            fingerprint:
              sha256: "AA:BB:CC:DD:..."
        - name: "Cert B"
          url: "https://example.com/cert2.cer"
          validation:
            fingerprint:
              sha256: "AA:BB:CC:DD:..."  # Duplicate fingerprint
```

> [!IMPORTANT]
> The `validate` and `certificates add` commands will reject duplicate certificates within a vendor.

## Formatting Rules

The configuration file must follow these formatting rules, which are automatically applied by the `format` command:

### 1. YAML Document Marker

The `format` command automatically ensures the file starts with `---` on the first line.

### 2. Vendor Sorting

Vendors must be sorted **alphabetically by ID**. For example:

```yaml
vendors:
    - id: "INTEL"    # First
    - id: "NTC"      # Second
    - id: "STM"      # Third
```

### 3. Certificate Sorting

Certificates within each vendor must be sorted **alphabetically by name**:

```yaml
certificates:
    - name: "NPCTxxxECC521RootCA"          # First
    - name: "NuvotonTPMRootCA1110"         # Second
    - name: "NuvotonTPMRootCA1111"         # Third
```

### 4. URL Encoding
P
All certificate URLs must:
- Use the **HTTPS scheme** (HTTP is not allowed)
- Be properly **URL-encoded** (special characters like spaces must be encoded)

```yaml
# ✓ Correct
url: "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton%20TPM%20Root%20CA%201110.cer"

# ✗ Incorrect - HTTP not allowed
url: "http://www.nuvoton.com/security/NTC-TPM-EK-Cert/certificate.cer"

# ✗ Incorrect - not URL-encoded
url: "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/Nuvoton TPM Root CA 1110.cer"
```

### 5. Fingerprint Format

Fingerprints must be:
- **Uppercase** hexadecimal characters
- Separated by **colons** (`:`)
- Grouped in **two-character pairs**

```yaml
# ✓ Correct
sha1: "65:5E:44:5E:96:54:5C:F3:E4:84:82:94:9B:35:A7:CE:B3:46:58:CC"

# ✗ Incorrect formats
sha1: "655e445e96545cf3e48482949b35a7ceb34658cc"        # No colons, lowercase
sha1: "65:5e:44:5e:96:54:5c:f3:e4:84:82:94:9b:35:a7:ce:b3:46:58:cc"  # Lowercase
```

### 6. String Quoting

All string values must be enclosed in **double quotes**:

```yaml
# ✓ Correct
name: "Nuvoton Technology"
id: "NTC"
version: "alpha"

# ✗ Incorrect
name: Nuvoton Technology
id: NTC
version: alpha
```

## CLI Commands

### Format Command

The `format` command automatically applies all formatting rules to the configuration file:

```bash
# Format the default config file
tpmtb config format

# Format a specific config file
tpmtb config format --config custom-roots.yaml
```

### Validate Command

The `validate` command checks that the configuration file follows all formatting rules:

```bash
# Validate the default config file
tpmtb config validate

# Validate a specific config file
tpmtb config validate --config custom-roots.yaml
```

If validation errors are found, the command:
- Returns exit code `1`
- Shows up to **10 validation errors** with line numbers
- Displays errors on stderr

Example output:

```
❌ .tpm-roots.yaml has validation errors:

  Line 3: invalid vendor ID "UNKNOWN": not found in TCG TPM Vendor ID Registry
  Line 4: duplicate vendor ID "NTC" (first defined at vendors[0])
  Line 7: vendors not sorted by ID: expected "INTEL" at position 0, got "NTC"
  Line 10: duplicate certificate "NuvotonTPMRootCA1110" in vendor "NTC"
  Line 15: URL must use HTTPS scheme: got "http"
  Line 18: URL not properly encoded: got "https://example.com/cert with spaces.cer", expected "https://example.com/cert%20with%20spaces.cer"
  Line 21: fingerprint not in uppercase with colons: got "aa:bb:cc:dd"

(showing first 10 errors)
```
