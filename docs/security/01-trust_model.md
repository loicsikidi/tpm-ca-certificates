# Trust Model

This document describes the trust model and security principles behind the TPM Trust Bundle project. It explains the mechanisms that enable users to trust the content produced by this bundle.

> [!NOTE]
> This file focuses on certificate sourcing trust. For a comprehensive overview of the threat model and mitigations, please refer to [Threat Model & Supply Chain Attack Mitigations](doc/02-threat_model.md).
 from certificate sourcing to release verification.

**Open Source Transparency:** This project is open source, making all information public and allowing anyone to track the history of changes through git. This transparency is a fundamental building block of the trust model — every decision, every certificate addition, and every modification is visible and auditable.

## Key Principles

### 1. Auditability Through Source URLs

Every root CA certificate in this bundle MUST be traceable to its original source via a URL. This is a critical improvement over other projects (e.g., [tpm-key-attestation](https://github.com/cedarcode/tpm-key_attestation/commit/42c78b57726e1abb0167110932a313a51250a7b0)[^1]) where only raw certificate data is visible without provenance.

> [!NOTE]
> 

> [!NOTE]
> **Why this matters:** Anyone can audit where a certificate comes from and verify its legitimacy by following the source URL back to the vendor's official communication.

### 2. Security Countermeasures for URL-Based Distribution

While using URLs introduces potential attack vectors, we implement several countermeasures:

- **HTTPS-only:** All certificate URLs must use HTTPS to ensure transport security
- **Domain ownership validation:** The domain must belong to the TPM vendor
- **Public proof requirement:** The person proposing a certificate URL must provide a publicly accessible resource (PDF, web page, etc.) proving official vendor communication
- **Hash-based integrity:** The configuration file contains hashes of all certificates to verify integrity after download

> [!TIP]
> - **Fingerprint verification:** The CLI is able to compare certificate fingerprints when vendors publish them (e.g., Nuvoton provides SHA-1 fingerprints) this is handy to further ensure the authenticity of the downloaded certificate.
>
> ```bash
> # check fingerprint before adding the certificate to the configuration file
> tpmtb config certificates add --fingerprint "sha1:7C:7B:3C:8A:46:5E:67:D2:8F:4D:B0:F3:5C:E1:20:C4:BB:4A:AC:CC" --url "https://www.nuvoton.com/security/NTC-TPM-EK-Cert/NPCTxxxECC521RootCA.cer"
> ```
### 3. Human Review Process

Given that TPM root CA information is scattered across vendor websites, PDFs, and various communication channels, human validation is essential.

**Current process:** At least one reviewer must validate that a certificate addition is legitimate by:
- Verifying the source URL leads to official vendor communication
- Confirming the certificate hash matches vendor-published information (when available)
- Checking that supporting evidence is archived in the `src/` directory

**Future improvement:** Implement a two-approver requirement for increased robustness.

### 4. Vendor Validation

The list of accepted TPM vendors is based on the official TCG TPM Vendor ID Registry:
https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf

Only vendors listed in this TCG registry are accepted in our configuration.

### 5. Evidence Archive

The `src/` directory serves as a centralized archive of evidence used to locate certificate URLs. This includes:
- Vendor PDFs
- Screenshots of official web pages
- Email communications
- Technical documentation

This archive enables:
- Future audits of why a certificate was included
- Verification that the source was legitimate at the time of addition
- Historical tracking of vendor certificate changes

### 6. Automated Monitoring

A daily scheduled job regenerates the configuration and performs several checks:

#### Daily Verification
- **Generation validation:** Ensure the configuration can still be generated successfully
- **Hash verification:** Confirm that certificate hashes remain valid (detect if a vendor site was compromised)
- **URL availability:** Verify source URLs are still accessible

#### Certificate Lifecycle Management
- **Expiration alerts:** Flag certificates approaching expiration
- **Automatic removal:** Expired certificates are removed from the bundle

This continuous monitoring ensures:
- Early detection of compromised vendor infrastructure
- Proactive management of certificate lifecycle
- Ongoing validation of the trust bundle's integrity

## The `tpmtb` CLI

To enforce these requirements and reduce human error, we created the `tpmtb` CLI tool that automates several critical tasks:

- **Embedded vendor registry:** The CLI includes the list of authorized TPM vendor IDs from the TCG registry, eliminating manual lookups
- **Configuration validation:** Validates that the configuration file meets all requirements (HTTPS URLs, valid vendor IDs, proper hash format, etc.)
- **Certificate verification:** Downloads certificates and verifies their hashes match the configuration
- **Fingerprint comparison:** When vendors publish certificate fingerprints, the CLI can compare them against downloaded certificates
- **Bundle generation:** Automates the creation of the trust bundle from the validated configuration

The CLI ensures consistency and reduces the risk of configuration errors that could compromise the trust model.


[^1]: I don't wish to incriminate them in any way, as this is not a prerogative of their project. Shoutout to Cedarcode for their great contribution on [TPM key attestation](https://github.com/cedarcode/tpm-key_attestation)!
