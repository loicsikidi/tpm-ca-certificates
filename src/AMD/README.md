# AMD

## Overview

AMD provides TPM certificates through their firmware TPM (fTPM) and Pluton implementations.

## Certificate Inventory

| Certificate Name | Type | Source | Does the source reference a fingerprint? |
|------------------|------|--------|:----------------------------------------:|
| AMDTPM ECC | Root | AIA extraction from intermediate certificates from Microsoft TPM bundle | No |
| AMDTPM RSA | Root | AIA extraction from intermediate certificates from Microsoft TPM bundle | No |
| AMD Pluton Global Factory ICA | Root | AIA extraction from intermediate certificates from Microsoft TPM bundle | No |

> [!IMPORTANT]
> `AMD Pluton Global Factory ICA` is currently classified as root certificate because we did not find a public URL (owned by AMD) giving its issuer (i.e. **CN=AMD Root CA R4**).

## Discovery Process

### AMDTPM RSA

**Discovery Method**:
1. Retrieved the certificate bundle maintained by Microsoft ([available here](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates))
2. Selected an intermediate certificate issued by AMD from the bundle
3. Extracted the Authority Information Access (AIA) extension from the intermediate certificate
4. The AIA extension contained a URL pointing to the root certificate: `http://ftpm.amd.com/pki/aia/264D39A23CEB5D5B49D610044EEBD121`
5. Downloaded the certificate from the AIA URL

Since the domain **ftpm.amd.com** is owned by Advanced Micro Devices, Inc., we can reasonably assume this certificate is legitimate.

### AMDTPM ECC

**Discovery Method**:
1. Retrieved the certificate bundle maintained by Microsoft
2. Selected an intermediate certificate issued by AMD from the bundle
3. Extracted the Authority Information Access (AIA) extension from the intermediate certificate
4. The AIA extension contained a URL pointing to the root certificate: `http://ftpm.amd.com/pki/aia/23452201D41C5AB064032BD23F158FEF`
5. Downloaded the certificate from the AIA URL

Since the domain **ftpm.amd.com** is owned by Advanced Micro Devices, Inc., we can reasonably assume this certificate is legitimate.

### AMDTPM ECC

**Discovery Method**:
1. Retrieved the certificate bundle maintained by Microsoft
2. Selected an intermediate certificate issued by AMD from the bundle
3. Extracted the Authority Information Access (AIA) extension from the intermediate certificate
4. The AIA extension contained a URL pointing to the root certificate: `http://ftpm.amd.com/pki/aia/23452201D41C5AB064032BD23F158FEF`
5. Downloaded the certificate from the AIA URL

Since the domain **ftpm.amd.com** is owned by Advanced Micro Devices, Inc., we can reasonably assume this certificate is legitimate.
