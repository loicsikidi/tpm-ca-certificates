# AMD

## Overview

AMD provides TPM certificates through their firmware TPM (fTPM) and Pluton implementations.

## Certificate Inventory

| Certificate Name | Type | Source | Does the source reference a fingerprint? |
|------------------|------|--------|:----------------------------------------:|
| AMDTPM ECC | Root | AIA extraction from intermediate certificates from Microsoft TPM bundle | No |
| AMDTPM RSA | Root | AIA extraction from intermediate certificates from Microsoft TPM bundle | No |
| AMD Pluton Global Factory ICA | Root | AIA extraction from intermediate certificates from Microsoft TPM bundle | No |
| AMD Pluton Per-Product Factory FIPS EK ICA (various DFID) | Intermediate | Deduced from Microsoft TPM bundle + AIA extraction | No |
| AMD Pluton Per-Product Factory NON-FIPS EK ICA (various DFID) | Intermediate | Deduced from Microsoft TPM bundle + AIA extraction | No |

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

**Verification**:
You can verify the AIA extraction process yourself using the included intermediate certificate:
```bash
openssl x509 -in src/AMD/AMD-fTPM-RSA-ICA-PHXFamily.crt -noout -text | grep -A2 "Authority Information Access"
```
Expected output should contain: `CA Issuers - URI:http://ftpm.amd.com/pki/aia/264D39A23CEB5D5B49D610044EEBD121`

### AMDTPM ECC

**Discovery Method**:
1. Retrieved the certificate bundle maintained by Microsoft
2. Selected an intermediate certificate issued by AMD from the bundle
3. Extracted the Authority Information Access (AIA) extension from the intermediate certificate
4. The AIA extension contained a URL pointing to the root certificate: `http://ftpm.amd.com/pki/aia/23452201D41C5AB064032BD23F158FEF`
5. Downloaded the certificate from the AIA URL

Since the domain **ftpm.amd.com** is owned by Advanced Micro Devices, Inc., we can reasonably assume this certificate is legitimate.

**Verification**:
You can verify the AIA extraction process yourself using the included intermediate certificate:
```bash
openssl x509 -in src/AMD/AMD-fTPM-ECC-ICA-PHXFamily.crt -noout -text | grep -A2 "Authority Information Access"
```
Expected output should contain: `CA Issuers - URI:http://ftpm.amd.com/pki/aia/23452201D41C5AB064032BD23F158FEF`

### AMD Pluton Global Factory ICA

**Discovery Method**:
1. Retrieved the certificate bundle maintained by Microsoft
2. Selected an intermediate certificate issued by AMD from the bundle
3. Extracted the Authority Information Access (AIA) extension from the intermediate certificate
4. The AIA extension contained a URL pointing to the root certificate: `https://ftpm.amd.com/hsp/ica/AMD-Pluton-Global-Factory-ICA.crt`
5. Downloaded the certificate from the AIA URL

Since the domain **ftpm.amd.com** is owned by Advanced Micro Devices, Inc., we can reasonably assume this certificate is legitimate.

**Verification**:
You can verify the AIA extraction process yourself using the included intermediate certificate:
```bash
openssl x509 -in src/AMD/AMD-Pluton-Per-Product-Factory-FIPS-EKICA-DFID00B20F00.crt -noout -text | grep -A2 "Authority Information Access"
```
Expected output should contain: `CA Issuers - URI:https://ftpm.amd.com/hsp/ica/AMD-Pluton-Global-Factory-ICA.crt`

### AMD Pluton Per-Product Factory Intermediate Certificates

**Discovery Method**:
1. Retrieved the certificate bundle maintained by Microsoft ([available here](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates))
2. Analyzed the certificate bundle to identify AMD Pluton Per-Product Factory intermediate certificates
3. Examined the certificate `02849DB0FD9F4CC4EF6175E75700B20F40.crt` from the bundle (referenced in [issue #84](https://github.com/loicsikidi/tpm-ca-certificates/issues/84))
4. Extracted the Authority Information Access (AIA) extension from this certificate
5. The AIA extension revealed a URL pattern: `https://ftpm.amd.com/hsp/ica/{DFID}-{mode}.crt`
   - Where `{DFID}` is the Device Family ID (e.g., `00B20F00`, `00B20F40`, `00B60F00`, `00B60F80`, `00B70F00`)
   - And `{mode}` is either `fips`, `non-fips` or `device`
6. Deduced the URLs for all intermediate certificates by:
   - Identifying all Device Family IDs present in the Microsoft TPM bundle
   - Constructing URLs for both FIPS and NON-FIPS variants using the discovered pattern

Since the domain **ftpm.amd.com** is owned by Advanced Micro Devices, Inc., we can reasonably assume these certificates are legitimate.

**Verification**:
You can verify the AIA extraction process yourself using the included intermediate certificate:

```bash
openssl x509 -in src/AMD/02849DB0FD9F4CC4EF6175E75700B20F40.crt -noout -text | grep -A2 "Authority Information Access"
```

Expected output should contain: `CA Issuers - URI:https://ftpm.amd.com/hsp/ica/00B20F40-non-fips.crt`
