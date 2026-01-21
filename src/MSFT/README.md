# Microsoft (MSFT)

## Certificate Inventory

| Certificate Name | Type | Source Document | Does the source reference a fingerprint? |
|------------------|------|-----------------|:-----------------------------------------:|
| Microsoft Pluton Policy CA A | Intermediate | AIA extraction from intermediate certificates from Microsoft TPM bundle | No |
| Microsoft Pluton Root CA 2021 | Root | AIA extraction from intermediate certificates from Microsoft TPM bundle | No |
| Microsoft TPM Root Certificate Authority 2014 | Root | AIA extraction from intermediate certificates from Microsoft TPM bundle | No |

## Discovery Process

### Microsoft Pluton Policy CA A

**Discovery Method**:
1. Retrieved the certificate bundle maintained by Microsoft (i.e. [available here](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates))
2. Selected an intermediate certificate issued by Microsoft from the bundle
3. Extracted the Authority Information Access (AIA) extension from the intermediate certificate
4. The AIA extension contained a URL pointing to the intermediate certificate: `https://www.microsoft.com/pkiops/certs/Microsoft%20Pluton%20Policy%20CA%20A.crt`

Since the domain **www.microsoft.com** is owned by Microsoft Corporation, we can reasonably assume this certificate is legitimate.

**Verification**:
You can verify the AIA extraction process yourself using the included intermediate certificate:
```bash
openssl x509 -in src/MSFT/Pluton-Factory-DEVICE-EK-ICA-DFID0001.cer -noout -text | grep -A2 "Authority Information Access"
```
Expected output should contain: `CA Issuers - URI:http://www.microsoft.com/pkiops/certs/Microsoft%20Pluton%20Policy%20CA%20A.crt`

### Microsoft Pluton Root CA 2021

**Discovery Method**:
1. Extracted the Authority Information Access (AIA) extension from *Microsoft Pluton Policy CA* certificate
2. The AIA extension contained a URL pointing to the root certificate: `https://www.microsoft.com/pkiops/certs/Microsoft%20Pluton%20Root%20CA%202021.crt`

Since the domain **www.microsoft.com** is owned by Microsoft Corporation, we can reasonably assume this certificate is legitimate.

**Verification**:
You can verify the AIA extraction process yourself using the included intermediate certificate:
```bash
openssl x509 -in src/MSFT/Microsoft-Pluton-Policy-CA-A.cer -noout -text | grep -A2 "Authority Information Access"
```
Expected output should contain: `CA Issuers - URI:http://www.microsoft.com/pkiops/certs/Microsoft%20Pluton%20Root%20CA%202021.crt`

### Microsoft TPM Root Certificate Authority 2014

**Discovery Method**:
1. Retrieved the certificate bundle maintained by Microsoft (i.e. [available here](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates))
2. Selected an intermediate certificate issued by Microsoft from the bundle
3. Extracted the Authority Information Access (AIA) extension from the intermediate certificate
4. The AIA extension contained a URL pointing to the root certificate: `https://www.microsoft.com/pkiops/certs/Microsoft%20TPM%20Root%20Certificate%202014.crt`

Since the domain **www.microsoft.com** is owned by Microsoft Corporation, we can reasonably assume this certificate is legitimate.

**Verification**:
You can verify the AIA extraction process yourself using the included intermediate certificate:
```bash
openssl x509 -in src/MSFT/WUS-IFX-KEYID-EFFEEC5E01610082C0E311CBD07A3204408B32B8.cer -noout -text | grep -A2 "Authority Information Access"
```
Expected output should contain: `CA Issuers - URI:http://www.microsoft.com/pkiops/certs/Microsoft%20TPM%20Root%20Certificate%20Authority%202014.crt`
