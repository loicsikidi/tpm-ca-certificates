# Microsoft (MSFT)

## Certificate Inventory

| Certificate Name | Type | Source Document | Does the source reference a fingerprint? |
|------------------|------|-----------------|:-----------------------------------------:|
| Microsoft TPM Root Certificate Authority 2014 | Root | Microsoft PKI Operations | No |

## Discovery Process

### Microsoft TPM Root Certificate Authority 2014

**Discovery Method**:
1. Retrieved the certificate bundle maintained by Microsoft (i.e. [available here](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates))
2. Selected an intermediate certificate issued by Microsoft from the bundle
3. Extracted the Authority Information Access (AIA) extension from the intermediate certificate
4. The AIA extension contained a URL pointing to the root certificate: `https://www.microsoft.com/pkiops/certs/Microsoft%20TPM%20Root%20Certificate%202014.crt`

Since the domain **www.microsoft.com** is owned by Microsoft Corporation, we can reasonably assume this certificate is legitimate.
