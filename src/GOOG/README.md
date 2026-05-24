# Google (GOOG)

## Certificate Inventory

| Certificate Name | Type | Source | Does the source reference a fingerprint? |
|------------------|------|--------|:----------------------------------------:|
| EK/AK CA Root | Root | Code reference in go-tpm-tools repository | No |
| EK/AK CA Intermediate | Intermediate | Manual verification via Confidential VM + code analysis | No |

## Discovery Process

### EK/AK CA Root

**Discovery Method**:
1. Found reference in Google's official go-tpm-tools repository
2. The URL is hardcoded in the server verification code: [verify.go:L55](https://github.com/google/go-tpm-tools/blob/cf6db90d8918831c7658679a3b6aea14b6e4af2f/server/verify.go#L55)
3. The root certificate URL is: `https://privateca-content-62d71773-0000-21da-852e-f4f5e80d7778.storage.googleapis.com/032bf9d39db4fa06aade/ca.crt`

**Verification**:
The certificate is referenced in the official Google go-tpm-tools codebase used for TPM attestation verification.

### EK/AK CA Intermediate

**Discovery Method**:
1. Initial reference found in third-party repository: [gcp-vtpm-ek-ak](https://github.com/salrashid123/gcp-vtpm-ek-ak)
2. Manual verification performed by creating a Google Cloud Confidential VM
3. Extracted the EK certificate from the VM's TPM
4. Confirmed that the intermediate CA URL matches the one found in the third-party repository
5. The intermediate certificate URL is: `https://privateca-content-65d64fcd-0000-2d96-bed1-3c286d46e2de.storage.googleapis.com/910faf291dea3504d2bb/ca.crt`

**Verification**:
The certificate was confirmed by deploying a Google Confidential VM and extracting the certificate chain from the TPM's EK certificate.
