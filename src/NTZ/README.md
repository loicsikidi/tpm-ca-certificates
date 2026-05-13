# Nationz Technologies Inc (NTZ)

## Certificate Inventory

| Certificate Name | Type | Source Document | Does the source reference a fingerprint? |
|------------------|------|-----------------|:-----------------------------------------:|
| Nationz TPM Manufacturing CA 001 | Intermediate | AIA find on the Web | No |
| Nationz TPM Manufacturing CA 002 | Intermediate | AIA deduction from pattern | No |
| Nationz TPM Manufacturing CA 003 | Intermediate | AIA deduction from pattern | No |
| Nationz TPM Root CA | Root | AIA extraction from intermediate certificate | No |

## Discovery Process

### Nationz TPM Manufacturing CA 001

**Discovery Method**:
1. Retrieved the certificate bundle maintained by Microsoft (i.e. [available here](https://learn.microsoft.com/en-us/windows-server/security/guarded-fabric-shielded-vm/guarded-fabric-install-trusted-tpm-root-certificates))
2. The bundle contained an intermediate certificate named `EkMfrCA001` issued by Nationz Technologies Inc
3. Performed a web search for the keyword "EkMfrCA001"
4. Found H3C support documentation ([available here](https://wwwsg.h3c.com/en/d_202601/2745273_294551_0.htm)) displaying certificate details including the CRL Distribution Point
5. The certificate's Authority Information Access (AIA) extension contained a URL pointing to: `http://pki.nationz.com.cn/EkMfrCA001/EkMfrCA001.crt`
6. Following the same URL pattern, discovered additional certificates: `EkMfrCA002` and `EkMfrCA003`

Since the domain **pki.nationz.com.cn** is owned by Nationz Technologies Inc, we can reasonably assume this certificate is legitimate.

**Verification**:
You can verify the certificate details yourself using the included intermediate certificate:
```bash
openssl x509 -in src/NTZ/EkMfrCA001.crt -noout -text | grep -A2 "Authority Information Access"
```
Expected output should contain: `CA Issuers - URI:http://pki.nationz.com.cn/EkMfrCA001/EkMfrCA001.crt`

#### Source Information

- **Screenshot Reference**: 
![](h3c_support.png)

### Nationz TPM Root CA

**Discovery Method**:
1. Extracted the Authority Information Access (AIA) extension from *Nationz TPM Manufacturing CA 001* certificate
2. The AIA extension's issuer information pointed to the root certificate: `http://pki.nationz.com.cn/EkRootCA/EkRootCA.crt`

Since the domain **pki.nationz.com.cn** is owned by Nationz Technologies Inc, we can reasonably assume this certificate is legitimate.

**Verification**:
You can verify the issuer information yourself using the included intermediate certificate:
```bash
openssl x509 -in src/NTZ/EkMfrCA001.crt -noout -issuer
```
Expected output: `issuer=C=CN, O=Nationz Technologies Inc, OU=Nationz TPM Device, CN=Nationz TPM Root CA`
