# Infineon Technologies (IFX)

## Overview

In early 2026, Infineon published a comprehensive and official list of its root and intermediate certificates for OPTIGA™ TPMs on their website.

**Official Page**: [OPTIGA™ TPM and Trust Certificates](https://www.infineon.com/design-resources/platforms/optiga-software-tools/optiga-tpm-and-trust-certificates)

This publication renders obsolete the auto discovery process that was previously necessary (see [README.2026-04-09.md](README.2026-04-09.md) for the complete history of this "treasure hunt").

## Current Root Certificates

According to Infineon's official documentation, the following root certificates are currently in service:

| Certificate Name | Type | URL |
|------------------|------|-----|
| Infineon OPTIGA(TM) ECC Root CA | Root | https://pki.infineon.com/OptigaEccRootCA/OptigaEccRootCA.crt |
| Infineon OPTIGA(TM) ECC Root CA 2 | Root | https://pki.infineon.com/OptigaEccRootCA2/OptigaEccRootCA2.crt |
| Infineon OPTIGA(TM) RSA Root CA | Root | https://pki.infineon.com/OptigaRsaRootCA/OptigaRsaRootCA.crt |
| Infineon OPTIGA(TM) RSA Root CA 2 | Root | https://pki.infineon.com/OptigaRsaRootCA2/OptigaRsaRootCA2.crt |

## Certificates by Product Family

Infineon's official page provides detailed information about the certificates used by each TPM product family. Reference screenshots are available for each family:

- **SLB 9665 (FW 5.xx)**: [SLB_9665_FW5.xx.png](SLB_9665_FW5.xx.png)
- **SLB 9670 (FW 7.xx)**: [SLB_9670_FW7.xx.png](SLB_9670_FW7.xx.png)
- **SLB 9672 (FW 15.xx)**: [SLB_9672_FW15.xx.png](SLB_9672_FW15.xx.png)
- **SLB 9672 (FW 16.xx)**: [SLB_9672_FW16.xx.png](SLB_9672_FW16.xx.png)
- **SLB 9673 (FW 26.xx)**: [SLB_9673_FW26.xx.png](SLB_9673_FW26.xx.png)
- **SLI 9670 (FW 13.xx)**: [SLI_9670_FW13.xx.png](SLI_9670_FW13.xx.png)
- **SLM 9670 (FW 13.xx)**: [SLM_9670_FW13.xx.png](SLM_9670_FW13.xx.png)

## Archived Certificates

Prior to the publication of the official list, several root and intermediate certificates were automatically discovered through exploration of Infineon's PKI infrastructure. These certificates have been removed from the active configuration (`.tpm-roots.yaml` and `.tpm-intermediates.yaml`) but are preserved in the [.archived/](../../.archived/) directory for historical reference.

Notably:
- **Infineon OPTIGA(TM) ECC Root CA 3**
- **Infineon OPTIGA(TM) RSA Root CA 3**
- Various auto-discovered intermediate certificates

These certificates may be reintroduced later if users tell us they are in used or if Infineon updates its official list.

## Historical Context

To understand the background and discovery process that preceded the publication of the official list, see [README.2026-04-09.md](README.2026-04-09.md).

> [!NOTE]
> This documentation reflects the state as of April 9, 2026. Infineon's official page should be consulted for the most up-to-date information.
