# TPM Root Certificates - Evidences

This directory contains the evidence and documentation proving how the URLs for TPM root certificates were discovered from each manufacturer. Each vendor subdirectory includes references to official documentation, screenshots, and fingerprint validation information.

## Vendor Index

| Vendor ID | Vendor Name | Documentation | Accessibility Score |
|-----------|-------------|:-------------:|:-------------------:|
| INTC | Intel | [README](INTC/) | C |
| IFX | Infineon | [README](IFX/) | B |
| NTC | Nuvoton Technology | [README](NTC/) | A |
| STM | STMicroelectronics | [README](STM/) | A |

### Accessibility Score Legend

The score reflects the availability and quality of resources for finding certificates:
- **A**: Comprehensive documentation available (PDF or centralized document with links to all root and intermediate certificates)
- **B**: Partial documentation available (document centralizing some resources, but incomplete)
- **C**: Scattered information (treasure hunt required, no centralized resource)
