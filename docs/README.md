# Documentation Index

Welcome to the TPM CA Certificates documentation! This guide will help you navigate through the available resources.

## 📚 Quick Start Guides

**New to the project?** Start here:

| Guide | Description | Audience |
|-------|-------------|----------|
| [Installation](guides/getting-started/01-installation.md) | Install the `tpmtb` CLI tool | Everyone |
| [Retrieve and Verify Bundle](guides/getting-started/02-retrieve-and-verify-bundle.md) | Download and verify TPM trust bundles | Users, System Admins |
| [Bundle Generation](guides/getting-started/03-generate-bundle.md) | Understand how bundles are created | Contributors, Security Engineers |
| [Using the SDK in Go](guides/getting-started/04-using-sdk-in-go.md) | Integrate bundle retrieval in Go applications | Developers |
| [Contributing](guides/getting-started/05-contributing.md) | Add new certificates to the project | Contributors |

## 🔐 Core Concepts

**Understand the trust model:**

| Document | Description |
|----------|-------------|
| [Security Model](concepts/01-security_model.md) | Trust principles, evidence requirements, and verification mechanisms |
| [Threat Model](concepts/02-threat_model.md) | Risk assessment, mitigations, and known limitations |

## 📋 Technical Specifications

**Detailed reference documentation:**

| Specification | Description |
|--------------|-------------|
| [Configuration File](specifications/01-configuration-file.md) | `.tpm-roots.yaml` format, validation rules, and CLI commands |
| [Release Management](specifications/02-release-management.md) | Release workflow, tagging, and artifact generation |
| [Bundle Generation Backward Compatibility](specifications/03-bundle-generation-backward-compatibility.md) | Version compatibility and migration strategies |
| [TPM Trust Bundle Format](specifications/04-tpm-trust-bundle-format.md) | Bundle structure, metadata, and PEM format |
| [Bundle Verification](specifications/05-bundle-verification.md) | Verification process, Sigstore integration, and SLSA attestation |
| [API Versioning](specifications/06-api-versioning.md) | Public API versioning strategy, channels, and stability guarantees |
| [Local Cache](specifications/07-local-cache.md) | Local cache system for offline verification and performance optimization |
| [Full Offline Mode](specifications/08-full-offline-mode.md) | Complete offline verification with intermediate certificates support |

## 🎯 Common Use Cases

### I want to use TPM trust bundles in my application

#### Integrating in Go applications

1. Follow [Using the SDK in Go](guides/getting-started/04-using-sdk-in-go.md)

#### Embedding the bundle in your application

1. Start with [Installation](guides/getting-started/01-installation.md)
2. Follow [Retrieve and Verify Bundle](guides/getting-started/02-retrieve-and-verify-bundle.md)

> [!TIP]
> For other programming languages, manually download and verify the bundle using the `tpmtb` CLI, then embed the resulting PEM file in your application.

### I want enrich the bundle with a new certificate

1. Read the [Security Model](concepts/01-security_model.md) to understand requirements
2. Follow the [Contributing Guide](guides/getting-started/05-contributing.md)
3. Reference the [Configuration File Specification](specifications/01-configuration-file.md)

### I want to understand the security guarantees

1. Read the [Security Model](concepts/01-security_model.md)
2. Review the [Threat Model](concepts/02-threat_model.md)
3. Check [Bundle Verification](specifications/05-bundle-verification.md) for technical details

### I want to understand how releases work

1. Check [Release Management](specifications/02-release-management.md)
2. Review [Bundle Verification](specifications/05-bundle-verification.md)
3. Understand [Backward Compatibility](specifications/03-bundle-generation-backward-compatibility.md)

## 🗂️ Documentation Structure

```
docs/
├── concepts/              # High-level architecture and trust model
│   ├── 01-security_model.md
│   └── 02-threat_model.md
├── guides/               # Step-by-step tutorials
│   └── getting-started/
│       ├── 01-installation.md
│       ├── 02-retrieve-and-verify-bundle.md
│       ├── 03-generate-bundle.md
│       ├── 04-using-sdk-in-go.md
│       └── 05-contributing.md
└── specifications/       # Technical reference documentation
    ├── 01-configuration-file.md
    ├── 02-release-management.md
    ├── 03-bundle-generation-backward-compatibility.md
    ├── 04-tpm-trust-bundle-format.md
    ├── 05-bundle-verification.md
    ├── 06-api-versioning.md
    ├── 07-local-cache.md
    └── 08-full-offline-mode.md
```

## 🆘 Getting Help

- 💬 [GitHub Discussions](https://github.com/loicsikidi/tpm-ca-certificates/discussions) - Ask questions and share ideas
- 🐛 [GitHub Issues](https://github.com/loicsikidi/tpm-ca-certificates/issues) - Report bugs or request features

## 🔗 External Resources

- [Sigstore Documentation](https://docs.sigstore.dev/) - Learn about keyless signing
- [SLSA Framework](https://slsa.dev/) - Supply chain security framework
- [TCG TPM Vendor ID Registry](https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-Vendor-ID-Registry-Family-1.2-and-2.0-Version-1.07-Revision-0.02_pub.pdf) - Official vendor ID list
- [Geomys Standard of Care](https://words.filippo.io/standard-of-care/) - Supply chain security best practices

## 📝 Document Versions

All specifications include version history and are maintained following semantic versioning principles. The configuration file format is currently in `alpha` version and will be promoted to `v1` once stabilized.
