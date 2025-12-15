# Bundle Generation Backward Compatibility

## Document History

| Version |    Date    |   Author    |   Description    |
|---------|------------|-------------|------------------|
| alpha   | 2025-11-30 | Loïc Sikidi | Initial version  |

This specification defines backward compatibility requirements for the `tpmtb generate` command to ensure that any bundle produced by CI/CD is reproducible locally by users or scripts, guaranteeing bundle integrity and trustworthiness.

`tpmtb` must allow users to regenerate bundles from older configuration file formats to verify that the bundle matches the expected output, regardless of when the configuration was created. This specification explains how this guarantee is maintained across different versions of `tpmtb` and the configuration file format.

> [!IMPORTANT]
> The backward compatibility specification is currently in `alpha` version. Once stabilized, it will be promoted to `v1`.

## Configuration File Format Versioning

The configuration file format version is defined by the `version` field in `.tpm-roots.yaml` and `.tpm-intermediates.yaml`:

```yaml
version: "alpha"  # Pre-stable: alpha, beta, gamma
version: "1"      # Stable: incrementing integers (1, 2, 3, ...)
```

### Version Evolution

As defined in the [Configuration File specification](01-configuration-file.md#fields), the version field evolves through two phases:

| Phase | Version Values | Description |
|-------|---------------|-------------|
| Pre-stable | `alpha`, `beta`, `gamma` | Development versions before API stabilization |
| Stable | `1`, `2`, `3`, ... | Production-ready versions with incrementing integers |

## Version Correlation

### Configuration Format Changes Imply Breaking Changes

A modification to the configuration file format **always** introduces a breaking change in `tpmtb`, because the tool must be capable of reading and validating the configuration file.

**Example**: If a configuration file uses `version: "2"`, there must exist a version `vX.Y.Z` of `tpmtb` that supports this format.

### Alignment with Tool Major Version

To maintain clarity, the tool's **major version** should align with the configuration format version when possible:

| Configuration Version | Tool Version | Example |
|----------------------|--------------|---------|
| `"1"` | `v1.x.x` | `v1.0.0`, `v1.2.3` |
| `"2"` | `v2.x.x` | `v2.0.0`, `v2.1.0` |
| `"3"` | `v3.x.x` | `v3.0.0`, `v3.0.1` |

### Breaking Changes Without Format Impact

If a breaking change occurs in `tpmtb` that does **not** affect the configuration file format:

1. The configuration `version` field remains **unchanged**
2. Documentation provides a **version mapping table** showing which `tpmtb` versions support which configuration format versions

**Example**:

| `tpmtb` Version | Supported Configuration Versions |
|----------------|----------------------------------|
| `v1.0.0` | `1` |
| `v2.0.0` | `1` (breaking change in CLI, format unchanged) |
| `v3.0.0` | `2` (new configuration format) |

## Backward Compatibility Policy

### General Rule

`tpmtb` MUST **ALWAYS** maintain **read compatibility** with previous configuration file format versions for the `generate` command.

The `generate` command produces a bundle file (default filename: `tpm-ca-certificates.pem`) from the configuration file, regardless of the configuration format version.

**Example**: If the current `tpmtb` version is `v2.0.0`, it must be capable of reading and processing configuration files with `version: "1"` and `version: "2"`.

### Scope of Backward Compatibility

Backward compatibility applies **only** to the `generate` command:

| Command | Backward Compatibility |
|---------|----------------------|
| `generate` | ✅ Reads all supported previous format versions |
| `validate` | ❌ Only validates the current format version |
| `format` | ❌ Only formats the current format version |
| `certificates add` | ❌ Only writes the current format version |

### Exception: v1 Stability Boundary

> [!WARNING]
> This section MAY be removed if pre-stable formats are mostly equivalent to stable `version: "1"`.

Starting from `tpmtb v1.0.0`, pre-stable configuration format versions (`alpha`, `beta`, `gamma`) are **no longer supported** if the gap between `alpha` and `version: "1"` is significant.

| `tpmtb` Version | Supported Configuration Versions |
|----------------|----------------------------------|
| `v0.x.x` | `alpha`, `beta`, `gamma`, `1`, `2`, ... (all) |
| `v1.x.x` | `1` (stable versions only) |
| `v2.x.x` | `1`, `2` (stable versions only) |

**Rationale**: Pre-stable formats are development artifacts and should not be supported indefinitely in production-grade releases.
