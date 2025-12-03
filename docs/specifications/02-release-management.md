# Release Management Specification

## Document History

| Version |    Date    |   Author    |   Description    |
|---------|------------|-------------|------------------|
| alpha   | 2025-11-26 | Loïc Sikidi | Initial version  |

## Overview

The TPM Trust Bundle project uses a dual-tagging strategy to separately version the trust bundle itself and the `tpmtb` CLI tool. This separation allows independent evolution of the certificate bundle and the tooling used to generate and validate it.

### Independent Release Cadence

Bundle and tool releases are **completely independent**:

- **Bundle releases** occur when certificate content changes (additions, removals)
- **Tool releases** occur when CLI functionality changes (features, fixes, improvements)

> [!NOTE]
> The release management specification is currently in `alpha` version. Once stabilized, it will be promoted to `v1`.

## Tag Types

### 1. Bundle Release Tags

Bundle releases use **date-based versioning** following the ISO 8601 calendar date format.

#### Format

```
YYYY-MM-DD
```

Where:
- `YYYY` = Four-digit year
- `MM` = Two-digit month (01-12)
- `DD` = Two-digit day (01-31)

#### Examples

```
2024-06-15
2025-01-20
2025-11-26
```

#### Purpose

Bundle release tags identify versions of the TPM trust bundle (certificate collection). They are used to:
- Track when new certificates were added
- Track when certificates were removed
- Provide a stable reference for bundle downloads

#### Rationale

Date-based versioning is chosen because:
1. **Low frequency**: Certificate bundle updates occur infrequently
2. **Chronological clarity**: The date immediately indicates when the bundle was released
3. **No confusion**: Avoids semantic versioning decisions (is adding a cert a minor or patch bump?)
4. **Uniqueness**: One release per day is sufficient for the expected update frequency

#### Bundle Release Artifacts

Each bundle release tag produces the following artifacts:

|   Name  |   Description |   Producer   |
|---------|---------------|--------------|
| `tpm-ca-certificates.pem` | The complete certificate bundle in PEM format | `tpmtb` |
| `checksums.txt` | SHA-256 checksum of the bundle | `sha256sum` |
| `checksums.txt.sigstore.json` | Sigstore signature for checksum verification | `cosign` |

> [!NOTE]
> The signature is stored in [sigstore bundle format](https://docs.sigstore.dev/about/bundle/).

#### Bundle Release Process

1. Update `.tpm-roots.yaml` with new/updated certificates
2. Run `tpmtb config format` to ensure consistent formatting
3. Run `tpmtb config validate` to verify configuration
4. Commit changes to repository
5. Create tag with format `YYYY-MM-DD` matching the current date
6. Push tag to trigger CI/CD pipeline
7. CI/CD generates bundle and publishes release artifacts

### 2. Tool Release Tags

Tool releases use **semantic versioning** (SemVer 2.0.0).

#### Format

```
vMAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

Where:
- `MAJOR` = Incompatible API changes
- `MINOR` = Backwards-compatible functionality additions
- `PATCH` = Backwards-compatible bug fixes
- `PRERELEASE` = Optional pre-release identifier (alpha, beta, rc.1, etc.)
- `BUILD` = Optional build metadata

#### Examples

```
v0.1.0
v1.0.0
v1.2.3
v2.0.0-beta.1
v1.5.2+20250115
```

#### Purpose

Tool release tags identify versions of the `tpmtb` CLI tool. They are used to:
- Track CLI feature additions
- Track CLI bug fixes
- Track breaking changes to CLI interface
- Provide stable tool binaries for users

#### Rationale

Semantic versioning is chosen because:
1. **Clear compatibility signals**: Users understand when breaking changes occur (major bump)
2. **Standard practice**: SemVer is the industry standard for tools and libraries
3. **Dependency management**: Allows precise version constraints in automation
4. **Independent evolution**: Tool can evolve faster than bundle content

#### Tool Release Artifacts

|   Name  |   Description |   Example   |   Producer   |
|---------|---------------|:-----------:|--------------|
| `tpmtb_$VERSION_$OS_$ARCH.$EXTENSION` | Binary executables stored in an archive (`tar.gz` for Linux and Darwin targets and `zip` for Windows targets) | <ul><li><em>tpmtb_1.0.0_linux_amd64.tar.gz</em></li><li><em>tpmtb_1.0.0_windows_amd64.zip</em></li></ul> | `goreleaser` |
| `tpmtb_$VERSION_$OS_$ARCH.$EXTENSION.sbom.json` | Software Bill of Materials (SBOM) in SPDX format | <ul><li><em>tpmtb_1.0.0_linux_amd64.tar.gz.sbom.json</em></li><li><em>tpmtb_1.0.0_windows_amd64.zip.sbom.json</em></li></ul> | `syft` |
| `checksums.txt` | SHA-256 checksums for all artefacts (archives and SBOMs)  | `goreleaser` |
| `checksums.txt.sigstore.json` | Sigstore signature for checksum verification | `cosign` |

> [!NOTE]
> The signature verification logic relies on `checksums.txt` as the central point of trust. Adding new build targets (OS/architecture combinations) does not break the verification workflow since all artifact checksums are aggregated in this single file before signing.

#### Tool Release Process

1. Update `CHANGELOG.md` with release notes
2. Commit version bump
3. Create tag with format `vMAJOR.MINOR.PATCH`
4. Push tag to trigger CI/CD pipeline
5. CI/CD builds binaries and publishes release artifacts

## Tag Disambiguation

> [!IMPORTANT]
> To ensure proper separation between bundle and tool releases, two distinct CI/CD pipelines are used:
> - `release-bundle.yml`: Dedicated to bundle generation and release
> - `release.yml`: Dedicated to binary/tool generation and release

To avoid confusion between bundle and tool releases, the following rules apply:

### Bundle Tags
- **MUST** match the exact format `YYYY-MM-DD`
- **MUST NOT** include a `v` prefix
- **MUST** correspond to a valid ISO 8601 calendar date

### Tool Tags
- **MUST** start with a `v` prefix
- **MUST** follow semantic versioning format
- **MUST NOT** be a valid date format

### Examples

| Tag | Type | Valid | Reason |
|-----|------|-------|--------|
| `2024-06-15` | Bundle | ✅ | Valid date format |
| `2025-13-01` | Bundle | ❌ | Invalid month (13) |
| `v1.0.0` | Tool | ✅ | Valid SemVer |
| `1.0.0` | Tool | ❌ | Missing `v` prefix |
| `v20240615` | Tool | ❌ | Date with `v` prefix |
| `2024.06.15` | Bundle | ❌ | Uses dots instead of hyphens |
