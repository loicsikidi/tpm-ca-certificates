# API Versioning Specification

## Document History

| Version |    Date    |   Author    |   Description    |
|---------|------------|-------------|------------------|
| v1      | 2025-12-07 | Loïc Sikidi | Initial version  |

## Scope

This specification applies exclusively to the public API (`pkg/api*`) intended for consumption by external repositories.

## Channels

The project exposes two distinct channels:

### Stable Channel
- Exposes stable APIs (v1, v2, etc.)
- **Stability guarantee**: No breaking changes without a major version bump
- Deprecation policy: Functions scheduled for removal in a future major version are first marked as deprecated in the current version

### Beta Channel
- Exposes APIs under development (v1beta, v2beta, etc.)
- **No stability guarantee**: Breaking changes may be introduced without prior notice

## Roadmap

### v0.x Phase
- Only `pkg/apiv1beta` will be available
- Goal: Establish a satisfactory API contract

### v1.0 Release
- `pkg/apiv1` will be introduced in the stable channel
- `pkg/apiv1beta` will remain in the beta channel with continued evolution

## Package Structure

```
pkg/
├── apiv1beta/    # Beta channel - unstable, subject to breaking changes
└── apiv1/        # Stable channel - stability guarantees (available from v1.0)
```

## Migration Path

External consumers should:
1. Start with `pkg/apiv1beta` during the v0.x phase
2. Monitor API changes and provide feedback
3. Migrate to `pkg/apiv1` when v1.0 is released for production use
4. Continue using `pkg/apiv1beta` for experimental features

## ⚠️ Warning: Potential Package Extraction

If the API versioning conflicts with `tpmtb`'s versioning strategy, the `pkg/api*` package may be extracted into a separate repository with its own lifecycle.

Should this scenario arise, this documentation will be updated with:
- The extraction strategy
- The rationale behind the decision
- Migration guidelines for consumers
