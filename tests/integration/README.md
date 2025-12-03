# Integration Tests for `verify` Command

This directory contains integration tests that validate the complete verification workflow for TPM trust bundles using GitHub Attestations.

## Test Repository

The tests use the public test repository: **`loicsikidi/test-hybrid-release`**

- **Tag:** `2025-01-03`
- **Commit:** `a703c9c414fcad56351b5b6326a7d0cbaf2f0b9c`
- **Artifact:** `tpm-ca-certificates.pem` (test certificate bundle)
- **Expected Digest:** `sha256:ac58579d398a60f0d610b0bd405c983ff30a91a551ca57dd4ca30aee2536cc4a`

## Running the Tests

### Run all integration tests

```bash
go test ./tests/integration/... -v
```

### Run with timeout

```bash
go test ./tests/integration/... -v -timeout=120s
```

### Skip integration tests in short mode

```bash
go test ./tests/integration/... -short
# Integration tests will be skipped
```

## Test Cases

### 1. `TestVerifyIntegration`

**Purpose:** End-to-end verification workflow validation

**Steps:**
1. Compute bundle digest (SHA-256)
2. Fetch attestations from GitHub API
3. Initialize Sigstore verifier with TUF
4. Build verification policy with:
   - OIDC Issuer: `https://token.actions.githubusercontent.com`
   - Source Repository: `loicsikidi/test-hybrid-release`
   - Build Workflow: `.github/workflows/release-bundle.yml@refs/tags/2025-01-03`
5. Verify attestations against policy

**Expected Result:** ✓ Verification succeeds

### 2. `TestVerifyInvalidDigest`

**Purpose:** Verify behavior with non-existent digest

**Steps:**
1. Try to fetch attestations with invalid digest
2. Verify no attestations are returned or error is raised

**Expected Result:** ✓ No attestations found or error returned

### 3. `TestVerifyPolicyMismatch`

**Purpose:** Verify that incorrect policy causes verification failure

**Steps:**
1. Fetch valid attestations
2. Build policy with wrong workflow name (`.github/workflows/wrong-workflow.yml`)
3. Attempt verification

**Expected Result:** ✓ Verification fails with certificate identity mismatch error

### 4. `TestDigestComputation`

**Purpose:** Validate SHA-256 digest computation

**Steps:**
1. Create test bundle with known content
2. Compute digest
3. Verify it matches expected value

**Expected Result:** ✓ Digest matches expected value

### 5. `TestBundleLocation`

**Purpose:** Verify bundle files can be accessed from different locations

**Test Cases:**
- File in current directory
- File in subdirectory

**Expected Result:** ✓ Digest computation works for all locations

## Requirements

- **Network Access:** Tests require internet connectivity to:
  - Fetch attestations from GitHub API (`api.github.com`)
  - Download TUF metadata from Sigstore (`tuf.sigstore.dev`)

- **No Authentication:** Tests use public GitHub API endpoints (no token required)

## Expected Output

```
=== RUN   TestVerifyIntegration
    verify_test.go:43: Step 1: Computing bundle digest...
    verify_test.go:52: ✓ Digest: sha256:ac58579d398a60f0d610b0bd405c983ff30a91a551ca57dd4ca30aee2536cc4a
    verify_test.go:55: Step 2: Fetching attestations from GitHub API...
    verify_test.go:65: ✓ Loaded 1 attestation(s)
    verify_test.go:75: Step 3: Creating Sigstore verifier...
    verify_test.go:80: ✓ Verifier created
    verify_test.go:83: Step 4: Building verification policy...
    verify_test.go:96: ✓ Policy built with criteria:
    verify_test.go:97:   - OIDC Issuer: https://token.actions.githubusercontent.com
    verify_test.go:98:   - Source Repo: loicsikidi/test-hybrid-release
    verify_test.go:99:   - Build Workflow: .github/workflows/release-bundle.yml@refs/tags/2025-01-03
    verify_test.go:102: Step 5: Verifying attestations...
    verify_test.go:113: ✓ Attestation 0 verified successfully
    verify_test.go:130: ✓ Verification succeeded
--- PASS: TestVerifyIntegration (0.66s)
=== RUN   TestVerifyInvalidDigest
--- PASS: TestVerifyInvalidDigest (0.22s)
=== RUN   TestVerifyPolicyMismatch
    verify_test.go:199: ✓ Attestation 0 correctly failed verification: ...
--- PASS: TestVerifyPolicyMismatch (0.27s)
=== RUN   TestDigestComputation
--- PASS: TestDigestComputation (0.00s)
=== RUN   TestBundleLocation
--- PASS: TestBundleLocation (0.00s)
PASS
ok      github.com/loicsikidi/tpm-trust-bundle/tests/integration    1.171s
```

## Troubleshooting

### Test fails with "no such host"

**Problem:** Network connectivity issue or DNS resolution failure

**Solution:**
- Check internet connection
- Verify `api.github.com` and `tuf.sigstore.dev` are accessible
- Check firewall/proxy settings

### Test fails with "attestation not found"

**Problem:** Test repository attestations may have been deleted or are unavailable

**Solution:**
- Verify the test repository still exists: https://github.com/loicsikidi/test-hybrid-release
- Check the release tag `2025-01-03` is still present
- Update test constants if repository has changed

### Test fails with "TUF metadata error"

**Problem:** TUF cache may be corrupted

**Solution:**
```bash
rm -rf ~/.tpmtb/tuf-cache
go test ./tests/integration/... -v
```

## Adding New Tests

When adding new integration tests:

1. Use `testing.Short()` check to allow skipping with `-short` flag
2. Add descriptive test names and documentation
3. Use `t.Helper()` in helper functions
4. Clean up temporary files with `defer os.Remove()`
5. Log test steps with `t.Log()` for debugging
6. Use subtests (`t.Run()`) for related test cases

## CI/CD Integration

These tests can be integrated into CI/CD pipelines:

```yaml
# Example GitHub Actions workflow
- name: Run integration tests
  run: go test ./tests/integration/... -v -timeout=120s
```

**Note:** Ensure CI environment has network access to required services.
