# Threat Model

This document outlines the risk assessment for the `tpm-ca-certificates` project and the mitigation measures implemented to minimize identified risks.

## Risks

### 1. Security Vulnerability in the `tpmtb` CLI Binary

An attacker could exploit a vulnerability in the CLI binary to compromise system security.

**Impact: Limited**

- The binary only interacts with the configuration file and TPM trust bundle
- The binary does not handle sensitive data
- The binary does not require elevated privileges to operate
- The binary does not require any forms of authentication

**Mitigation Measures**

- Rigorous code review for every change
- Use of `govulncheck` to detect vulnerabilities in dependencies
- Automated tests to validate code behavior

### 2. Compromise of the TPM Trust Bundle

An attacker could tamper with the TPM trust bundle to include malicious certificates.

**Impact**

- **Critical:** If the attacker compromises the release pipeline (transparency log, signature, provenance attestation), they can publish a malicious bundle that will be accepted by users
- **Moderate:** If the attacker publishes a malicious bundle without transparency log and/or provenance attestation, users who properly verify signatures and attestations will detect the compromise and reject the malicious bundle

**What is the concrete impact if the bundle is compromised?**

If the TPM trust bundle is compromised, it will primarily impact onboarding services as they could be tricked into accepting counterfeit TPMs. In an enterprise context, this could allow an attacker to introduce unauthorized machines into the network, thereby compromising the overall security of the IT infrastructure [^1]. This requires a coordinated attack (bundle compromise + deployment of counterfeit TPMs in the target infrastructure), which is a complex operation to execute. Furthermore, if the project is used by many users, the compromise would be quickly detected and corrected, limiting long-term impact.

[^1]: Hence the importance of implementing other security layers (e.g., measured boot or secure boot) to mitigate this risk.

## Supply Chain Attack Mitigation

To minimize this risk, we implement recommendations from the [Geomys Standard of Care](https://words.filippo.io/standard-of-care/), a set of best practices for supply chain security in open source projects:

### 1. Code Review
Every change requires review and approval. Currently, I am the sole approver, but if additional volunteers join, we will extend this to a quorum of 2 reviewers.

### 2. Dependency Management
Following the Geomys model: no automated dependency updates (no Dependabot). Dependencies are updated deliberately and reviewed carefully.

> [!NOTE]
> [go-test.yaml](../../.github/workflows/go-test.yaml) CI workflow includes `govulncheck` to detect vulnerabilities in dependencies at a daily cadence.

### 3. Phishing-Resistant Authentication
All approvers MUST use WebAuthn 2FA on GitHub and on fallback accounts (e.g., domain registrar, Google account).

### 4. Long-Lived Credentials
Regular contributors MUST avoid persistent long-lived credentials, or make them non-extractable when possible. 

Examples:
- Use `git-credential-oauth` instead of personal access tokens
- Use hardware-bound SSH keys with [`yubikey-agent`](https://github.com/FiloSottile/yubikey-agent), [`ssh-tpm-agent`](https://github.com/Foxboron/ssh-tpm-agent) or [`Secretive`](https://github.com/maxgoedjen/secretive),  instead of traditional SSH keys for git pushes to GitHub
- Avoid extractable credentials that could be stolen or leaked

### 6. CI Security
- **Zizmor analysis:** Static analysis of GitHub Actions workflows
- **No caching:** Disable caching mechanisms that could be poisoned
- **Least-privileged permissions:** GitHub Actions tokens have minimal required permissions

### 7. Vulnerability Handling
We appreciate the work of security researchers and honor embargoes of up to 90 days. Vulnerability details are not shared with people not involved in fixing them until they are made public.

> [!NOTE]
> Following mitigations are not part of the Geomys Standard of Care but are important additional measures.

### 8. Signatures & Attestations
Release signatures are produced using keyless key pairs (via Sigstore/Cosign). This eliminates the complexity and risk of managing long-lived signing keys (secure storage, loss, rotation, compromise, etc.).

### 9. Tooling
We will provide tooling to verify bundles's trustworthiness by checking:
- Transparency log entries (Rekor)
- Provenance attestation (SLSA)
- Signature validity

This empowers users to independently validate that a bundle is trustworthy.

> [!NOTE]
> `tpmtb bundle verify` and `tpmtb bundle download` commands are implemented to facilitate this verification out of the box.

## What We Protect Against
- **Supply chain attacks:** 
  * Verify certificates through multiple channels (URL + pinning + public proof)
  * Security hardening following Geomys Standard of Care
- **Man-in-the-middle attacks:** HTTPS-only URLs
- **Unauthorized additions:** Human review process
- **Compromised vendor sites:** Daily hash verification and monitoring
- **Release tampering:** Transparency logs, provenance attestation, and keyless signing

## What We Don't Protect Against
- **Compromised vendor signing infrastructure:** If a vendor's root CA private key is compromised, we rely on vendor disclosure and community awareness
- **Malicious TPM vendors:** We trust TCG-registered vendors to maintain secure certificate practices
- **Coordination attacks:** A sophisticated attacker who compromises both the vendor website and this repository simultaneously during a review window
- **Complete GitHub platform compromise:** If GitHub itself is compromised, our defenses may be insufficient

## Residual Risks
- Human error during the review process
- Time gap between vendor compromise and daily monitoring detection
- Reliance on vendor honesty and security practices
- Small reviewer pool (currently 1, future goal: 2)

## Known Limitations

### GitHub Platform Dependency

The current implementation has a direct dependency on GitHub's attestation service for bundle verification. This design choice:

**Trade-offs:**
- ✅ **Simplifies the initial iteration:** Leverages GitHub's mature attestation infrastructure without too much effort
- ❌ **Complicates migration:** Moving the repository to another platform (GitLab, Gitea, etc.) would require reworking the entire verification workflow
- ❌ **Vendor lock-in:** Creates coupling between the project's security model and GitHub's availability and policies

**Future Considerations:**

If platform independence becomes a requirement, we should evaluate [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier) as a potential solution. This tool provides platform-agnostic SLSA provenance verification and could enable:
- Repository portability across different hosting platforms
- Reduced dependency on GitHub-specific services
- Broader ecosystem compatibility

For now, the GitHub dependency is an acceptable trade-off given:
- The project's early stage
- GitHub's reliability and widespread adoption in the open source ecosystem
- The complexity cost of implementing platform-agnostic verification from the start
