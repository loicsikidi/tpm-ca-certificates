# Testing Guide

## Overview

> [!NOTE]
> This document assumes that you are working in the nix shell provided by the repository. To enter the nix shell, run:
> ```bash
> nix shell
> ```

## Running Tests

### Unit tests

```bash
gotest --short
```

### Integration tests

```bash
export GITHUB_TOKEN=$(gh auth token)
gotest
```

#### Testing with TPM EK Certificates

Some tests in this package require a TPM Endorsement Key (EK) certificate for verification testing. Since EK certificates contain sensitive hardware information, they are not included in the repository.

```bash
export TPM_EK_CERT_PATH=/path/to/your/ek-certificate.pem
export GITHUB_TOKEN=$(gh auth token)
gotest
```
