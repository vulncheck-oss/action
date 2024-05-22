<p align="center">
    <img src="/logo-action.png" align="center" alt="VulnCheck Logo" width="150" />
</p>

# The VulnCheck Action

> Bring VulnCheck into your CI/CD pipeline.

This Github Action uses the VulnCheck CLI to integrte security-related tasks
into your CI/CD pipeline.

![CI](https://github.com/vulncheck-oss/action/actions/workflows/ci.yml/badge.svg)
[![Check dist/](https://github.com/vulncheck-oss/action/actions/workflows/check-dist.yml/badge.svg)](https://github.com/vulncheck-oss/action/actions/workflows/check-dist.yml)
[![Coverage](./badges/coverage.svg)](./badges/coverage.svg)

## Usage

### Scan your project for vulnerabilities

```yaml
name: Scan with VulnCheck

on:
  pull_request:
    branches:
      - main

permissions: write-all

jobs:
  scan:
    name: Scan with VulnCheck
    runs-on: ubuntu-latest
    steps:
      - uses: vulncheck-oss/action@v1.0.3
        with:
          command: scan
          token: ${{ secrets.VC_TOKEN }}
```