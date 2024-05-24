

# The VulnCheck Action

> Bring VulnCheck into your CI/CD pipeline.

<p align="center">
  <img src="/demo-pr-comment.png" />
</p>
<img src="/logo-action.png" align="right" alt="VulnCheck Logo" width="150" />

This Github Action uses the VulnCheck
[CLI](https://github.com/vulncheck-oss/cli) to integrate security-related tasks
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
