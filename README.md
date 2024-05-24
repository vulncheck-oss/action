<p align="center">
  <img src="/logo-action.png" alt="VulnCheck Logo" width="150" />
</p>

## The VulnCheck Action

> Bring VulnCheck into your CI/CD pipeline.

<p align="center">
  <img src="/demo-pr-comment.png" />
</p>

This Github Action uses the VulnCheck
[CLI](https://github.com/vulncheck-oss/cli) to integrate security-related tasks
into your CI/CD pipeline.

![CI](https://github.com/vulncheck-oss/action/actions/workflows/ci.yml/badge.svg)
[![Check dist/](https://github.com/vulncheck-oss/action/actions/workflows/check-dist.yml/badge.svg)](https://github.com/vulncheck-oss/action/actions/workflows/check-dist.yml)
[![Coverage](./badges/coverage.svg)](./badges/coverage.svg)

## 🤸 Usage

### 🔏 Scan for vulnerabilities

This example will scan for vulnerabilities and report them as a comment on a
pull request

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

### 💅 Customizing

The only required parameter for any command is the `token` parameter. This is
your VulnCheck API token that can be created in hte portal.

> [!Important]
>
> We recommend you store this token as a secret in either repository or
> organization.

The following are optional parameters that can be used with the `scan` command

| Name                           | Description                   | Default |
| ------------------------------ | ----------------------------- | ------- |
| `scan-path`                    | Path to the directory to scan | `./`    |
| `scan-cvss-base-threshold`     | CVSS base score threshold     | `0`     |
| `scan-cvss-temporal-threshold` | CVSS temporal score threshold | `0`     |

> [!Note]
>
> Specifying either a base or temporal threshold will change the pull request
> comments to split the vulnerabilities into two sections, the first will be
> results found above the threshold and the second will be results found below.
