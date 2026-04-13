# ghaups (GitHub Actions Update, Pin, and Scan)

A simple CLI tool that updates GitHub Actions in workflow files to their latest versions.

The tool:

1. Scans each provided workflow file for GitHub Actions (e.g., `actions/checkout@v3.0.0`).
2. Checks the latest version by following the GitHub releases/latest redirect.
3. Fetches the SHA commit hash for that version via GitHub API.
4. Updates the workflow file with the SHA and version comment (e.g., `actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 #v5.0.0`).
5. Scans each action repository for HIGH/CRITICAL vulnerabilities using Trivy.
6. Reports what was updated and any security issues found.

## Requirements

- [trivy](https://trivy.dev/docs/latest/getting-started/installation/) for vulnerability scanning

## Usage

```bash
usage: ghaups.py [-h] [--no-scan] [--no-update] [--log-level {debug,info,warning,error}] files [files ...]

GitHub Actions Update, Pin, and Scan

A simple CLI tool that updates GitHub Actions in workflow files to their latest versions.

positional arguments:
  files                 Workflow file(s) to process

options:
  -h, --help            show this help message and exit
  --no-scan             Skip scanning actions for vulnerabilities using Trivy
  --no-update           Pin to current version without checking for updates
  --log-level {debug,info,warning,error}
                        Set log level (default: info)

Examples:
  ghaups.py .github/workflows/ci.yml
  ghaups.py --log-level debug workflow.yml
  ghaups.py --no-scan .github/workflows/ci.yml
  ghaups.py --no-update .github/workflows/ci.yml
```

## Example Output

```
$ ghaups.py .github/workflows/opentofu.yml
INFO: UPDATE: actions/cache -> 27d5ce7f107f # v5.0.5
INFO: WROTE: .github/workflows/opentofu.yml (1 actions)
INFO: SCAN PASS: LocalStack/setup-localstack
INFO: SCAN PASS: aws-actions/configure-aws-credentials
INFO: SCAN PASS: aws-actions/configure-aws-credentials
INFO: SCAN PASS: actions/checkout
INFO: SCAN PASS: opentofu/setup-opentofu
INFO: SCAN PASS: actions/cache
INFO: SCAN PASS: actions/github-script
INFO: TOTAL: 1 actions updated
```
