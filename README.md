# ghaups (GitHub Actions Update, Pin, and Scan)

A simple CLI tool that updates GitHub Actions in workflow files to their latest versions.

## Usage

```bash
python ghaups.py <workflow_file1> [workflow_file2] ...
```

## Examples

Update a single workflow file:
```bash
python ghaups.py .github/workflows/ci.yml
```

Update multiple workflow files:
```bash
python ghaups.py workflow1.yml workflow2.yml workflow3.yml
```

## What it does

The tool:
1. Scans each provided workflow file for GitHub Actions (e.g., `actions/checkout@v3.0.0`)
2. Checks the latest version by following the GitHub releases/latest redirect
3. Fetches the SHA commit hash for that version via GitHub API
4. Updates the workflow file with the SHA and version comment (e.g., `actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 #v5.0.0`)
5. Scans each action repository for HIGH/CRITICAL vulnerabilities using Trivy
6. Reports what was updated and any security issues found

## Example Output

```
ghaups (GitHub Actions Update, Pin, and Scan)
==================================================
Processing test-workflow.yml
  Found action: actions/checkout@v3.0.0
  Updating to: actions/checkout@08c6903cd8c0fde910a37f88322edcfb5dd907a8 #v5.0.0
  Found action: actions/setup-node@v3.5.1  
  Updating to: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 #v4.4.0
  Found action: aws-actions/configure-aws-credentials@v3.0.2
  Updating to: aws-actions/configure-aws-credentials@7474bc4690e29a8392af63c5b98e7449536d5c3a #v4.3.1
  Updated 3 actions in test-workflow.yml

Summary: Updated 3 actions across 1 files
```

## Requirements

- Python 3.7+
- `requests` library
- `trivy` (for vulnerability scanning)