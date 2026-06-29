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

## Repository Setup

The daily workflow creates a PR that modifies `.github/workflows/` files. The default `GITHUB_TOKEN` **cannot** push changes to workflow files — it has no `workflows` permission and there is no way to grant one ([GitHub restriction](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#using-the-github_token-in-a-workflow)). Instead of a personal access token, the workflow mints a short-lived token from an **organization GitHub App**, via [`actions/create-github-app-token`](https://github.com/actions/create-github-app-token). App tokens carry the `workflows` permission, expire automatically (~1 hour), and PRs they open still trigger downstream CI. One app set up at the org level covers every repo in the org.

### Creating the GitHub App

1. Go to **Organization Settings → Developer settings → GitHub Apps → New GitHub App** (`https://github.com/organizations/<org>/settings/apps`).
2. Set:
   - **GitHub App name:** e.g. `ghaups-daily` (must be globally unique).
   - **Homepage URL:** anything (e.g. your org or repo URL).
   - **Webhook:** uncheck **Active** (no webhook needed).
   - **Permissions → Repository permissions:**
     - `Contents` → `Read and write`
     - `Pull requests` → `Read and write`
     - `Workflows` → `Read and write`  ← this is the one a PAT/`GITHUB_TOKEN` can't give you
3. Under **Where can this GitHub App be installed?** choose **Only on this account**, then **Create GitHub App**.
4. On the app's page, note the **Client ID**, then under **Private keys** click **Generate a private key** and download the `.pem` file.
5. In the left sidebar click **Install App** → install it on the org → either **All repositories** or **Only select repositories** (include any repo that runs this workflow).

### Wiring it into the org

In the org, go to **Organization Settings → Secrets and variables → Actions**:

- **Variables** tab → **New organization variable:** name `GHAUPS_APP_CLIENT_ID`, value = the Client ID from step 4.
- **Secrets** tab → **New organization secret:** name `GHAUPS_APP_PRIVATE_KEY`, value = the **entire contents** of the downloaded `.pem` file (including the `-----BEGIN/END-----` lines).
- For both, set the **repository access** to the repos that need them (or **All repositories**).

That's it — the workflow reads `vars.GHAUPS_APP_CLIENT_ID` and `secrets.GHAUPS_APP_PRIVATE_KEY` (org-level values are visible to every repo they're shared with) and needs no PAT.

## GitHub Action

See [`.github/workflows/ghaups-daily.yml`](.github/workflows/ghaups-daily.yml) for a runnable example — it pins actions daily via cron and on `workflow_dispatch`, then opens a PR.

### Action inputs

| Input       | Required | Default | Description |
|-------------|----------|---------|-------------|
| `files`     | yes      | —       | Space-separated workflow file paths relative to repo root |
| `no-scan`   | no       | `false` | Skip Trivy vulnerability scanning |
| `no-update` | no       | `false` | Pin current version to SHA without update check |
| `log-level` | no       | `info`  | Log level: `debug`, `info`, `warning`, `error` |

## Running ghaups across an entire org

To pin actions in **every** repo of an org without copying a workflow into each
one, call the reusable [`org-pin-actions.yml`](.github/workflows/org-pin-actions.yml)
workflow from a single host repo (your org's `.github` repo, or a dedicated
`org-automation` repo). It discovers every repo the GitHub App is installed on,
fans out over them with a matrix, and opens a `ghaups/pin-actions` PR to each.

It reuses the **same** GitHub App and org secret/variable from
[Repository Setup](#repository-setup) above — the App's installation scope
(**All repositories** or a selected set) is what decides which repos get pinned.

Put this one file at `.github/workflows/ghaups-org.yml` in the host repo:

```yaml
name: ghaups org pin
on:
  schedule:
    - cron: '25 22 * * *'
  workflow_dispatch:
    inputs:
      repo:
        description: 'Single repo to pin (blank = all)'
        required: false
        default: ''

permissions: {}

jobs:
  pin:
    # Pin this to a full commit SHA (or a release tag) for supply-chain safety;
    # `@0` floats to the latest 0.x release.
    uses: devopscoop/ghaups/.github/workflows/org-pin-actions.yml@0
    with:
      client-id: ${{ vars.GHAUPS_APP_CLIENT_ID }}
      repo: ${{ inputs.repo }}        # blank on schedule runs = all repos
    secrets:
      app-private-key: ${{ secrets.GHAUPS_APP_PRIVATE_KEY }}
```

Test it first with **Run workflow** (`workflow_dispatch`) and a single `repo`
to confirm token scoping and the PR flow before the full fan-out runs.

Reusable-workflow inputs:

| Input          | Required | Default            | Description |
|----------------|----------|--------------------|-------------|
| `client-id`    | yes      | —                  | GitHub App client ID |
| `owner`        | no       | calling repo owner | Org/owner to target |
| `repo`         | no       | _(all)_            | Single repo to pin; blank = every repo the App is installed on |
| `no-update`    | no       | `false`            | Pin to current SHA without checking for newer versions |
| `max-parallel` | no       | `5`                | Max repos processed concurrently |

Secret `app-private-key` (the App's `.pem` contents) is required.

**Caveats:** a job matrix is capped at **256** repos per run — larger orgs need
to batch. Per-repo branch protection or rulesets must allow the App to push the
PR branch.

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
