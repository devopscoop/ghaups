# ghaups — agent guidelines

## What this is

Single-file Python CLI (`ghaups.py`) that updates GitHub Actions in workflow files to pinned SHA references, optionally scans them with [Trivy](https://trivy.dev/docs/latest/getting-started/installation/) for HIGH/CRITICAL vulnerabilities.

## Quick start

```bash
uv run ghaups.py .github/workflows/*.yml
```

## Key commands

```bash
uv run ghaups.py <files...>            # update + scan (default)
uv run ghaups.py --no-scan <files...>  # skip Trivy scan
uv run ghaups.py --no-update <files...># pin current version to SHA, no update check
uv run ghaups.py --log-level debug <files...>
```

## Architecture

- **Entrypoint:** `ghaups.py` — single module, no package structure, no tests.
- **Dependencies:** Python ≥3.11, `requests` (managed via `uv`, lockfile is `uv.lock`).
- **No CI, no pre-commit, no typecheck or lint config.**
- **Cache:** `~/.ghaups_cache.json` (1-hour TTL) to avoid GitHub API rate limits.
- **GitHub Action:** `action.yml` + `Dockerfile` + `entrypoint.sh` — Docker-based action that maps `INPUT_*` env vars to CLI args.
- **Release:** Push `MAJOR.MINOR.PATCH` tag → workflow creates a GitHub Release and moves `MAJOR` / `MAJOR.MINOR` tags forward.

## Release

```bash
git tag 0.1.0
git push origin 0.1.0
```

This pushes the tag to the remote. The release workflow in `.github/workflows/release.yml` triggers on the push, creates a GitHub Release, and force-updates the `0` and `0.1` floating tags forward.

## How it works

1. Parses `uses: owner/repo@ref` lines from workflow files.
1. Follows GitHub `/releases/latest` redirect to find latest version.
1. Resolves version tag → commit SHA via GitHub API.
1. Rewrites file with `owner/repo@<sha> #vX.Y.Z` format (pinned + commented).
1. Optionally runs `trivy repository --scanners vuln --severity CRITICAL --commit <sha> <repo_url>`.

## Behavioral quirks

- `--no-update` resolves the **current** tag to its SHA (does not look for newer versions).
- `--no-scan` and `--no-update` are independent flags; both can be combined.
- Logging splits: INFO/DEBUG → stdout, WARNING/ERROR → stderr.
- Trivy currently scans only CRITICAL severity (`--severity CRITICAL`, note `HIGH` is commented out in code).
- Trivy exit code 1 for found vulnerabilities triggers `sys.exit(1)` at the end.

## Common gotchas

- **Trivy must be installed separately** — not a Python dependency.
- GitHub API has rate limits; the 1-hour cache helps but hitting many actions may still fail.
- Only scans actions after resolving SHA (not unpinned tag refs).
- No dry-run mode; files are written in-place on update.
