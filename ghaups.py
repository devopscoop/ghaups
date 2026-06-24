#!/usr/bin/env python3
"""
GHAUPS (GitHub Actions Update, Pin, and Scan)

A simple CLI tool that updates GitHub Actions in workflow files to their latest versions.
"""

import sys
import re
import json
import logging
import argparse
import requests
import subprocess
from pathlib import Path
from typing import List, Tuple, Optional
from datetime import datetime, timedelta

CACHE_FILE = Path.home() / '.ghaups_cache.json'
CACHE_EXPIRY_HOURS = 1

logger = logging.getLogger('ghaups')

# In-memory cache loaded once per run; persisted once at exit. Avoids
# re-reading/re-writing the cache file on every action lookup.
_cache_data: Optional[dict] = None
_cache_dirty = False


def setup_logging(level: str) -> None:
    """Configure logging with WARNING+ to stderr, others to stdout."""
    level_map = {
        'debug': logging.DEBUG,
        'info': logging.INFO,
        'warning': logging.WARNING,
        'error': logging.ERROR,
    }
    log_level = level_map.get(level.lower(), logging.INFO)

    logger.setLevel(log_level)
    logger.handlers.clear()

    formatter = logging.Formatter('%(levelname)s: %(message)s')

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setLevel(log_level)
    stdout_handler.addFilter(lambda record: record.levelno < logging.WARNING)
    stdout_handler.setFormatter(formatter)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.WARNING)
    stderr_handler.setFormatter(formatter)

    logger.addHandler(stdout_handler)
    logger.addHandler(stderr_handler)


def load_cache() -> dict:
    """Load the cache from disk."""
    if CACHE_FILE.exists():
        try:
            with open(CACHE_FILE, 'r') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def save_cache(cache: dict) -> None:
    """Save the cache to disk."""
    try:
        with open(CACHE_FILE, 'w') as f:
            json.dump(cache, f, indent=2)
    except IOError:
        pass


def _get_cache() -> dict:
    """Return the in-memory cache, loading it from disk on first use."""
    global _cache_data
    if _cache_data is None:
        _cache_data = load_cache()
    return _cache_data


def flush_cache() -> None:
    """Persist the in-memory cache to disk if it has unsaved changes."""
    if _cache_dirty and _cache_data is not None:
        save_cache(_cache_data)


def get_cached_version(owner: str, repo: str) -> Optional[Tuple[str, str]]:
    """Get version info from cache if available and not expired."""
    cache = _get_cache()
    key = f"{owner}/{repo}"

    if key in cache:
        entry = cache[key]
        cached_time = datetime.fromisoformat(entry.get('timestamp', '2000-01-01'))
        if datetime.now() - cached_time < timedelta(hours=CACHE_EXPIRY_HOURS):
            logger.debug(f"{owner}/{repo}: cache hit -> {entry.get('version')}")
            return entry.get('version'), entry.get('sha')

    return None


def set_cached_version(owner: str, repo: str, version: str, sha: str) -> None:
    """Save version info to the in-memory cache (persisted at exit)."""
    global _cache_dirty
    cache = _get_cache()
    key = f"{owner}/{repo}"
    cache[key] = {
        'version': version,
        'sha': sha,
        'timestamp': datetime.now().isoformat(),
    }
    _cache_dirty = True


def get_sha_for_tag(owner: str, repo: str, tag: str) -> Optional[str]:
    """Get the SHA for a specific tag, trying both git ref endpoints."""
    try:
        for path in ('git/ref/tags', 'git/refs/tags'):
            url = f"https://api.github.com/repos/{owner}/{repo}/{path}/{tag}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                sha = response.json().get('object', {}).get('sha')
                if sha:
                    logger.debug(f"{owner}/{repo}: found {tag} @ {sha[:12]}")
                    return sha
        return None
    except Exception as e:
        logger.warning(f"Failed to fetch {owner}/{repo} tag {tag}: {e}")
        return None


def get_latest_version_and_sha(owner: str, repo: str) -> Optional[Tuple[str, str]]:
    """Get the latest version and SHA of a GitHub Action with caching."""
    cached = get_cached_version(owner, repo)
    if cached:
        return cached

    logger.debug(f"{owner}/{repo}: fetching from GitHub")

    try:
        url = f"https://github.com/{owner}/{repo}/releases/latest"
        response = requests.get(url, allow_redirects=True, timeout=10)

        if response.status_code != 200:
            return None

        final_url = response.url
        match = re.search(r'/releases/tag/(.+)$', final_url)
        if not match:
            return None

        version = match.group(1)

        sha = get_sha_for_tag(owner, repo, version)
        if sha:
            set_cached_version(owner, repo, version, sha)
            return version, sha

        return None
    except Exception as e:
        logger.warning(f"Failed to fetch {owner}/{repo}: {e}")
        return None


def scan_action_with_trivy(owner: str, repo: str, sha: str) -> bool:
    """Scan a GitHub Action repository for vulnerabilities using Trivy."""
    try:
        repo_url = f"https://github.com/{owner}/{repo}"
        cmd = [
            'trivy',
            'repository',
            '--scanners',
            'vuln',
            '--severity',
            'CRITICAL', # 'HIGH,CRITICAL',
            '--exit-code',
            '1',
            '--commit',
            sha,
            repo_url,
        ]

        logger.debug(f"Scanning {owner}/{repo}@{sha[:12]}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

        if result.returncode == 0:
            logger.info(f"SCAN PASS: {owner}/{repo}")
            return True
        else:
            logger.warning(f"SCAN FAIL: {owner}/{repo} has vulnerabilities")
            if result.stdout:
                logger.warning(result.stdout)
            return False

    except subprocess.TimeoutExpired:
        logger.warning(f"Trivy scan timed out for {owner}/{repo}")
        return False
    except FileNotFoundError:
        logger.error('Trivy not found. Install Trivy to enable scanning.')
        return False
    except Exception as e:
        logger.warning(f"Scan error for {owner}/{repo}: {e}")
        return False


def parse_action_reference(
    uses_line: str,
) -> Optional[Tuple[str, str, str, Optional[str]]]:
    """Parse a GitHub Action reference from a 'uses' line."""
    match = re.search(
        r'uses:\s+["\']?([^/]+)/([^@\s"\']+)@([^"\'\s#]+)(?:\s*#\s*(\S+))?', uses_line
    )
    if match:
        owner, repo, ref, version_comment = match.groups()
        if '.' not in owner:
            return owner, repo, ref, version_comment
    return None


def update_workflow_file(
    file_path: Path, no_update: bool = False
) -> Tuple[int, List[Tuple[str, str, str]]]:
    """Update a single workflow file with the latest action versions.

    Returns the number of actions updated and the list of (owner, repo, sha)
    references seen, for the caller to scan (deduplicated) afterwards.
    """
    logger.debug(f"Processing {file_path}")

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f"Cannot read {file_path}: {e}")
        return 0, 0

    updated_count = 0
    modified_lines = []
    actions_to_scan = []

    for line in lines:
        modified_line = line

        if 'uses:' in line:
            action_info = parse_action_reference(line)
            if action_info:
                owner, repo, current_ref, version_comment = action_info

                if version_comment:
                    logger.debug(
                        f"Found {owner}/{repo}@{current_ref} # {version_comment}"
                    )
                else:
                    logger.debug(f"Found {owner}/{repo}@{current_ref}")

                if no_update:
                    is_sha_ref = len(current_ref) == 40
                    if is_sha_ref:
                        sha = current_ref
                        logger.debug(f"{owner}/{repo}@{current_ref}: already pinned")
                        actions_to_scan.append((owner, repo, sha))
                    else:
                        sha = get_sha_for_tag(owner, repo, current_ref)
                        if sha:
                            logger.info(
                                f"PIN: {owner}/{repo}@{current_ref} -> {sha[:12]} # {current_ref}"
                            )
                            old_ref = f"{owner}/{repo}@{current_ref}"
                            new_ref = f"{owner}/{repo}@{sha} # {current_ref}"
                            modified_line = re.sub(
                                f"{re.escape(old_ref)}.*", new_ref, line
                            )
                            updated_count += 1
                            actions_to_scan.append((owner, repo, sha))
                        else:
                            logger.warning(
                                f"Cannot find SHA for {owner}/{repo}@{current_ref}"
                            )
                else:
                    result = get_latest_version_and_sha(owner, repo)
                    if result:
                        latest_version, sha = result

                        is_same_sha = current_ref == sha
                        is_same_version = (
                            version_comment == latest_version
                            if version_comment
                            else current_ref == latest_version
                        )

                        if is_same_sha and is_same_version:
                            logger.debug(f"{owner}/{repo}: up to date")
                            actions_to_scan.append((owner, repo, sha))
                        else:
                            logger.info(
                                f"UPDATE: {owner}/{repo} -> {sha[:12]} # {latest_version}"
                            )
                            old_ref = f"{owner}/{repo}@{current_ref}"
                            new_ref = f"{owner}/{repo}@{sha} # {latest_version}"
                            modified_line = re.sub(
                                f"{re.escape(old_ref)}.*", new_ref, line
                            )
                            updated_count += 1
                            actions_to_scan.append((owner, repo, sha))
                    else:
                        logger.warning(
                            f"Cannot determine latest version for {owner}/{repo}"
                        )

        modified_lines.append(modified_line)

    if updated_count > 0:
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(modified_lines)
            logger.info(f"WROTE: {file_path} ({updated_count} actions)")
        except Exception as e:
            logger.error(f"Cannot write {file_path}: {e}")
            return 0, []

    return updated_count, actions_to_scan


def main():
    """Main entry point for ghaups CLI."""
    parser = argparse.ArgumentParser(
        prog='ghaups.py',
        description="""
GitHub Actions Update, Pin, and Scan

A simple CLI tool that updates GitHub Actions in workflow files to their latest versions.
""",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ghaups.py .github/workflows/ci.yml
  ghaups.py --log-level debug workflow.yml
  ghaups.py --no-scan .github/workflows/ci.yml
  ghaups.py --no-update .github/workflows/ci.yml
""",
    )
    parser.add_argument('files', nargs='+', help='Workflow file(s) to process')
    parser.add_argument(
        '--no-scan',
        action='store_true',
        help='Skip scanning actions for vulnerabilities using Trivy',
    )
    parser.add_argument(
        '--no-update',
        action='store_true',
        help='Pin to current version without checking for updates',
    )
    parser.add_argument(
        '--log-level',
        choices=['debug', 'info', 'warning', 'error'],
        default='info',
        help='Set log level (default: info)',
    )

    args = parser.parse_args()

    setup_logging(args.log_level)

    total_updated = 0
    total_vulnerabilities = 0
    scan_targets: List[Tuple[str, str, str]] = []

    try:
        for file_path_str in args.files:
            file_path = Path(file_path_str)

            if not file_path.exists():
                logger.error(f"File not found: {file_path}")
                continue

            if not file_path.is_file():
                logger.error(f"Not a file: {file_path}")
                continue

            updated_count, file_targets = update_workflow_file(
                file_path, no_update=args.no_update
            )
            total_updated += updated_count
            scan_targets.extend(file_targets)
    finally:
        flush_cache()

    if total_updated > 0:
        logger.info(f"TOTAL: {total_updated} actions updated")

    if not args.no_scan:
        # Deduplicate so each unique action is scanned only once, even when it
        # appears in multiple files or multiple times in one file.
        seen = set()
        unique_targets = []
        for target in scan_targets:
            if target not in seen:
                seen.add(target)
                unique_targets.append(target)

        if unique_targets:
            logger.debug(f"Scanning {len(unique_targets)} actions")
        for owner, repo, sha in unique_targets:
            if not scan_action_with_trivy(owner, repo, sha):
                total_vulnerabilities += 1

        if total_vulnerabilities > 0:
            logger.warning(f"{total_vulnerabilities} actions have vulnerabilities")
            sys.exit(1)


if __name__ == '__main__':
    main()
