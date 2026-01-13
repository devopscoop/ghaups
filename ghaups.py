#!/usr/bin/env python3
"""
ghaups (GitHub Actions Update, Pin, and Scan)

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

CACHE_FILE = Path.home() / ".ghaups_cache.json"
CACHE_EXPIRY_HOURS = 1

logger = logging.getLogger("ghaups")


def setup_logging(level: str) -> None:
    """Configure logging with WARNING+ to stderr, others to stdout."""
    level_map = {
        "debug": logging.DEBUG,
        "info": logging.INFO,
        "warning": logging.WARNING,
        "error": logging.ERROR,
    }
    log_level = level_map.get(level.lower(), logging.INFO)
    
    logger.setLevel(log_level)
    logger.handlers.clear()
    
    formatter = logging.Formatter("%(levelname)s: %(message)s")
    
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


def get_cached_version(owner: str, repo: str) -> Optional[Tuple[str, str]]:
    """Get version info from cache if available and not expired."""
    cache = load_cache()
    key = f"{owner}/{repo}"
    
    if key in cache:
        entry = cache[key]
        cached_time = datetime.fromisoformat(entry.get('timestamp', '2000-01-01'))
        if datetime.now() - cached_time < timedelta(hours=CACHE_EXPIRY_HOURS):
            logger.debug(f"{owner}/{repo}: cache hit -> {entry.get('version')}")
            return entry.get('version'), entry.get('sha')
    
    return None


def set_cached_version(owner: str, repo: str, version: str, sha: str) -> None:
    """Save version info to cache."""
    cache = load_cache()
    key = f"{owner}/{repo}"
    cache[key] = {
        'version': version,
        'sha': sha,
        'timestamp': datetime.now().isoformat()
    }
    save_cache(cache)


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
        
        api_url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{version}"
        api_response = requests.get(api_url, timeout=10)
        
        if api_response.status_code == 200:
            tag_data = api_response.json()
            sha = tag_data.get('object', {}).get('sha')
            if sha:
                logger.debug(f"{owner}/{repo}: found {version} @ {sha[:12]}")
                set_cached_version(owner, repo, version, sha)
                return version, sha
        
        ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/tags/{version}"
        ref_response = requests.get(ref_url, timeout=10)
        
        if ref_response.status_code == 200:
            ref_data = ref_response.json()
            sha = ref_data.get('object', {}).get('sha')
            if sha:
                logger.debug(f"{owner}/{repo}: found {version} @ {sha[:12]}")
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
            "trivy", "repository",
            "--scanners", "vuln",
            "--severity", "HIGH,CRITICAL",
            "--exit-code", "1",
            "--commit", sha,
            repo_url
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
        logger.error("Trivy not found. Install Trivy to enable scanning.")
        return False
    except Exception as e:
        logger.warning(f"Scan error for {owner}/{repo}: {e}")
        return False


def parse_action_reference(uses_line: str) -> Optional[Tuple[str, str, str, Optional[str]]]:
    """Parse a GitHub Action reference from a 'uses' line."""
    match = re.search(r'uses:\s+["\']?([^/]+)/([^@\s"\']+)@([^"\'\s#]+)(?:\s*#\s*(\S+))?', uses_line)
    if match:
        owner, repo, ref, version_comment = match.groups()
        if '.' not in owner:
            return owner, repo, ref, version_comment
    return None


def update_workflow_file(file_path: Path, scan: bool = False) -> Tuple[int, int]:
    """Update a single workflow file with the latest action versions."""
    logger.debug(f"Processing {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f"Cannot read {file_path}: {e}")
        return 0, 0
    
    updated_count = 0
    vuln_count = 0
    modified_lines = []
    actions_to_scan = []
    
    for line in lines:
        modified_line = line
        
        if 'uses:' in line:
            action_info = parse_action_reference(line)
            if action_info:
                owner, repo, current_ref, version_comment = action_info
                
                if version_comment:
                    logger.debug(f"Found {owner}/{repo}@{current_ref} # {version_comment}")
                else:
                    logger.debug(f"Found {owner}/{repo}@{current_ref}")
                
                result = get_latest_version_and_sha(owner, repo)
                if result:
                    latest_version, sha = result
                    
                    is_same_sha = current_ref == sha
                    is_same_version = version_comment == latest_version if version_comment else current_ref == latest_version
                    
                    if is_same_sha and is_same_version:
                        logger.debug(f"{owner}/{repo}: up to date")
                        actions_to_scan.append((owner, repo, sha))
                    else:
                        logger.info(f"UPDATE: {owner}/{repo} -> {sha[:12]} # {latest_version}")
                        old_ref = f"{owner}/{repo}@{current_ref}"
                        new_ref = f"{owner}/{repo}@{sha} # {latest_version}"
                        modified_line = re.sub(f"{re.escape(old_ref)}.*", new_ref, line)
                        updated_count += 1
                        actions_to_scan.append((owner, repo, sha))
                else:
                    logger.warning(f"Cannot determine latest version for {owner}/{repo}")
        
        modified_lines.append(modified_line)
    
    if updated_count > 0:
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(modified_lines)
            logger.info(f"WROTE: {file_path} ({updated_count} actions)")
        except Exception as e:
            logger.error(f"Cannot write {file_path}: {e}")
            return 0, 0
    
    if scan and actions_to_scan:
        logger.debug(f"Scanning {len(actions_to_scan)} actions")
        for owner, repo, sha in actions_to_scan:
            if not scan_action_with_trivy(owner, repo, sha):
                vuln_count += 1
    
    return updated_count, vuln_count


def main():
    """Main entry point for ghaups CLI."""
    parser = argparse.ArgumentParser(
        prog='ghaups',
        description='GitHub Actions Update, Pin, and Scan',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python ghaups.py .github/workflows/ci.yml
  python ghaups.py --log-level debug workflow.yml
  python ghaups.py --scan .github/workflows/ci.yml
'''
    )
    parser.add_argument('files', nargs='+', help='Workflow file(s) to process')
    parser.add_argument('--scan', action='store_true', help='Scan actions for vulnerabilities using Trivy')
    parser.add_argument('--log-level', choices=['debug', 'info', 'warning', 'error'], default='info', help='Set log level (default: info)')
    
    args = parser.parse_args()
    
    setup_logging(args.log_level)
    
    total_updated = 0
    total_vulnerabilities = 0
    
    for file_path_str in args.files:
        file_path = Path(file_path_str)
        
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            continue
        
        if not file_path.is_file():
            logger.error(f"Not a file: {file_path}")
            continue
        
        updated_count, vuln_count = update_workflow_file(file_path, scan=args.scan)
        total_updated += updated_count
        total_vulnerabilities += vuln_count
    
    if total_updated > 0:
        logger.info(f"TOTAL: {total_updated} actions updated")
    
    if args.scan and total_vulnerabilities > 0:
        logger.warning(f"{total_vulnerabilities} actions have vulnerabilities")
        sys.exit(1)


if __name__ == "__main__":
    main()
