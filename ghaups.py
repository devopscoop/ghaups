#!/usr/bin/env python3
"""
ghaups (GitHub Actions Update, Pin, and Scan)

A simple CLI tool that updates GitHub Actions in workflow files to their latest versions.
"""

import sys
import re
import json
import argparse
import requests
import subprocess
from pathlib import Path
from typing import List, Tuple, Optional
from datetime import datetime, timedelta

CACHE_FILE = Path.home() / ".ghaups_cache.json"
CACHE_EXPIRY_HOURS = 1


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
    """
    Get version info from cache if available and not expired.
    
    Returns:
        Tuple of (version, sha) or None if not cached or expired
    """
    cache = load_cache()
    key = f"{owner}/{repo}"
    
    if key in cache:
        entry = cache[key]
        cached_time = datetime.fromisoformat(entry.get('timestamp', '2000-01-01'))
        if datetime.now() - cached_time < timedelta(hours=CACHE_EXPIRY_HOURS):
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
    """
    Get the latest version and SHA of a GitHub Action.
    Uses local cache with 1-hour expiry to avoid rate limiting.
    
    Args:
        owner: GitHub repository owner
        repo: GitHub repository name
        
    Returns:
        Tuple of (version, sha) or None if not found
    """
    # Check cache first
    cached = get_cached_version(owner, repo)
    if cached:
        return cached
    
    try:
        # First, get the latest version by following releases/latest redirect
        url = f"https://github.com/{owner}/{repo}/releases/latest"
        response = requests.get(url, allow_redirects=True, timeout=10)
        
        if response.status_code != 200:
            return None
            
        # Extract version from the final URL after redirect
        final_url = response.url
        match = re.search(r'/releases/tag/(.+)$', final_url)
        if not match:
            return None
            
        version = match.group(1)
        
        # Now get the SHA for this tag using GitHub API
        api_url = f"https://api.github.com/repos/{owner}/{repo}/git/ref/tags/{version}"
        api_response = requests.get(api_url, timeout=10)
        
        if api_response.status_code == 200:
            tag_data = api_response.json()
            sha = tag_data.get('object', {}).get('sha')
            if sha:
                set_cached_version(owner, repo, version, sha)
                return version, sha
        
        # Fallback: try to get SHA from the tag reference directly
        ref_url = f"https://api.github.com/repos/{owner}/{repo}/git/refs/tags/{version}"
        ref_response = requests.get(ref_url, timeout=10)
        
        if ref_response.status_code == 200:
            ref_data = ref_response.json()
            sha = ref_data.get('object', {}).get('sha')
            if sha:
                set_cached_version(owner, repo, version, sha)
                return version, sha
        
        return None
    except Exception as e:
        print(f"Error fetching latest version for {owner}/{repo}: {e}")
        return None


def scan_action_with_trivy(owner: str, repo: str, sha: str) -> bool:
    """
    Scan a GitHub Action repository for vulnerabilities using Trivy.
    
    Args:
        owner: GitHub repository owner
        repo: GitHub repository name
        sha: Git commit SHA to scan
        
    Returns:
        True if scan passed (no HIGH/CRITICAL vulnerabilities), False otherwise
    """
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
        
        print(f"    Scanning {owner}/{repo}@{sha} for vulnerabilities...")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        
        if result.returncode == 0:
            print(f"    ✓ No HIGH/CRITICAL vulnerabilities found in {owner}/{repo}")
            return True
        else:
            print(f"    ✗ HIGH/CRITICAL vulnerabilities found in {owner}/{repo}")
            if result.stdout:
                print(f"    Trivy output:\n{result.stdout}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f"    ⚠ Trivy scan timed out for {owner}/{repo}")
        return False
    except FileNotFoundError:
        print(f"    ⚠ Trivy not found. Please install Trivy to enable vulnerability scanning.")
        return False
    except Exception as e:
        print(f"    ⚠ Error scanning {owner}/{repo}: {e}")
        return False


def parse_action_reference(uses_line: str) -> Optional[Tuple[str, str, str, Optional[str]]]:
    """
    Parse a GitHub Action reference from a 'uses' line.
    
    Args:
        uses_line: The line containing the action reference
        
    Returns:
        Tuple of (owner, repo, ref, version_comment) or None if not a GitHub action
        ref is the SHA or version tag, version_comment is the version from # comment if present
    """
    # Match patterns like: owner/repo@version or owner/repo@sha # version
    match = re.search(r'uses:\s+["\']?([^/]+)/([^@\s"\']+)@([^"\'\s#]+)(?:\s*#\s*(\S+))?', uses_line)
    if match:
        owner, repo, ref, version_comment = match.groups()
        # Only process GitHub actions (not local actions or Docker actions)
        if '.' not in owner:  # Simple check to exclude Docker actions
            return owner, repo, ref, version_comment
    
    return None


def update_workflow_file(file_path: Path, scan: bool = False) -> Tuple[int, int]:
    """
    Update a single workflow file with the latest action versions and optionally scan for vulnerabilities.
    
    Args:
        file_path: Path to the workflow file
        scan: Whether to scan actions for vulnerabilities using Trivy
        
    Returns:
        Tuple of (actions updated, actions with vulnerabilities)
    """
    print(f"Processing {file_path}")
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return 0, 0
    
    updated_count = 0
    vuln_count = 0
    modified_lines = []
    actions_to_scan = []  # Store actions for scanning after updates
    
    for line in lines:
        modified_line = line
        
        # Check if this line contains a 'uses' statement
        if 'uses:' in line:
            action_info = parse_action_reference(line)
            if action_info:
                owner, repo, current_ref, version_comment = action_info
                
                # Display found action with version comment if present
                if version_comment:
                    print(f"  Found action: {owner}/{repo}@{current_ref} # {version_comment}")
                else:
                    print(f"  Found action: {owner}/{repo}@{current_ref}")
                
                result = get_latest_version_and_sha(owner, repo)
                if result:
                    latest_version, sha = result
                    
                    # Check if already up to date (same SHA and version)
                    is_same_sha = current_ref == sha
                    is_same_version = version_comment == latest_version if version_comment else current_ref == latest_version
                    
                    if is_same_sha and is_same_version:
                        print(f"  Already up to date")
                        # Add to scan list with current SHA
                        actions_to_scan.append((owner, repo, sha))
                    else:
                        print(f"  Updating to: {owner}/{repo}@{sha} # {latest_version}")
                        # Replace the version in the line with SHA and version comment
                        old_ref = f"{owner}/{repo}@{current_ref}"
                        new_ref = f"{owner}/{repo}@{sha} # {latest_version}"
                        modified_line = re.sub(f"{re.escape(old_ref)}.*", new_ref, line)
                        updated_count += 1
                        # Add to scan list with new SHA
                        actions_to_scan.append((owner, repo, sha))
                else:
                    print(f"  Could not determine latest version for {owner}/{repo}")
        
        modified_lines.append(modified_line)
    
    # Write back the modified content
    if updated_count > 0:
        try:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.writelines(modified_lines)
            print(f"  Updated {updated_count} actions in {file_path}")
        except Exception as e:
            print(f"Error writing {file_path}: {e}")
            return 0, 0
    
    # Scan actions for vulnerabilities (only if --scan flag is used)
    if scan and actions_to_scan:
        print(f"  Scanning {len(actions_to_scan)} actions for vulnerabilities...")
        for owner, repo, sha in actions_to_scan:
            scan_passed = scan_action_with_trivy(owner, repo, sha)
            if not scan_passed:
                vuln_count += 1
    
    return updated_count, vuln_count


def main():
    """Main entry point for ghaups CLI."""
    parser = argparse.ArgumentParser(
        prog='ghaups',
        description='GitHub Actions Update, Pin, and Scan - Updates GitHub Actions to latest versions and pins them using SHA commits.',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python ghaups.py .github/workflows/ci.yml
  python ghaups.py workflow1.yml workflow2.yml
  python ghaups.py --scan .github/workflows/ci.yml
'''
    )
    parser.add_argument('files', nargs='+', help='Workflow file(s) to process')
    parser.add_argument('--scan', action='store_true', help='Scan actions for HIGH/CRITICAL vulnerabilities using Trivy')
    
    args = parser.parse_args()
    
    total_updated = 0
    total_vulnerabilities = 0
    
    print("ghaups (GitHub Actions Update, Pin, and Scan)")
    print("=" * 50)
    
    for file_path_str in args.files:
        file_path = Path(file_path_str)
        
        if not file_path.exists():
            print(f"Error: File not found: {file_path}")
            continue
        
        if not file_path.is_file():
            print(f"Error: Not a file: {file_path}")
            continue
        
        updated_count, vuln_count = update_workflow_file(file_path, scan=args.scan)
        total_updated += updated_count
        total_vulnerabilities += vuln_count
        print()  # Empty line between files
    
    print(f"Summary:")
    print(f"  • Updated {total_updated} actions across {len(args.files)} files")
    
    if args.scan:
        print(f"  • Found {total_vulnerabilities} actions with HIGH/CRITICAL vulnerabilities")
        if total_vulnerabilities > 0:
            print(f"\n⚠ Warning: {total_vulnerabilities} actions have security vulnerabilities!")
            sys.exit(1)
        else:
            print(f"\n✓ All actions are secure!")
    else:
        print(f"\n✓ Done! Use --scan to check for vulnerabilities.")


if __name__ == "__main__":
    main()
