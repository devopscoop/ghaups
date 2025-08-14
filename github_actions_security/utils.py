"""
Utility functions for GitHub Actions Security Tool
"""

import logging
import sys
from pathlib import Path
from typing import List


def setup_logging(verbosity: int) -> None:
    """Set up logging based on verbosity level."""
    if verbosity == 0:
        level = logging.WARNING
    elif verbosity == 1:
        level = logging.INFO
    elif verbosity == 2:
        level = logging.DEBUG
    else:
        level = logging.DEBUG
    
    # Configure logging format
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    if verbosity >= 2:
        log_format = "%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s"
    
    logging.basicConfig(
        level=level,
        format=log_format,
        handlers=[
            logging.StreamHandler(sys.stderr)
        ]
    )
    
    # Reduce noise from external libraries
    if verbosity < 3:
        logging.getLogger("urllib3").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("git").setLevel(logging.WARNING)


def find_workflow_files(directory: Path) -> List[Path]:
    """Find all GitHub Actions workflow files in a directory."""
    workflow_files = []
    
    # Common workflow file patterns
    patterns = [
        "**/.github/workflows/*.yml",
        "**/.github/workflows/*.yaml",
        "**/workflows/*.yml",
        "**/workflows/*.yaml"
    ]
    
    for pattern in patterns:
        workflow_files.extend(directory.glob(pattern))
    
    # Also check if the directory itself contains workflow files
    if directory.name in ["workflows", ".github"]:
        for ext in ["yml", "yaml"]:
            workflow_files.extend(directory.glob(f"*.{ext}"))
    
    # Remove duplicates and sort
    unique_files = list(set(workflow_files))
    unique_files.sort()
    
    return unique_files


def validate_workflow_file(file_path: Path) -> bool:
    """Validate if a file is a valid workflow file."""
    if not file_path.exists():
        return False
    
    if file_path.suffix.lower() not in ['.yml', '.yaml']:
        return False
    
    try:
        import yaml
        with open(file_path, 'r', encoding='utf-8') as f:
            content = yaml.safe_load(f)
        
        # Basic validation - must have 'on' or 'jobs' key
        if not isinstance(content, dict):
            return False
        
        return 'on' in content or 'jobs' in content
        
    except Exception:
        return False


def format_file_size(size_bytes: float) -> str:
    """Format file size in human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"


def ensure_directory_exists(directory: Path) -> None:
    """Ensure a directory exists, creating it if necessary."""
    directory.mkdir(parents=True, exist_ok=True)


def is_git_repository(directory: Path) -> bool:
    """Check if the directory is a Git repository."""
    git_dir = directory / ".git"
    return git_dir.exists() and (git_dir.is_dir() or git_dir.is_file())


def get_git_remote_url(directory: Path) -> str:
    """Get the Git remote URL for the repository."""
    if not is_git_repository(directory):
        return ""
    
    try:
        import subprocess
        result = subprocess.run(
            ["git", "-C", str(directory), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    
    return ""


def sanitize_filename(filename: str) -> str:
    """Sanitize a filename by removing invalid characters."""
    import re
    # Replace invalid characters with underscores
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', filename)
    # Remove leading/trailing spaces and dots
    sanitized = sanitized.strip(' .')
    # Ensure it's not empty
    if not sanitized:
        sanitized = "untitled"
    return sanitized


def parse_action_reference(uses: str) -> dict:
    """Parse an action reference string into components."""
    import re
    
    # Handle different formats
    if uses.startswith('./'):
        return {
            "type": "local",
            "path": uses,
            "owner": None,
            "repo": None,
            "ref": None
        }
    
    if uses.startswith('docker://'):
        return {
            "type": "docker",
            "image": uses[9:],  # Remove 'docker://' prefix
            "owner": None,
            "repo": None,
            "ref": None
        }
    
    # GitHub action format: owner/repo@ref
    pattern = r'^([^/]+)/([^@]+)@(.+)$'
    match = re.match(pattern, uses)
    
    if match:
        return {
            "type": "github",
            "owner": match.group(1),
            "repo": match.group(2),
            "ref": match.group(3),
            "path": None,
            "image": None
        }
    
    return {
        "type": "unknown",
        "original": uses,
        "owner": None,
        "repo": None,
        "ref": None,
        "path": None,
        "image": None
    }
