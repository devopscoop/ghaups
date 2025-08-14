"""
Data models for GitHub Actions Security Tool
"""

from dataclasses import dataclass
from typing import List, Optional
import re


@dataclass
class Action:
    """Represents a GitHub Action reference in a workflow."""
    
    def __init__(self, uses: str):
        self.original_uses = uses
        self.original_ref = None
        self._parse_uses(uses)
    
    def _parse_uses(self, uses: str) -> None:
        """Parse the 'uses' string to extract owner, repo, and ref."""
        # Handle different action formats:
        # - actions/checkout@v3
        # - actions/checkout@main
        # - actions/checkout@abc123...
        # - ./local-action
        # - docker://image:tag
        
        if uses.startswith('./') or uses.startswith('docker://'):
            # Local or Docker actions - not supported for pinning
            self.owner = None
            self.repo = None
            self.ref = None
            self.is_github_action = False
            return
        
        # GitHub action format: owner/repo@ref
        pattern = r'^([^/]+)/([^@]+)@(.+)$'
        match = re.match(pattern, uses)
        
        if match:
            self.owner = match.group(1)
            self.repo = match.group(2)
            self.ref = match.group(3)
            self.original_ref = self.ref
            self.is_github_action = True
        else:
            # Invalid format
            self.owner = None
            self.repo = None
            self.ref = None
            self.is_github_action = False
    
    def needs_pinning(self) -> bool:
        """Check if this action needs to be pinned to a SHA."""
        if not self.is_github_action or not self.ref:
            return False
        
        # Already pinned if ref looks like a SHA (40 hex characters)
        if re.match(r'^[a-f0-9]{40}$', self.ref):
            return False
        
        return True
    
    def pin_to_sha(self, sha: str) -> None:
        """Pin this action to a specific SHA."""
        if not self.is_github_action:
            raise ValueError("Cannot pin non-GitHub actions")
        
        self.ref = sha
    
    def get_pinned_uses(self) -> str:
        """Get the uses string with the action pinned to SHA."""
        if not self.is_github_action:
            return self.original_uses
        
        # If the action has been pinned (SHA != original ref), add comment with original version
        if self.ref != self.original_ref and self.original_ref:
            return f"{self.owner}/{self.repo}@{self.ref} # {self.original_ref}"
        else:
            return f"{self.owner}/{self.repo}@{self.ref}"
    
    def __str__(self) -> str:
        if self.is_github_action:
            return f"{self.owner}/{self.repo}@{self.ref}"
        return self.original_uses


@dataclass
class Workflow:
    """Represents a GitHub Actions workflow."""
    
    def __init__(self, name: str, content: dict, actions: List[Action]):
        self.name = name
        self.content = content
        self.actions = actions
    
    def get_modified_content(self) -> dict:
        """Get the workflow content with pinned actions."""
        modified_content = self.content.copy()
        
        # Find and replace action references in jobs
        if 'jobs' in modified_content:
            for job_name, job in modified_content['jobs'].items():
                if 'steps' in job:
                    for step in job['steps']:
                        if 'uses' in step:
                            # Find the corresponding action and update
                            for action in self.actions:
                                if step['uses'] == action.original_uses:
                                    step['uses'] = action.get_pinned_uses()
                                    break
        
        return modified_content


@dataclass
class Vulnerability:
    """Represents a security vulnerability found in an action."""
    
    def __init__(self, vuln_id: str, severity: str, title: str, description: str, 
                 package: Optional[str] = None, installed_version: Optional[str] = None, 
                 fixed_version: Optional[str] = None):
        self.vuln_id = vuln_id
        self.severity = severity
        self.title = title
        self.description = description
        self.package = package
        self.installed_version = installed_version
        self.fixed_version = fixed_version
    
    def to_dict(self) -> dict:
        """Convert vulnerability to dictionary format."""
        return {
            "vuln_id": self.vuln_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "package": self.package,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version
        }
