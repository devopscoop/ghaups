"""
GitHub API integration module
"""

import requests
import time
import logging
import os
from typing import Optional
from urllib.parse import urljoin


class GitHubAPI:
    """GitHub API client for resolving action versions."""
    
    def __init__(self, token: Optional[str] = None, base_url: str = "https://api.github.com"):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.base_url = base_url
        self.session = requests.Session()
        self.logger = logging.getLogger(__name__)
        
        # Set up authentication
        if self.token:
            self.session.headers.update({
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json"
            })
        else:
            self.logger.warning("No GitHub token provided. API rate limits will be lower.")
        
        # Rate limiting
        self.rate_limit_remaining = None
        self.rate_limit_reset = None
    
    def _make_request(self, endpoint: str, method: str = "GET", **kwargs) -> requests.Response:
        """Make a request to the GitHub API with rate limiting."""
        url = urljoin(self.base_url, endpoint.lstrip('/'))
        
        # Check rate limit
        self._check_rate_limit()
        
        try:
            response = self.session.request(method, url, **kwargs)
            
            # Update rate limit info
            self.rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
            self.rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))
            
            response.raise_for_status()
            return response
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"GitHub API request failed: {e}")
            raise
    
    def _check_rate_limit(self) -> None:
        """Check and handle rate limiting."""
        if self.rate_limit_remaining is not None and self.rate_limit_remaining < 10:
            if self.rate_limit_reset:
                wait_time = max(0, self.rate_limit_reset - int(time.time()) + 1)
                if wait_time > 0:
                    self.logger.warning(f"Rate limit approaching. Waiting {wait_time} seconds...")
                    time.sleep(wait_time)
    
    def get_latest_sha(self, owner: str, repo: str, ref: str) -> str:
        """Get the latest SHA for a given reference (tag, branch, etc.)."""
        try:
            # Try to resolve the reference to a commit SHA
            endpoint = f"/repos/{owner}/{repo}/commits/{ref}"
            response = self._make_request(endpoint)
            commit_data = response.json()
            
            sha = commit_data['sha']
            self.logger.debug(f"Resolved {owner}/{repo}@{ref} to SHA: {sha}")
            return sha
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                # Try to get the default branch if ref doesn't exist
                self.logger.warning(f"Reference '{ref}' not found for {owner}/{repo}, trying default branch")
                return self._get_default_branch_sha(owner, repo)
            raise
        except Exception as e:
            self.logger.error(f"Failed to resolve {owner}/{repo}@{ref}: {e}")
            raise
    
    def _get_default_branch_sha(self, owner: str, repo: str) -> str:
        """Get the SHA of the default branch."""
        try:
            # Get repository info to find default branch
            endpoint = f"/repos/{owner}/{repo}"
            response = self._make_request(endpoint)
            repo_data = response.json()
            
            default_branch = repo_data['default_branch']
            
            # Get the SHA of the default branch
            endpoint = f"/repos/{owner}/{repo}/commits/{default_branch}"
            response = self._make_request(endpoint)
            commit_data = response.json()
            
            sha = commit_data['sha']
            self.logger.info(f"Using default branch '{default_branch}' SHA for {owner}/{repo}: {sha}")
            return sha
            
        except Exception as e:
            self.logger.error(f"Failed to get default branch SHA for {owner}/{repo}: {e}")
            raise
    
    def get_repository_info(self, owner: str, repo: str) -> dict:
        """Get repository information."""
        try:
            endpoint = f"/repos/{owner}/{repo}"
            response = self._make_request(endpoint)
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Failed to get repository info for {owner}/{repo}: {e}")
            raise
    
    def check_repository_exists(self, owner: str, repo: str) -> bool:
        """Check if a repository exists and is accessible."""
        try:
            self.get_repository_info(owner, repo)
            return True
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return False
            raise
        except Exception:
            return False
    
    def get_rate_limit_status(self) -> dict:
        """Get current rate limit status."""
        try:
            endpoint = "/rate_limit"
            response = self._make_request(endpoint)
            return response.json()
        except Exception as e:
            self.logger.error(f"Failed to get rate limit status: {e}")
            return {}
