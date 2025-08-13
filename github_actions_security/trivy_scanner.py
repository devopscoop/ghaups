"""
Trivy integration module for vulnerability scanning
"""

import subprocess
import json
import tempfile
import shutil
import logging
from pathlib import Path
from typing import List, Optional, Dict, Any

from .models import Vulnerability


class TrivyScanner:
    """Trivy vulnerability scanner integration."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.trivy_path = self._find_trivy()
    
    def _find_trivy(self) -> Optional[str]:
        """Find the Trivy executable."""
        trivy_path = shutil.which("trivy")
        if trivy_path:
            self.logger.debug(f"Found Trivy at: {trivy_path}")
        return trivy_path
    
    def check_trivy_installation(self) -> bool:
        """Check if Trivy is installed and accessible."""
        if not self.trivy_path:
            self.logger.error("Trivy not found in PATH")
            return False
        
        try:
            result = subprocess.run(
                [self.trivy_path, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                self.logger.info(f"Trivy version: {result.stdout.strip()}")
                return True
            else:
                self.logger.error(f"Trivy version check failed: {result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"Failed to check Trivy installation: {e}")
            return False
    
    def scan_action(self, owner: str, repo: str, ref: str) -> List[Vulnerability]:
        """Scan a GitHub Action repository for vulnerabilities."""
        if not self.trivy_path:
            raise RuntimeError("Trivy is not available")
        
        repo_url = f"https://github.com/{owner}/{repo}.git"
        
        try:
            # Clone repository to temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                temp_path = Path(temp_dir)
                repo_path = temp_path / "repo"
                
                self._clone_repository(repo_url, repo_path, ref)
                
                # Scan with Trivy
                vulnerabilities = self._run_trivy_scan(repo_path)
                
                self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities in {owner}/{repo}@{ref}")
                return vulnerabilities
                
        except Exception as e:
            self.logger.error(f"Failed to scan {owner}/{repo}@{ref}: {e}")
            raise
    
    def _clone_repository(self, repo_url: str, repo_path: Path, ref: str) -> None:
        """Clone a repository to the specified path."""
        try:
            # Clone repository
            clone_cmd = [
                "git", "clone", "--depth", "1", "--branch", ref,
                repo_url, str(repo_path)
            ]
            
            result = subprocess.run(
                clone_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                # If branch/tag clone fails, try cloning and checking out
                self.logger.debug(f"Branch clone failed, trying full clone and checkout: {result.stderr}")
                
                clone_cmd = ["git", "clone", repo_url, str(repo_path)]
                result = subprocess.run(clone_cmd, capture_output=True, text=True, timeout=60)
                
                if result.returncode != 0:
                    raise RuntimeError(f"Git clone failed: {result.stderr}")
                
                # Checkout specific ref
                checkout_cmd = ["git", "-C", str(repo_path), "checkout", ref]
                result = subprocess.run(checkout_cmd, capture_output=True, text=True, timeout=30)
                
                if result.returncode != 0:
                    raise RuntimeError(f"Git checkout failed: {result.stderr}")
            
            self.logger.debug(f"Successfully cloned repository to {repo_path}")
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Git clone operation timed out")
        except Exception as e:
            raise RuntimeError(f"Failed to clone repository: {e}")
    
    def _run_trivy_scan(self, repo_path: Path) -> List[Vulnerability]:
        """Run Trivy scan on the repository."""
        try:
            # Run Trivy filesystem scan
            trivy_cmd = [
                self.trivy_path,
                "fs",
                "--format", "json",
                "--security-checks", "vuln,secret,config",
                str(repo_path)
            ]
            
            result = subprocess.run(
                trivy_cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            if result.returncode != 0:
                self.logger.warning(f"Trivy scan completed with warnings: {result.stderr}")
            
            # Parse JSON output
            if result.stdout:
                scan_results = json.loads(result.stdout)
                return self._parse_trivy_results(scan_results)
            else:
                self.logger.info("No vulnerabilities found")
                return []
                
        except subprocess.TimeoutExpired:
            raise RuntimeError("Trivy scan timed out")
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse Trivy output: {e}")
        except Exception as e:
            raise RuntimeError(f"Trivy scan failed: {e}")
    
    def _parse_trivy_results(self, scan_results: Dict[Any, Any]) -> List[Vulnerability]:
        """Parse Trivy scan results and extract vulnerabilities."""
        vulnerabilities = []
        
        # Handle different Trivy output formats
        results = scan_results.get("Results", [])
        if not results:
            # Try alternative format
            results = [scan_results] if "Vulnerabilities" in scan_results else []
        
        for result in results:
            target = result.get("Target", "unknown")
            vulns = result.get("Vulnerabilities", [])
            
            for vuln in vulns:
                vulnerability = Vulnerability(
                    vuln_id=vuln.get("VulnerabilityID", ""),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    title=vuln.get("Title", ""),
                    description=vuln.get("Description", ""),
                    package=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion", "")
                )
                vulnerabilities.append(vulnerability)
            
            # Handle secrets
            secrets = result.get("Secrets", [])
            for secret in secrets:
                vulnerability = Vulnerability(
                    vuln_id=f"SECRET-{secret.get('RuleID', 'UNKNOWN')}",
                    severity="HIGH",
                    title=f"Secret detected: {secret.get('Title', 'Unknown')}",
                    description=f"Secret found in {target}: {secret.get('Match', '')}",
                    package=target
                )
                vulnerabilities.append(vulnerability)
            
            # Handle misconfigurations
            misconfigs = result.get("Misconfigurations", [])
            for misconfig in misconfigs:
                vulnerability = Vulnerability(
                    vuln_id=misconfig.get("ID", "MISCONFIG-UNKNOWN"),
                    severity=misconfig.get("Severity", "MEDIUM"),
                    title=misconfig.get("Title", "Misconfiguration"),
                    description=misconfig.get("Description", ""),
                    package=target
                )
                vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def scan_dockerfile(self, dockerfile_path: Path) -> List[Vulnerability]:
        """Scan a Dockerfile for vulnerabilities."""
        if not self.trivy_path:
            raise RuntimeError("Trivy is not available")
        
        try:
            trivy_cmd = [
                self.trivy_path,
                "config",
                "--format", "json",
                str(dockerfile_path)
            ]
            
            result = subprocess.run(
                trivy_cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                self.logger.warning(f"Trivy Dockerfile scan completed with warnings: {result.stderr}")
            
            if result.stdout:
                scan_results = json.loads(result.stdout)
                return self._parse_trivy_results(scan_results)
            else:
                return []
                
        except Exception as e:
            self.logger.error(f"Failed to scan Dockerfile: {e}")
            raise
