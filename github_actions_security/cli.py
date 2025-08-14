import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from .workflow_parser import WorkflowParser
from .github_api import GitHubAPI
from .trivy_scanner import TrivyScanner
from .utils import setup_logging, find_workflow_files

def create_parser() -> argparse.ArgumentParser:
    """Create and configure the argument parser."""
    parser = argparse.ArgumentParser(
        description="ghaups (GitHub Actions Update, Pin, and Scan)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --workflow-dir .github/workflows --pin-actions
  %(prog)s --workflow-file workflow.yml --scan-vulnerabilities
  %(prog)s --workflow-dir . --pin-actions --scan-vulnerabilities --output report.json
        """
    )
    
    # Input options
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        "--workflow-file", "-f",
        type=Path,
        help="Path to a specific workflow file"
    )
    input_group.add_argument(
        "--workflow-dir", "-d",
        type=Path,
        help="Directory containing workflow files (searches recursively)"
    )
    
    # Action options
    parser.add_argument(
        "--pin-actions", "-p",
        action="store_true",
        help="Pin actions to specific SHA versions"
    )
    parser.add_argument(
        "--scan-vulnerabilities", "-s",
        action="store_true",
        help="Scan actions for vulnerabilities using Trivy"
    )

    
    # Output options
    parser.add_argument(
        "--output", "-o",
        type=Path,
        help="Output file for security report (JSON format)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="count",
        default=0,
        help="Increase verbosity (use -v, -vv, or -vvv)"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes"
    )
    
    # GitHub API options
    parser.add_argument(
        "--github-token",
        help="GitHub API token (or set GITHUB_TOKEN environment variable)"
    )
    
    return parser


def validate_args(args: argparse.Namespace) -> None:
    """Validate command-line arguments."""
    if not args.pin_actions and not args.scan_vulnerabilities:
        raise ValueError("At least one action must be specified: --pin-actions or --scan-vulnerabilities")
    
    if args.workflow_file and not args.workflow_file.exists():
        raise FileNotFoundError(f"Workflow file not found: {args.workflow_file}")
    
    if args.workflow_dir and not args.workflow_dir.exists():
        raise FileNotFoundError(f"Workflow directory not found: {args.workflow_dir}")


def process_workflows(
    workflow_files: List[Path],
    args: argparse.Namespace,
    github_api: GitHubAPI,
    trivy_scanner: Optional[TrivyScanner]
) -> dict:
    """Process workflow files and return results."""
    results = {
        "processed_files": [],
        "pinned_actions": [],
        "vulnerability_reports": [],
        "errors": []
    }
    
    parser = WorkflowParser()
    
    for workflow_file in workflow_files:
        logging.info(f"Processing workflow file: {workflow_file}")
        
        try:
            # Parse workflow
            workflow = parser.parse_workflow(workflow_file)
            
            file_result = {
                "file": str(workflow_file),
                "actions": workflow.actions,
                "pinned_actions": [],
                "vulnerabilities": []
            }
            
            # Pin actions if requested
            if args.pin_actions:
                pinned_actions = []
                modified_workflow = workflow
                
                for action in workflow.actions:
                    if action.needs_pinning():
                        try:
                            latest_sha = github_api.get_latest_sha(action.owner, action.repo, action.ref)
                            action.pin_to_sha(latest_sha)
                            pinned_actions.append({
                                "action": f"{action.owner}/{action.repo}",
                                "original_ref": action.original_ref,
                                "pinned_sha": latest_sha
                            })
                            logging.info(f"Pinned {action.owner}/{action.repo} to SHA: {latest_sha}")
                        except Exception as e:
                            logging.error(f"Failed to pin {action.owner}/{action.repo}: {e}")
                            results["errors"].append({
                                "file": str(workflow_file),
                                "action": f"{action.owner}/{action.repo}",
                                "error": str(e)
                            })
                
                file_result["pinned_actions"] = pinned_actions
                
                # Save modified workflow if not dry run
                if pinned_actions and not args.dry_run:
                    parser.save_workflow(workflow_file, modified_workflow)
            
            # Scan for vulnerabilities if requested
            if args.scan_vulnerabilities and trivy_scanner:
                for action in workflow.actions:
                    try:
                        vulnerabilities = trivy_scanner.scan_action(action.owner, action.repo, action.ref)
                        if vulnerabilities:
                            file_result["vulnerabilities"].extend(vulnerabilities)
                            logging.warning(f"Found {len(vulnerabilities)} vulnerabilities in {action.owner}/{action.repo}")
                    except Exception as e:
                        logging.error(f"Failed to scan {action.owner}/{action.repo}: {e}")
                        results["errors"].append({
                            "file": str(workflow_file),
                            "action": f"{action.owner}/{action.repo}",
                            "error": str(e)
                        })
            
            results["processed_files"].append(file_result)
            
        except Exception as e:
            logging.error(f"Failed to process {workflow_file}: {e}")
            results["errors"].append({
                "file": str(workflow_file),
                "error": str(e)
            })
    
    return results


def main() -> int:
    """Main entry point for the CLI."""
    parser = create_parser()
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(args.verbose)
    
    try:
        # Validate arguments
        validate_args(args)
        
        # Find workflow files
        if args.workflow_file:
            workflow_files = [args.workflow_file]
        else:
            workflow_files = find_workflow_files(args.workflow_dir)
            if not workflow_files:
                logging.error(f"No workflow files found in {args.workflow_dir}")
                return 1
        
        logging.info(f"Found {len(workflow_files)} workflow file(s) to process")
        
        # Initialize GitHub API
        github_api = GitHubAPI(token=args.github_token)
        
        # Initialize Trivy scanner if needed
        trivy_scanner = None
        if args.scan_vulnerabilities:
            trivy_scanner = TrivyScanner()
            if not trivy_scanner.check_trivy_installation():
                logging.error("Trivy is not installed or not accessible. Please install Trivy to scan for vulnerabilities.")
                return 1
        
        # Process workflows
        results = process_workflows(workflow_files, args, github_api, trivy_scanner)
        
        # Output results
        if args.output:
            import json
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            logging.info(f"Results saved to {args.output}")
        
        # Print summary
        print(f"\nSummary:")
        print(f"  Processed files: {len(results['processed_files'])}")
        
        if args.pin_actions:
            total_pinned = sum(len(f['pinned_actions']) for f in results['processed_files'])
            print(f"  Actions pinned: {total_pinned}")
        
        if args.scan_vulnerabilities:
            total_vulns = sum(len(f['vulnerabilities']) for f in results['processed_files'])
            print(f"  Vulnerabilities found: {total_vulns}")
        
        if results['errors']:
            print(f"  Errors: {len(results['errors'])}")
            for error in results['errors']:
                print(f"    - {error['file']}: {error['error']}")
        
        return 0 if not results['errors'] else 1
        
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        return 1
