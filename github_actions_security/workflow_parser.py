"""
GitHub Actions workflow parser module
"""

import yaml
from pathlib import Path
from typing import List, Dict, Any
import logging

from .models import Action, Workflow


class WorkflowParser:
    """Parser for GitHub Actions workflow files."""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def parse_workflow(self, workflow_path: Path) -> Workflow:
        """Parse a workflow file and extract actions."""
        try:
            with open(workflow_path, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
            
            if not content:
                raise ValueError("Empty workflow file")
            
            actions = self._extract_actions(content)
            workflow_name = content.get('name', workflow_path.stem)
            
            return Workflow(workflow_name, content, actions)
            
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML in workflow file: {e}")
        except Exception as e:
            raise RuntimeError(f"Failed to parse workflow file: {e}")
    
    def _extract_actions(self, content: Dict[Any, Any]) -> List[Action]:
        """Extract all action references from workflow content."""
        actions = []
        
        if 'jobs' not in content:
            return actions
        
        for job_name, job in content['jobs'].items():
            if not isinstance(job, dict) or 'steps' not in job:
                continue
            
            for step in job['steps']:
                if not isinstance(step, dict) or 'uses' not in step:
                    continue
                
                uses = step['uses']
                if isinstance(uses, str):
                    action = Action(uses)
                    if action.is_github_action:
                        actions.append(action)
                        self.logger.debug(f"Found action: {action}")
        
        return actions
    
    def save_workflow(self, workflow_path: Path, workflow: Workflow) -> None:
        """Save the modified workflow back to file."""
        try:
            # Get modified content
            modified_content = self._get_modified_content_with_comments(workflow, workflow_path)
            
            # Write back to file
            with open(workflow_path, 'w', encoding='utf-8') as f:
                f.write(modified_content)
            
            self.logger.info(f"Updated workflow file: {workflow_path}")
            
        except Exception as e:
            raise RuntimeError(f"Failed to save workflow file: {e}")
    
    def _get_modified_content_with_comments(self, workflow: Workflow, original_path: Path) -> str:
        """Get modified workflow content while preserving comments and formatting."""
        # Read original file content
        with open(original_path, 'r', encoding='utf-8') as f:
            original_lines = f.readlines()
        
        # Create mapping of old uses to new uses
        uses_mapping = {}
        for action in workflow.actions:
            if action.original_uses != action.get_pinned_uses():
                uses_mapping[action.original_uses] = action.get_pinned_uses()
        
        # Replace uses lines while preserving formatting
        modified_lines = []
        for line in original_lines:
            modified_line = line
            for old_uses, new_uses in uses_mapping.items():
                if f"uses: {old_uses}" in line:
                    modified_line = line.replace(f"uses: {old_uses}", f"uses: {new_uses}")
                elif f'uses: "{old_uses}"' in line:
                    modified_line = line.replace(f'uses: "{old_uses}"', f'uses: "{new_uses}"')
                elif f"uses: '{old_uses}'" in line:
                    modified_line = line.replace(f"uses: '{old_uses}'", f"uses: '{new_uses}'")
            
            modified_lines.append(modified_line)
        
        return ''.join(modified_lines)