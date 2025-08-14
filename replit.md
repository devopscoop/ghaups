# Overview

This is ghaups (GitHub Actions Update, Pin, and Scan), a Python-based security tool designed to analyze GitHub Actions workflows for security vulnerabilities and best practices. The tool focuses on two main security features: automatically pinning GitHub Actions to specific SHA commits (preventing supply chain attacks) and scanning action repositories for known vulnerabilities using Trivy. It provides a command-line interface for processing individual workflow files or entire directories containing GitHub Actions workflows.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Core Components

**Modular Python Architecture**: The application follows a clean modular design with separate components for different responsibilities:
- CLI module handles command-line interface and argument parsing
- Workflow parser processes YAML workflow files using PyYAML
- GitHub API client manages authentication and rate limiting for GitHub API calls
- Trivy scanner integrates with external Trivy tool for vulnerability scanning
- Models define data structures for Actions, Workflows, and Vulnerabilities
- Utilities provide common functionality like logging and file discovery

**Command-Line Interface**: Built using Python's argparse library, supporting mutually exclusive input options (single file vs directory scanning) and various action flags for pinning actions and vulnerability scanning.

**Data Flow Architecture**: The tool processes workflows in a pipeline:
1. Parse YAML workflow files to extract action references
2. Resolve action versions using GitHub API to get specific SHA commits
3. Optionally scan action repositories for vulnerabilities using Trivy
4. Generate reports and modify workflow files with pinned versions

**Error Handling and Logging**: Comprehensive logging system with configurable verbosity levels, proper exception handling throughout the workflow processing pipeline.

## Security Design Patterns

**Action Pinning Strategy**: Converts semantic version references (like @v3) to specific SHA commits to prevent supply chain attacks where action maintainers could modify tagged versions. Preserves original version information in comments for maintainability (e.g., `actions/checkout@f43a0e5f... # v3`).

**Rate Limiting**: GitHub API client implements proper rate limiting to respect GitHub's API limits, with automatic backoff and retry mechanisms.

**Backup Support**: Creates backups of original workflow files before modification to ensure recovery capability.

# External Dependencies

**GitHub API**: Uses GitHub's REST API v3 to resolve action versions and retrieve commit SHAs. Supports authentication via GitHub tokens for higher rate limits.

**Trivy Security Scanner**: Integrates with Aqua Security's Trivy tool for vulnerability scanning of action repositories. Requires Trivy to be installed separately on the system.

**PyYAML Library**: Handles parsing and manipulation of GitHub Actions workflow YAML files.

**Requests Library**: Manages HTTP communication with GitHub API, including session handling and authentication headers.

**Python Standard Library**: Leverages subprocess for Trivy integration, pathlib for file operations, logging for comprehensive logging, and argparse for CLI functionality.