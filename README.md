# ghaups (GitHub Actions Update, Pin, and Scan)

A Python security tool that analyzes GitHub Actions workflows, pins actions to specific SHAs, and scans for vulnerabilities using Trivy.

## Features

- **Workflow Analysis**: Parse GitHub Actions workflow YAML files
- **Action Pinning**: Automatically pin actions to specific SHA commits for security with version comments (e.g., `actions/checkout@f43a0e5f... # v3`)
- **Vulnerability Scanning**: Integrate with Trivy to scan action repositories for vulnerabilities
- **Backup Support**: Create backups of original workflow files before modification
- **GitHub API Integration**: Resolve action versions using GitHub API
- **Command-line Interface**: Easy-to-use CLI with comprehensive options

## Installation

1. **Clone the repository**:
   ```bash
   git clone <repository-url>
   cd ghaups
   ```

2. **Install Python dependencies**:
   ```bash
   pip install PyYAML requests
   ```

3. **Install Trivy** (required for vulnerability scanning):
   
   **Linux**:
   ```bash
   sudo apt-get install wget apt-transport-https gnupg lsb-release
   wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
   echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
   sudo apt-get update
   sudo apt-get install trivy
   ```
   
   **macOS**:
   ```bash
   brew install trivy
   ```
   
   **Windows**:
   Download from [Trivy releases](https://github.com/aquasecurity/trivy/releases)

4. **Set up GitHub token** (optional but recommended):
   ```bash
   export GITHUB_TOKEN=your_github_token_here
   ```

## Usage

### Basic Examples

**Pin actions in a single workflow file**:
```bash
python main.py --workflow-file .github/workflows/ci.yml --pin-actions
