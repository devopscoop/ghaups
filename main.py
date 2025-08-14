#!/usr/bin/env python3
"""
ghaups (GitHub Actions Update, Pin, and Scan) - Main Entry Point
"""

import sys
from github_actions_security.cli import main

if __name__ == "__main__":
    sys.exit(main())
