# Brewfile for ghaups
#
# Installs every CLI tool used or referenced by this repo.
# Usage: brew bundle

# git - the release/tagging flow in AGENTS.md
brew "git"

# pre-commit - hooks referenced in AGENTS.md enforce SHA pinning and other policies
brew "pre-commit"

# trivy - vulnerability scanning of action repos (ghaups.py shells out to it;
# skippable with --no-scan). Not a Python dependency, must be installed separately.
brew "trivy"

# uv - runs the tool (`uv run ghaups.py ...`); manages Python (>=3.11) and the
# requests dependency via uv.lock
brew "uv"

# zizmor - GitHub Actions workflow auditing, referenced in AGENTS.md
brew "zizmor"
