# ShadowHunt

Find secrets hidden in employees' personal GitHub repositories.

## What is Shadow IT?

Employees use personal GitHub accounts for company work, creating security blind spots. ShadowHunt discovers these hidden repositories and scans them for leaked secrets (API keys, passwords, tokens).

## Quick Start

```bash
# Install gitleaks
brew install gitleaks  # macOS
# or download from https://github.com/gitleaks/gitleaks/releases

# Run ShadowHunt
python shadowhunt.py
```

Enter your GitHub token and target organization when prompted.

## How It Works

1. **Find Contributors**: Analyzes organization repos to find employee GitHub accounts
2. **Map Personal Repos**: Discovers employees' personal repositories  
3. **Scan for Secrets**: Uses gitleaks to find exposed credentials

## Example Output

```
🚨 SECRET FINDINGS:
   🔑 AWS Access Key in john-doe/backup-scripts/config.py
   🔑 Database password in jane-smith/test-env/.env
   🔑 API token in dev-user/personal-tools/settings.json

📊 Results: 89 repos scanned, 12 secrets found
```

## Files

- `shadowhunt.py` - Main analysis tool
- `shadowhunt_scanner.py` - Secret scanning module  
- `dynamic_cytoscape_graph.html` - Visualization template

## Requirements

- Python 3.8+
- Git
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- GitHub token with `public_repo` scope

## Defensive Use Only

This tool is for legitimate security assessments of your own organization only. Respect GitHub's ToS and get proper authorization.