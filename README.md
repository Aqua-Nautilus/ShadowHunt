# ShadowHunt

Advanced GitHub Shadow IT & Secret Hunter with threading, commit tracking, and organization filtering.

## Overview

ShadowHunt identifies security risks in your organization by discovering employees' personal GitHub repositories and scanning them for exposed secrets. With enhanced threading capabilities and smart filtering, it efficiently processes large organizations while providing detailed commit-level analysis.

## Key Features

- **🚀 Multi-threaded Performance**: Concurrent repository fetching and scanning
- **📅 Commit Date Tracking**: Track when secrets were committed using git blame
- **🏢 Organization Email Filtering**: Focus on company employees vs external contributors  
- **🔍 Smart Deduplication**: Thread-safe duplicate secret detection across files
- **📊 Comprehensive Analysis**: Analyze all maintainers (no artificial limits)
- **⚡ Rate Limit Handling**: Automatic GitHub API rate limit management
- **🎯 Interactive Filtering**: Choose organization domains and contributor scope

## Quick Start

### Prerequisites
```bash
# Install gitleaks
brew install gitleaks  # macOS
# or download from https://github.com/gitleaks/gitleaks/releases

# Ensure git is available
git --version
```

### Run Analysis
```bash
python shadowhunt.py
```

The tool will prompt for:
- GitHub token (requires `public_repo` scope)
- Target organization/user
- Repository and commit limits
- Organization domain selection
- Maintainer filtering options

## Advanced Workflow

### 1. Contributor Discovery
- Fetches organization repositories with threading (5 workers)
- Analyzes commit history across all repos
- Identifies maintainers based on commit patterns and email domains
- Auto-detects organization domains from email patterns

### 2. Smart Filtering Options
```
👥 DOMAIN SELECTION FOR FILTERING
1. example.com (15 contributors)
2. All domains (87 contributors)
Choose option (1-2):

👥 MAINTAINER SCOPE SELECTION  
1. Scan organization maintainers only (15 users with @example.com)
2. Scan all maintainers (87 users total)
Choose option (1-2):
```

### 3. Secret Scanning
- Multi-threaded repository cloning with `--mirror` flag
- Concurrent gitleaks scanning (3 workers)
- Commit date extraction using `git blame`
- Date-based filtering for recent secrets
- Thread-safe deduplication prevents duplicate results

## Enhanced Output

```
🚨 SECRET FINDINGS WITH COMMIT DETAILS:

📁 Repository: john-doe/backup-scripts
🔑 Secret: AWS Access Key (high)
📄 File: config/aws.py:23
📅 Commit Date: 2024-01-15 14:30:22
🔗 Commit: https://github.com/john-doe/backup-scripts/commit/abc123...
👤 Author: john.doe@company.com
🏢 Organization: company-org

📊 SCAN RESULTS:
   🔍 Repositories scanned: 147
   🚨 Secrets found: 12  
   📅 Date range: 2024-01-01 to present
   ⚡ Processing time: 3m 42s
```

## Configuration Options

### Repository Limits
- **Max repositories**: Control how many repos to analyze
- **Max commits per repo**: Limit commit history depth
- **Date filtering**: Show only secrets from specific dates

### Threading Configuration
- **Repository fetching**: 5 concurrent workers
- **Secret scanning**: 3 concurrent workers  
- **Rate limiting**: Automatic API throttling

### Output Formats
- **Console display**: Real-time results with commit details
- **JSON export**: Structured data with timestamps
- **HTML visualization**: Interactive network graphs

## Files

- **`shadowhunt.py`**: Main contributor analysis engine
- **`shadowhunt_scanner.py`**: Multi-threaded secret scanning with git integration
- **`dynamic_cytoscape_graph.html`**: Interactive visualization template
- **`latest_analysis.json`**: Most recent analysis results
- **`analysis_[org]_[timestamp].json`**: Timestamped analysis exports

## Technical Requirements

- **Python 3.8+** with threading support
- **Git 2.0+** with blame functionality
- **[Gitleaks](https://github.com/gitleaks/gitleaks)** for secret detection
- **GitHub token** with `public_repo` scope (no admin required)
- **Network access** for GitHub API and git operations

## Performance Features

### Threading Architecture
- Concurrent repository metadata fetching
- Parallel git cloning with progress tracking
- Multi-threaded gitleaks execution
- Thread-safe result collection

### Memory Optimization
- Streaming JSON processing
- Efficient git mirror cloning
- Automatic cleanup of temporary repositories
- Rate-limited API calls to prevent throttling

### Error Handling
- Robust retry mechanisms for network failures
- Graceful handling of private/deleted repositories
- Comprehensive error logging with context
- Automatic recovery from API rate limits

## Defensive Security Use

This tool is designed exclusively for legitimate security assessments:

- ✅ **Authorized assessments** of your own organization
- ✅ **Defensive security** research and vulnerability discovery  
- ✅ **Compliance auditing** for exposed credentials
- ✅ **Shadow IT discovery** within your company

- ❌ **Unauthorized scanning** of external organizations
- ❌ **Malicious reconnaissance** or data harvesting
- ❌ **Violation** of GitHub Terms of Service
- ❌ **Scanning without explicit permission**

Always obtain proper authorization and respect rate limits, privacy, and legal boundaries.