#!/usr/bin/env python3
"""
ShadowHunt Gitleaks Scanner Module - Enhanced Version
Scans maintainer repositories for secrets using gitleaks with threading, fork detection, and size filtering
"""

import json
import os
import subprocess
import shutil
import sys
import requests
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass


@dataclass
class RepositoryInfo:
    """Information about a repository for scanning"""
    full_name: str  # owner/repo
    owner: str
    name: str
    maintainer_username: str
    repo_type: str  # 'personal' or 'organization'
    size_kb: int = 0
    is_fork: bool = False
    fork_parent: Optional[str] = None
    is_fork_of_master_org: bool = False
    default_branch: str = 'main'
    clone_url: str = ''
    scan_eligible: bool = True
    skip_reason: Optional[str] = None


class GitleaksScanner:
    def __init__(self, scan_base_dir: str = "./scans", github_token: str = None):
        self.scan_base_dir = Path(scan_base_dir)
        self.reports_dir = self.scan_base_dir
        self.max_repo_size_mb = 50  # Default size limit
        self.master_org = None  # Will be set from analysis data
        self.github_token = github_token
        
        # Statistics
        self.total_secrets_found = 0
        self.scanned_repos = 0
        self.failed_repos = 0
        self.skipped_repos = 0
        self.total_repos_analyzed = 0
        
        # GitHub API setup
        self.github_session = requests.Session()
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'Gitleaks-Scanner'
        }
        if self.github_token:
            headers['Authorization'] = f'token {self.github_token}'
        
        self.github_session.headers.update(headers)
        self.rate_limit_remaining = None
        self.rate_limit_reset = None
        
    def check_gitleaks_available(self) -> bool:
        """Check if gitleaks command is available in PATH"""
        try:
            result = subprocess.run(['gitleaks', 'version'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                print(f"✅ Gitleaks found: {result.stdout.strip()}")
                return True
            else:
                print("❌ Gitleaks command failed")
                return False
        except subprocess.TimeoutExpired:
            print("❌ Gitleaks command timed out")
            return False
        except FileNotFoundError:
            print("❌ Gitleaks not found in PATH")
            print("   Please install gitleaks: https://github.com/gitleaks/gitleaks")
            return False
        except Exception as e:
            print(f"❌ Error checking gitleaks: {e}")
            return False
    
    def check_github_rate_limit(self) -> bool:
        """Check GitHub API rate limit and display information"""
        try:
            print("🔍 Checking GitHub API rate limit...")
            response = self.github_session.get("https://api.github.com/rate_limit", timeout=10)
            
            if response.status_code == 200:
                rate_data = response.json()
                core_limit = rate_data.get('resources', {}).get('core', {})
                
                self.rate_limit_remaining = core_limit.get('remaining', 0)
                self.rate_limit_reset = core_limit.get('reset', 0)
                limit = core_limit.get('limit', 0)
                
                if self.github_token:
                    print(f"✅ GitHub API (Authenticated):")
                    print(f"   🎫 Rate limit: {self.rate_limit_remaining:,}/{limit:,} requests remaining")
                else:
                    print(f"⚠️  GitHub API (Unauthenticated):")
                    print(f"   🎫 Rate limit: {self.rate_limit_remaining:,}/{limit:,} requests remaining")
                    print(f"   💡 Consider using a GitHub token for higher limits")
                
                if self.rate_limit_remaining < 100:
                    reset_time = time.strftime('%H:%M:%S', time.localtime(self.rate_limit_reset))
                    print(f"   ⚠️  Warning: Low rate limit! Resets at {reset_time}")
                
                return True
            else:
                print(f"❌ Failed to check rate limit: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error checking rate limit: {e}")
            return False
    
    def get_repository_info(self, repo_full_name: str) -> Optional[Dict]:
        """Fetch repository information from GitHub API"""
        try:
            url = f"https://api.github.com/repos/{repo_full_name}"
            response = self.github_session.get(url, timeout=10)
            
            # Update rate limit info
            if 'X-RateLimit-Remaining' in response.headers:
                self.rate_limit_remaining = int(response.headers['X-RateLimit-Remaining'])
            if 'X-RateLimit-Reset' in response.headers:
                self.rate_limit_reset = int(response.headers['X-RateLimit-Reset'])
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return None  # Repo not found or private
            else:
                return None
        except Exception:
            return None
    
    def analyze_repository_metadata(self, repo_full_name: str, maintainer_username: str, repo_type: str) -> RepositoryInfo:
        """Analyze repository metadata including size and fork status"""
        if '/' not in repo_full_name:
            return RepositoryInfo(
                full_name=repo_full_name,
                owner='unknown',
                name=repo_full_name,
                maintainer_username=maintainer_username,
                repo_type=repo_type,
                scan_eligible=False,
                skip_reason="Invalid repository format"
            )
        
        owner, name = repo_full_name.split('/', 1)
        repo_info = RepositoryInfo(
            full_name=repo_full_name,
            owner=owner,
            name=name,
            maintainer_username=maintainer_username,
            repo_type=repo_type,
            clone_url=f"https://github.com/{repo_full_name}.git"
        )
        
        # Fetch repository metadata from GitHub API
        github_data = self.get_repository_info(repo_full_name)
        if not github_data:
            repo_info.scan_eligible = False
            repo_info.skip_reason = "Repository not accessible or private"
            return repo_info
        
        # Extract size (in KB)
        repo_info.size_kb = github_data.get('size', 0)
        
        # Extract fork information
        repo_info.is_fork = github_data.get('fork', False)
        if repo_info.is_fork and github_data.get('parent'):
            repo_info.fork_parent = github_data['parent']['full_name']
            # Check if it's a fork of the master organization
            if self.master_org and github_data['parent']['owner']['login'].lower() == self.master_org.lower():
                repo_info.is_fork_of_master_org = True
        
        # Extract default branch
        repo_info.default_branch = github_data.get('default_branch', 'main')
        
        # Check size eligibility
        size_mb = repo_info.size_kb / 1024
        if size_mb > self.max_repo_size_mb:
            repo_info.scan_eligible = False
            repo_info.skip_reason = f"Repository too large ({size_mb:.1f}MB > {self.max_repo_size_mb}MB limit)"
        
        return repo_info
    
    def prompt_size_threshold(self, total_repos: int, repo_sizes: List[Tuple[str, float]]) -> int:
        """Prompt user for repository size threshold"""
        print(f"\n📊 REPOSITORY SIZE ANALYSIS")
        print("="*60)
        
        # Show size distribution
        size_ranges = [
            (1, "< 1MB"),
            (5, "1-5MB"),
            (10, "5-10MB"),
            (25, "10-25MB"),
            (50, "25-50MB"),
            (100, "50-100MB"),
            (float('inf'), "> 100MB")
        ]
        
        print("Repository size distribution:")
        for max_size, label in size_ranges:
            count = sum(1 for _, size in repo_sizes if size <= max_size and (max_size == 1 or size > (max_size - 5 if max_size <= 50 else max_size - 50)))
            if max_size == 1:
                count = sum(1 for _, size in repo_sizes if size < 1)
            elif max_size == float('inf'):
                count = sum(1 for _, size in repo_sizes if size > 100)
            print(f"  {label:>8}: {count:>3} repositories")
        
        print(f"\nTotal repositories: {total_repos}")
        print(f"Largest repository: {max(repo_sizes, key=lambda x: x[1])[1]:.1f}MB ({max(repo_sizes, key=lambda x: x[1])[0]})")
        
        print(f"\n💡 RECOMMENDATIONS:")
        print(f"   • Small projects (≤10MB): Fast scanning, good for secrets detection")
        print(f"   • Medium projects (10-50MB): Moderate time, most development repos")
        print(f"   • Large projects (50-100MB): Slower scanning, may include assets")
        print(f"   • Very large (>100MB): Very slow, often data/media repositories")
        
        while True:
            try:
                user_input = input(f"\nEnter maximum repository size to scan in MB (recommended: 50): ").strip()
                if not user_input:
                    return 50  # Default
                
                size_limit = int(user_input)
                if size_limit <= 0:
                    print("Size limit must be positive")
                    continue
                
                eligible_count = sum(1 for _, size in repo_sizes if size <= size_limit)
                print(f"✅ Will scan {eligible_count}/{total_repos} repositories (≤{size_limit}MB)")
                return size_limit
                
            except ValueError:
                print("Please enter a valid number")
    
    def prompt_user_consent(self) -> bool:
        """Prompt user for consent to scan repositories"""
        print("\n" + "="*80)
        print("🔍 SHADOWHUNT GITLEAKS SECRET SCANNING - ENHANCED")
        print("="*80)
        print("This will:")
        print("  • Analyze repository metadata (size, fork status)")
        print("  • Clone maintainer repositories sequentially")
        print("  • Detect forks from the master organization")
        print("  • Filter repositories by size to optimize scanning")
        print("  • Scan each repository for exposed secrets using gitleaks")
        print("  • Show detailed secret information with GitHub links")
        print("  • Display file content and commit information")
        print()
        
        while True:
            response = input("Would you like to scan each maintainer's repositories for secrets using gitleaks? (y/n): ").strip().lower()
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no']:
                print("🚫 Gitleaks scanning skipped by user")
                return False
            else:
                print("Please enter 'y' for yes or 'n' for no")
    
    def parse_analysis_json(self, json_file: str) -> Optional[Dict]:
        """Parse the analysis JSON file"""
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if 'maintainers' not in data:
                print(f"❌ No 'maintainers' key found in {json_file}")
                return None
            
            # Extract master organization name for fork detection
            self.master_org = data.get('organization_name', 'Unknown')
                
            print(f"📋 Loaded analysis for {data.get('organization_name', 'Unknown Organization')}")
            print(f"   👥 Maintainers: {len(data['maintainers'])}")
            print(f"   🏢 Master organization: {self.master_org}")
            
            return data
        except FileNotFoundError:
            print(f"❌ Analysis file not found: {json_file}")
            return None
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in {json_file}: {e}")
            return None
        except Exception as e:
            print(f"❌ Error reading {json_file}: {e}")
            return None
    
    def setup_directories(self):
        """Create necessary directories for scanning"""
        try:
            self.scan_base_dir.mkdir(parents=True, exist_ok=True)
            print(f"📁 Scan directory: {self.scan_base_dir.absolute()}")
        except Exception as e:
            print(f"❌ Error creating scan directory: {e}")
            raise
    
    def gather_repository_info(self, maintainers: List[Dict]) -> List[RepositoryInfo]:
        """Gather repository information from all maintainers"""
        print(f"\n🔍 Analyzing repository metadata...")
        
        all_repos = []
        
        for maintainer in maintainers:
            username = maintainer.get('username', 'unknown')
            personal_repos = maintainer.get('personal_repositories', [])
            org_repos = maintainer.get('organization_repositories', [])
            
            print(f"  👤 {username}: {len(personal_repos)} personal + {len(org_repos)} org repos")
            
            # Process personal repositories
            for repo in personal_repos:
                if repo and '/' in repo:
                    repo_info = self.analyze_repository_metadata(repo, username, 'personal')
                    all_repos.append(repo_info)
            
            # Process organization repositories
            for repo in org_repos:
                if repo and '/' in repo:
                    repo_info = self.analyze_repository_metadata(repo, username, 'organization')
                    all_repos.append(repo_info)
            
            # Add small delay to avoid rate limiting
            time.sleep(0.1)
        
        return all_repos
    
    def clone_repository(self, repo_url: str, clone_path: Path) -> bool:
        """Clone a repository to the specified path"""
        try:
            # Remove existing directory if it exists
            if clone_path.exists():
                shutil.rmtree(clone_path)
            
            # Create parent directories
            clone_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Clone the repository
            result = subprocess.run([
                'git', 'clone', '--depth', '1', repo_url, str(clone_path)
            ], capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return True
            else:
                return False
                
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def run_gitleaks_scan(self, repo_path: Path, report_path: Path) -> bool:
        """Run gitleaks scan on a repository"""
        try:
            # Ensure report directory exists
            report_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Run gitleaks from the repository root
            result = subprocess.run([
                'gitleaks', 'detect', '-v',
                '--source', '.',
                '--report-format', 'json',
                '--report-path', str(report_path.absolute())
            ], cwd=str(repo_path), capture_output=True, text=True, timeout=600)
            
            # Gitleaks returns 1 if secrets are found, 0 if none found
            return result.returncode in [0, 1]
                
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False
    
    def get_current_commit_hash(self, repo_path: Path) -> str:
        """Get the current commit hash from the cloned repository"""
        try:
            result = subprocess.run([
                'git', 'rev-parse', 'HEAD'
            ], cwd=str(repo_path), capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                return "unknown"
        except Exception:
            return "unknown"
    
    def read_file_content(self, repo_path: Path, file_path: str, line_number: int) -> Tuple[str, List[str]]:
        """Read file content around the secret line"""
        try:
            full_file_path = repo_path / file_path
            if not full_file_path.exists():
                return "File not found", []
            
            with open(full_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Get lines around the secret (5 lines before and after)
            start_line = max(0, line_number - 6)  # -1 for 0-based indexing, -5 for context
            end_line = min(len(lines), line_number + 4)  # +4 for context after
            
            context_lines = []
            for i in range(start_line, end_line):
                line_num = i + 1
                line_content = lines[i].rstrip('\n\r')
                if line_num == line_number:
                    context_lines.append(f">>> {line_num:>3}: {line_content}")  # Mark the secret line
                else:
                    context_lines.append(f"    {line_num:>3}: {line_content}")
            
            return full_file_path.name, context_lines
        except Exception as e:
            return f"Error reading file: {e}", []
    
    def create_github_link(self, repo_full_name: str, commit_hash: str, file_path: str, line_number: int) -> str:
        """Create GitHub link to the specific file and line"""
        if commit_hash == "unknown":
            return f"https://github.com/{repo_full_name}/blob/main/{file_path}#L{line_number}"
        else:
            return f"https://github.com/{repo_full_name}/blob/{commit_hash}/{file_path}#L{line_number}"
    
    def analyze_gitleaks_report(self, report_path: Path) -> Tuple[int, List[Dict]]:
        """Analyze gitleaks report and return findings"""
        try:
            if not report_path.exists():
                return 0, []
            
            with open(report_path, 'r', encoding='utf-8') as f:
                report_data = json.load(f)
            
            if not report_data:
                return 0, []
            
            return len(report_data), report_data
            
        except json.JSONDecodeError:
            return 0, []
        except Exception:
            return 0, []
    
    def scan_single_repository(self, repo_info: RepositoryInfo) -> Dict:
        """Scan a single repository and show detailed results"""
        result = {
            'repo_info': repo_info,
            'success': False,
            'secrets_found': 0,
            'secrets_data': [],
            'error': None,
            'commit_hash': 'unknown'
        }
        
        try:
            clone_path = self.scan_base_dir / repo_info.maintainer_username / repo_info.owner / repo_info.name
            report_path = self.scan_base_dir / f"{repo_info.maintainer_username}__{repo_info.owner}__{repo_info.name}__report.json"
            
            # Progress update
            fork_indicator = " [FORK]" if repo_info.is_fork else ""
            master_fork_indicator = " [MASTER FORK]" if repo_info.is_fork_of_master_org else ""
            size_info = f" ({repo_info.size_kb/1024:.1f}MB)"
            
            print(f"  📦 {repo_info.full_name}{fork_indicator}{master_fork_indicator}{size_info}")
            
            # Clone repository
            if not self.clone_repository(repo_info.clone_url, clone_path):
                result['error'] = "Clone failed"
                self.failed_repos += 1
                print(f"    ❌ Clone failed")
                return result
            
            # Get commit hash
            commit_hash = self.get_current_commit_hash(clone_path)
            result['commit_hash'] = commit_hash
            
            # Run gitleaks scan
            if not self.run_gitleaks_scan(clone_path, report_path):
                result['error'] = "Gitleaks scan failed"
                self.failed_repos += 1
                print(f"    ❌ Gitleaks scan failed")
                return result
            
            # Analyze results
            secrets_count, secrets_data = self.analyze_gitleaks_report(report_path)
            result['success'] = True
            result['secrets_found'] = secrets_count
            result['secrets_data'] = secrets_data
            
            # Update statistics
            self.total_secrets_found += secrets_count
            self.scanned_repos += 1
            
            if secrets_count > 0:
                print(f"    🚨 {secrets_count} secret(s) found!")
                
                # Show detailed secrets immediately
                for i, secret in enumerate(secrets_data, 1):
                    rule_name = secret.get('RuleID', 'Unknown Rule')
                    file_path = secret.get('File', 'Unknown File')
                    line_number = secret.get('StartLine', 0)
                    secret_value = secret.get('Secret', 'Unknown Secret')
                    
                    print(f"\n    🚨 SECRET #{i}:")
                    print(f"       👤 Maintainer: {repo_info.maintainer_username}")
                    print(f"       📁 Repository: {repo_info.full_name}")
                    print(f"       🔑 Secret Value: {secret_value}")
                    print(f"       📝 Rule: {rule_name}")
                    print(f"       📄 File: {file_path}")
                    print(f"       📍 Line: {line_number}")
                    print(f"       🔗 Commit: {commit_hash}")
                    
                    # Create GitHub link
                    github_link = self.create_github_link(repo_info.full_name, commit_hash, file_path, line_number)
                    print(f"       🌐 GitHub Link: {github_link}")
                    
                    # Show file content
                    filename, context_lines = self.read_file_content(clone_path, file_path, line_number)
                    if context_lines:
                        print(f"       📖 File Content ({filename}):")
                        for line in context_lines:
                            print(f"           {line}")
                    else:
                        print(f"       📖 Could not read file content")
                    print()
                
            else:
                print(f"    ✅ No secrets found")
            
            # Clean up cloned repo to save space (but keep it temporarily for file reading)
            # We'll clean up later after all processing is done
            
            return result
            
        except Exception as e:
            result['error'] = str(e)
            self.failed_repos += 1
            print(f"    ❌ Error: {str(e)}")
            return result
    
    def print_detailed_secrets(self, scan_results: List[Dict]):
        """Print detailed information about found secrets"""
        if self.total_secrets_found == 0:
            return
        
        print(f"\n🚨 DETAILED SECRET FINDINGS:")
        print("="*80)
        
        for result in scan_results:
            if result['success'] and result['secrets_found'] > 0:
                repo_info = result['repo_info']
                secrets_data = result['secrets_data']
                
                fork_info = ""
                if repo_info.is_fork_of_master_org:
                    fork_info = f" [FORK OF {self.master_org}]"
                elif repo_info.is_fork:
                    fork_info = f" [FORK]"
                
                print(f"\n📁 {repo_info.full_name}{fork_info} ({repo_info.size_kb/1024:.1f}MB)")
                print(f"   👤 Maintainer: {repo_info.maintainer_username}")
                print(f"   🔍 Secrets found: {result['secrets_found']}")
                
                for i, secret in enumerate(secrets_data, 1):
                    rule_name = secret.get('RuleID', 'Unknown Rule')
                    file_path = secret.get('File', 'Unknown File')
                    line_number = secret.get('StartLine', 'Unknown Line')
                    
                    print(f"   [{i}] Rule: {rule_name}")
                    print(f"       File: {file_path}")
                    print(f"       Line: {line_number}")
                    
                    # Show secret excerpt if available (be careful not to expose actual secrets)
                    if 'Secret' in secret:
                        secret_preview = secret['Secret'][:20] + "..." if len(secret['Secret']) > 20 else secret['Secret']
                        print(f"       Preview: {secret_preview}")
                print()
    
    def print_final_summary(self, eligible_repos: List[RepositoryInfo], scan_results: List[Dict]):
        """Print final scanning summary"""
        print("\n" + "="*80)
        print("📋 GITLEAKS SCANNING COMPLETE")
        print("="*80)
        
        # Repository statistics
        total_repos = len(eligible_repos)
        scanned_count = sum(1 for r in scan_results if r['success'])
        failed_count = sum(1 for r in scan_results if not r['success'])
        skipped_count = self.skipped_repos
        
        print(f"📊 Repository Summary:")
        print(f"   📁 Total repositories analyzed: {self.total_repos_analyzed}")
        print(f"   ✅ Eligible for scanning: {total_repos}")
        print(f"   🔍 Successfully scanned: {scanned_count}")
        print(f"   ❌ Failed to scan: {failed_count}")
        print(f"   ⏭️  Skipped (size limit): {skipped_count}")
        
        # Secret findings
        print(f"\n🔍 Secret Detection:")
        print(f"   🚨 Total secrets found: {self.total_secrets_found}")
        
        if self.total_secrets_found > 0:
            # Fork analysis
            master_fork_secrets = sum(
                r['secrets_found'] for r in scan_results 
                if r['success'] and r['repo_info'].is_fork_of_master_org
            )
            other_fork_secrets = sum(
                r['secrets_found'] for r in scan_results 
                if r['success'] and r['repo_info'].is_fork and not r['repo_info'].is_fork_of_master_org
            )
            original_repo_secrets = sum(
                r['secrets_found'] for r in scan_results 
                if r['success'] and not r['repo_info'].is_fork
            )
            
            print(f"   🏢 Secrets in {self.master_org} forks: {master_fork_secrets}")
            print(f"   🍴 Secrets in other forks: {other_fork_secrets}")
            print(f"   📁 Secrets in original repos: {original_repo_secrets}")
            
            # Size analysis
            large_repo_secrets = sum(
                r['secrets_found'] for r in scan_results 
                if r['success'] and r['repo_info'].size_kb > 10*1024  # > 10MB
            )
            
            print(f"   📏 Secrets in large repos (>10MB): {large_repo_secrets}")
        
        print(f"\n📁 Reports saved in: {self.scan_base_dir.absolute()}")
        print(f"   Look for files ending with '__report.json'")
        
        if self.total_secrets_found > 0:
            print(f"\n🚨 ACTION REQUIRED: {self.total_secrets_found} secrets found!")
            print("   Review the detailed findings above and take appropriate action.")
        else:
            print(f"\n✅ No secrets detected in any scanned repositories!")
    
    def scan_from_analysis_file(self, json_file: str) -> bool:
        """Main function to scan repositories from analysis JSON file"""
        print("🚀 Starting ShadowHunt Enhanced Gitleaks Secret Scanning")
        
        # Check if user wants to proceed
        if not self.prompt_user_consent():
            return False
        
        # Check if gitleaks is available
        if not self.check_gitleaks_available():
            return False
        
        # Check GitHub rate limit
        if not self.check_github_rate_limit():
            print("⚠️  Proceeding without rate limit information")
        
        # Parse the analysis JSON
        analysis_data = self.parse_analysis_json(json_file)
        if not analysis_data:
            return False
        
        # Setup directories
        try:
            self.setup_directories()
        except Exception:
            return False
        
        # Gather repository information
        maintainers = analysis_data['maintainers']
        all_repo_info = self.gather_repository_info(maintainers)
        self.total_repos_analyzed = len(all_repo_info)
        
        print(f"\n📊 Repository Analysis Complete:")
        print(f"   📁 Total repositories found: {len(all_repo_info)}")
        
        # Debug: Show repository status breakdown
        accessible_count = 0
        size_limited_count = 0
        inaccessible_count = 0
        
        for repo in all_repo_info:
            if repo.scan_eligible:
                accessible_count += 1
            elif "Repository too large" in (repo.skip_reason or ""):
                size_limited_count += 1
            else:
                inaccessible_count += 1
        
        print(f"   ✅ Accessible repositories: {accessible_count}")
        print(f"   📏 Size-limited repositories: {size_limited_count}")
        print(f"   ❌ Inaccessible repositories: {inaccessible_count}")
        
        # Show size distribution and get user preference for accessible repos
        accessible_repos = [r for r in all_repo_info if r.scan_eligible or "Repository too large" in (r.skip_reason or "")]
        if accessible_repos:
            repo_sizes = [(r.full_name, r.size_kb / 1024) for r in accessible_repos]
            self.max_repo_size_mb = self.prompt_size_threshold(len(accessible_repos), repo_sizes)
        else:
            print("⚠️  No accessible repositories found, using default size limit")
        
        # Filter repositories based on size and eligibility
        eligible_repos = []
        for repo in all_repo_info:
            size_mb = repo.size_kb / 1024
            
            # Debug output for first few repos
            if len(eligible_repos) < 5:
                print(f"   🔍 Debug: {repo.full_name} - Eligible: {repo.scan_eligible}, Size: {size_mb:.1f}MB, Reason: {repo.skip_reason}")
            
            if not repo.scan_eligible and "Repository too large" not in (repo.skip_reason or ""):
                self.skipped_repos += 1
                continue
            elif size_mb > self.max_repo_size_mb:
                self.skipped_repos += 1
                continue
            else:
                eligible_repos.append(repo)
        
        print(f"   🎯 Eligible for scanning: {len(eligible_repos)}")
        
        if not eligible_repos:
            print("❌ No repositories eligible for scanning!")
            print("   This might be due to:")
            print("   • All repositories are private/inaccessible")
            print("   • All repositories exceed the size limit")
            print("   • GitHub API rate limit issues")
            return False
        
        print(f"\n🎯 Starting sequential scanning of {len(eligible_repos)} repositories...")
        print(f"   📏 Size limit: {self.max_repo_size_mb}MB")
        
        # Scan repositories sequentially
        scan_results = []
        try:
            for i, repo in enumerate(eligible_repos, 1):
                print(f"\n[{i}/{len(eligible_repos)}] Scanning repository...")
                try:
                    result = self.scan_single_repository(repo)
                    scan_results.append(result)
                    
                    # Clean up after each repo to save space
                    clone_path = self.scan_base_dir / repo.maintainer_username / repo.owner / repo.name
                    try:
                        if clone_path.exists():
                            shutil.rmtree(clone_path)
                    except Exception:
                        pass  # Ignore cleanup errors
                        
                except Exception as e:
                    print(f"❌ Unexpected error scanning {repo.full_name}: {e}")
                    self.failed_repos += 1
                        
        except KeyboardInterrupt:
            print(f"\n🛑 Scanning interrupted by user")
            return False
        
        # Print final summary
        self.print_final_summary(eligible_repos, scan_results)
        
        return True


def main():
    """Main function for standalone usage"""
    if len(sys.argv) < 2:
        print("Usage: python shadowhunt_scanner.py <analysis_json_file> [github_token]")
        print("Example: python shadowhunt_scanner.py analysis_mozilla_20240124.json")
        print("Example: python shadowhunt_scanner.py analysis_mozilla_20240124.json ghp_xxxxxxxxxxxx")
        print("Or set GITHUB_TOKEN environment variable")
        sys.exit(1)
    
    json_file = sys.argv[1]
    
    # Get GitHub token from command line or environment
    github_token = None
    if len(sys.argv) > 2:
        github_token = sys.argv[2]
    else:
        github_token = os.environ.get('GITHUB_TOKEN')
    
    scanner = GitleaksScanner(github_token=github_token)
    
    success = scanner.scan_from_analysis_file(json_file)
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()