#!/usr/bin/env python3
"""
ShadowHunt - Uncovering Shadow IT and Hidden Secrets
Clean, organized tool for analyzing GitHub organization contributors and discovering hidden personal repositories
"""

import requests
import json
import time
from collections import defaultdict
from datetime import datetime
import getpass
import sys
import webbrowser
import os
import shutil
from typing import Dict, List, Tuple, Optional

# Import the gitleaks scanner
try:
    from shadowhunt_scanner import GitleaksScanner
except ImportError:
    print("⚠️  Gitleaks scanner module not found. Secret scanning will be unavailable.")
    GitleaksScanner = None


class GitHubContributorAnalyzer:
    def __init__(self, token: str):
        self.token = token
        self.headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'GitHub-Contributor-Analyzer'
        }
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self.rate_limit_remaining = 5000
        self.rate_limit_reset = None
        
    def make_request(self, url: str, params: dict = None) -> Optional[dict]:
        """Make API request with rate limiting"""
        if self.rate_limit_remaining < 100 and self.rate_limit_reset:
            wait_time = max(0, self.rate_limit_reset - time.time() + 10)
            if wait_time > 0:
                print(f"⏳ Rate limit low. Waiting {wait_time:.0f} seconds...")
                time.sleep(wait_time)
        
        try:
            response = self.session.get(url, params=params, timeout=30)
            self.rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
            self.rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))
            
            if response.status_code != 200:
                return None
            return response.json()
        except Exception:
            return None
    
    def validate_token(self) -> bool:
        """Validate GitHub token"""
        print("🔐 Validating GitHub token...")
        user_data = self.make_request("https://api.github.com/user")
        if user_data:
            print(f"✅ Token valid! Authenticated as: {user_data.get('login', 'Unknown')}")
            return True
        print("❌ Invalid GitHub token!")
        return False
    
    def fetch_all_pages(self, base_url: str, params: dict, max_pages: int = 20) -> List[dict]:
        """Fetch all pages from a paginated API endpoint"""
        all_items = []
        page = 1
        
        while page <= max_pages:
            page_params = {**params, 'page': page, 'per_page': 100}
            data = self.make_request(base_url, page_params)
            
            if not data or len(data) == 0:
                break
                
            all_items.extend(data)
            page += 1
            
            if len(data) < 100:  # Last page
                break
                
        return all_items
    
    def get_organization_repos(self, org_name: str, max_repos: int = 100) -> List[dict]:
        """Get repositories for an organization"""
        print(f"📂 Fetching repositories for organization: {org_name}")
        url = f"https://api.github.com/orgs/{org_name}/repos"
        params = {'type': 'all', 'sort': 'updated'}
        repos = self.fetch_all_pages(url, params, max_pages=10)
        
        # Filter out forks
        non_fork_repos = [repo for repo in repos if not repo.get('fork', False)]
        result = non_fork_repos[:max_repos]
        print(f"✅ Found {len(result)} repositories")
        return result
    
    def get_user_repos(self, username: str, max_repos: int = 100) -> List[dict]:
        """Get repositories for a user"""
        print(f"👤 Fetching repositories for user: {username}")
        url = f"https://api.github.com/users/{username}/repos"
        params = {'type': 'owner', 'sort': 'updated'}
        repos = self.fetch_all_pages(url, params, max_pages=10)
        result = repos[:max_repos]
        print(f"✅ Found {len(result)} repositories")
        return result
    
    def should_filter_user(self, username: str) -> bool:
        """Check if user should be filtered out"""
        if not username:
            return True
        
        username_lower = username.lower()
        
        # Filter dependabot and gitstart users
        if username_lower == "dependabot[bot]" or username_lower.startswith("gitstart"):
            return True
            
        return False

    def analyze_repository_contributors(self, repo_full_name: str, max_commits: int = 1000) -> Dict[str, dict]:
        """Analyze contributors for a single repository"""
        print(f"  🔍 Analyzing: {repo_full_name}")
        
        contributors = defaultdict(lambda: {
            'commits': 0, 'emails': set(), 'repositories': set(),
            'first_commit': None, 'last_commit': None
        })
        
        url = f"https://api.github.com/repos/{repo_full_name}/commits"
        commits = self.fetch_all_pages(url, {}, max_pages=max_commits // 100)
        
        filtered_count = 0
        for commit in commits[:max_commits]:
            author = commit.get('author')
            commit_data = commit.get('commit', {})
            author_data = commit_data.get('author', {})
            
            if author and author.get('login'):
                username = author['login']
                
                # Filter out unwanted users
                if self.should_filter_user(username):
                    filtered_count += 1
                    continue
                
                email = author_data.get('email', '').strip().lower()
                commit_date = author_data.get('date')
                
                contributors[username]['commits'] += 1
                contributors[username]['repositories'].add(repo_full_name)
                
                if email and email != 'noreply@github.com':
                    contributors[username]['emails'].add(email)
                
                if commit_date:
                    if not contributors[username]['first_commit'] or commit_date < contributors[username]['first_commit']:
                        contributors[username]['first_commit'] = commit_date
                    if not contributors[username]['last_commit'] or commit_date > contributors[username]['last_commit']:
                        contributors[username]['last_commit'] = commit_date
        
        filtered_msg = f" (filtered {filtered_count} bot/automated commits)" if filtered_count > 0 else ""
        print(f"    ✅ Found {len(contributors)} contributors{filtered_msg}")
        return contributors
    
    def analyze_target(self, target: str, max_repos: int = 50, max_commits_per_repo: int = 1000) -> Dict[str, dict]:
        """Analyze contributors for an organization or user"""
        # Auto-detect target type
        org_data = self.make_request(f"https://api.github.com/orgs/{target}")
        if org_data:
            print(f"🏢 Detected organization: {org_data.get('name', target)}")
            repos = self.get_organization_repos(target, max_repos)
        else:
            user_data = self.make_request(f"https://api.github.com/users/{target}")
            if user_data:
                print(f"👤 Detected user: {user_data.get('name', target)}")
                repos = self.get_user_repos(target, max_repos)
            else:
                print(f"❌ Could not find: {target}")
                return {}
        
        if not repos:
            return {}
        
        # Analyze contributors across all repositories
        all_contributors = defaultdict(lambda: {
            'commits': 0, 'emails': set(), 'repositories': set(),
            'first_commit': None, 'last_commit': None
        })
        
        print(f"\n🔬 Analyzing contributors across {len(repos)} repositories...")
        for i, repo in enumerate(repos, 1):
            print(f"[{i}/{len(repos)}] {repo['full_name']}")
            repo_contributors = self.analyze_repository_contributors(repo['full_name'], max_commits_per_repo)
            
            # Merge contributor data
            for username, data in repo_contributors.items():
                all_contributors[username]['commits'] += data['commits']
                all_contributors[username]['emails'].update(data['emails'])
                all_contributors[username]['repositories'].update(data['repositories'])
                
                if data['first_commit']:
                    if not all_contributors[username]['first_commit'] or data['first_commit'] < all_contributors[username]['first_commit']:
                        all_contributors[username]['first_commit'] = data['first_commit']
                if data['last_commit']:
                    if not all_contributors[username]['last_commit'] or data['last_commit'] > all_contributors[username]['last_commit']:
                        all_contributors[username]['last_commit'] = data['last_commit']
        
        return all_contributors
    
    def get_email_domains(self, contributors: Dict[str, dict]) -> Dict[str, List[str]]:
        """Get email domain mapping"""
        domain_users = defaultdict(list)
        for username, data in contributors.items():
            for email in data['emails']:
                if '@' in email:
                    domain = email.split('@')[1].lower()
                    domain_users[domain].append(username)
        return domain_users
    
    def identify_company_domain(self, contributors: Dict[str, dict]) -> Optional[str]:
        """Identify the most likely company domain"""
        domain_users = self.get_email_domains(contributors)
        excluded_domains = {
            'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
            'users.noreply.github.com', 'noreply.github.com',
            'googlemail.com', 'icloud.com', 'protonmail.com'
        }
        
        company_domains = {
            domain: len(users) for domain, users in domain_users.items()
            if domain not in excluded_domains and len(users) >= 2
        }
        
        return max(company_domains.items(), key=lambda x: x[1])[0] if company_domains else None
    
    def identify_maintainers(self, contributors: Dict[str, dict], company_domain: Optional[str] = None) -> List[Tuple[str, dict]]:
        """Identify likely maintainers"""
        maintainer_candidates = []
        commit_counts = [data['commits'] for data in contributors.values()]
        avg_commits = sum(commit_counts) / len(commit_counts) if commit_counts else 0
        high_commit_threshold = max(avg_commits * 2, 50)
        
        for username, data in contributors.items():
            is_maintainer = False
            reasons = []
            
            if data['commits'] >= high_commit_threshold:
                is_maintainer = True
                reasons.append(f"High commits ({data['commits']})")
            
            if len(data['repositories']) >= 3:
                is_maintainer = True
                reasons.append(f"Multiple repos ({len(data['repositories'])})")
            
            if company_domain:
                has_company_email = any(company_domain in email.lower() for email in data['emails'])
                if has_company_email and data['commits'] >= 10:
                    is_maintainer = True
                    reasons.append(f"Company email (@{company_domain})")
            
            if is_maintainer:
                data_copy = dict(data)
                data_copy['maintainer_reasons'] = reasons
                maintainer_candidates.append((username, data_copy))
        
        return sorted(maintainer_candidates, key=lambda x: x[1]['commits'], reverse=True)
    
    def get_user_repositories(self, username: str) -> Dict[str, List[str]]:
        """Get user's repositories separated by personal vs organization"""
        url = f"https://api.github.com/users/{username}/repos"
        # Use 'all' to get both personal and organization repositories
        repos = self.fetch_all_pages(url, {'type': 'all'}, max_pages=10)
        
        personal_repos = []
        org_repos = []
        
        for repo in repos:
            if repo['owner']['login'] == username:
                personal_repos.append(f"{username}/{repo['name']}")
            else:
                org_repos.append(f"{repo['owner']['login']}/{repo['name']}")
        
        return {
            'personal': personal_repos,
            'organization': org_repos,
            'total': len(repos)
        }
    
    def print_summary(self, contributors: Dict[str, dict], target: str, company_domain: Optional[str]):
        """Print analysis summary"""
        domain_users = self.get_email_domains(contributors)
        total_repos = len(set().union(*(data['repositories'] for data in contributors.values())))
        
        print(f"\n📋 ANALYSIS SUMMARY:")
        print(f"   👥 Total contributors: {len(contributors):,}")
        print(f"   📁 Total repositories: {total_repos:,}")
        
        if company_domain:
            company_count = len(domain_users.get(company_domain, []))
            print(f"   🏢 Company domain: {company_domain}")
            print(f"   📧 Company emails: {company_count}/{len(contributors)} ({company_count/len(contributors)*100:.1f}%)")
        else:
            print(f"   🏢 No company domain identified")
    
    def print_contributors(self, contributors: Dict[str, dict], company_domain: Optional[str]):
        """Print all contributors sorted by commits"""
        sorted_contributors = sorted(contributors.items(), key=lambda x: x[1]['commits'], reverse=True)
        
        print(f"\n🏆 ALL CONTRIBUTORS (sorted by commits):")
        print("-" * 100)
        print(f"{'Rank':<4} {'Username':<20} {'Commits':<8} {'Repos':<6} {'Emails':<6} {'Email Addresses'}")
        print("-" * 100)
        
        for i, (username, data) in enumerate(sorted_contributors, 1):
            emails_str = ', '.join(list(data['emails'])[:2])
            if len(data['emails']) > 2:
                emails_str += f" (+{len(data['emails'])-2} more)"
            
            has_company_email = company_domain and any(company_domain in email.lower() for email in data['emails'])
            username_display = f"🏢 {username}" if has_company_email else username
            
            print(f"{i:<4} {username_display:<20} {data['commits']:<8} {len(data['repositories']):<6} {len(data['emails']):<6} {emails_str}")
    
    def print_domains(self, contributors: Dict[str, dict], company_domain: Optional[str]):
        """Print email domain analysis"""
        domain_users = self.get_email_domains(contributors)
        filtered_domains = {domain: users for domain, users in domain_users.items() if len(users) >= 2}
        sorted_domains = sorted(filtered_domains.items(), key=lambda x: len(x[1]), reverse=True)
        
        print(f"\n📧 EMAIL DOMAINS (2+ users):")
        print("-" * 70)
        print(f"{'Domain':<30} {'Users':<6} {'Usernames'}")
        print("-" * 70)
        
        for domain, users in sorted_domains:
            users_str = ', '.join(users)
            domain_display = f"🏢 {domain}" if domain == company_domain else domain
            print(f"{domain_display:<30} {len(users):<6} {users_str}")
    
    def print_user_repositories(self, contributors: Dict[str, dict]):
        """Print repository lists for top contributors"""
        if not hasattr(self, 'token'):
            return
            
        sorted_contributors = sorted(contributors.items(), key=lambda x: x[1]['commits'], reverse=True)
        top_contributors = sorted_contributors[:10]
        
        print(f"\n📁 USER REPOSITORIES:")
        print("="*60)
        
        for i, (username, data) in enumerate(top_contributors, 1):
            print(f"\n👤 {i}. {username}")
            print(f"   📧 {', '.join(list(data['emails'])[:1])}")
            
            try:
                repos_data = self.get_user_repositories(username)
                personal_repos = repos_data['personal']
                org_repos = repos_data['organization']
                total_repos = repos_data['total']
                
                print(f"   📊 Total repositories: {total_repos}")
                print(f"       👤 Personal: {len(personal_repos)}")
                print(f"       🏢 Organization: {len(org_repos)}")
                
                if personal_repos:
                    personal_list = ', '.join(personal_repos)
                    print(f"   👤 Personal repos: {personal_list}")
                else:
                    print(f"   👤 Personal repos: None")
                
                if org_repos:
                    org_list = ', '.join(org_repos)
                    print(f"   🏢 Organization repos: {org_list}")
                else:
                    print(f"   🏢 Organization repos: None")
                    
            except Exception as e:
                print(f"   ❌ Error: {str(e)[:50]}...")
            
            if i < len(top_contributors):
                time.sleep(0.3)
    
    def print_results(self, contributors: Dict[str, dict], target: str):
        """Print all results"""
        if not contributors:
            print("❌ No contributors found!")
            return
        
        print(f"\n" + "="*80)
        print(f"📊 CONTRIBUTOR ANALYSIS FOR: {target.upper()}")
        print(f"="*80)
        
        company_domain = self.identify_company_domain(contributors)
        
        self.print_summary(contributors, target, company_domain)
        self.print_contributors(contributors, company_domain)
        self.print_domains(contributors, company_domain)
        self.print_user_repositories(contributors)
    
    def save_results(self, contributors: Dict[str, dict], target: str):
        """Save results to JSON"""
        company_domain = self.identify_company_domain(contributors)
        maintainers = self.identify_maintainers(contributors, company_domain)
        
        # Get all contributors sorted by commit count for detailed analysis
        all_contributors = sorted(contributors.items(), key=lambda x: x[1]['commits'], reverse=True)
        
        # Get detailed repository info for all contributors
        maintainers_with_repos = []
        
        print(f"\n🔍 Fetching detailed repository data for all {len(all_contributors)} contributors...")
        
        for i, (username, data) in enumerate(all_contributors, 1):
            print(f"  [{i}/{len(all_contributors)}] {username}")
            
            try:
                # Get user's detailed repository breakdown
                repos_data = self.get_user_repositories(username)
                
                # Check if this contributor is also identified as a maintainer
                is_maintainer = any(m[0] == username for m in maintainers)
                maintainer_reasons = []
                if is_maintainer:
                    # Find the maintainer reasons
                    for m_username, m_data in maintainers:
                        if m_username == username:
                            maintainer_reasons = m_data.get('maintainer_reasons', [])
                            break
                
                maintainer_info = {
                    'username': username,
                    'commits': data['commits'],
                    'emails': list(data['emails']),
                    'has_company_email': bool(company_domain and any(
                        company_domain in email.lower() for email in data['emails']
                    )),
                    'analyzed_repositories': list(data['repositories']),
                    'repo_count_in_analysis': len(data['repositories']),
                    'is_maintainer': is_maintainer,
                    'maintainer_reasons': maintainer_reasons,
                    'personal_repositories': repos_data['personal'],
                    'organization_repositories': repos_data['organization'],
                    'total_repositories': repos_data['total'],
                    'personal_repo_count': len(repos_data['personal']),
                    'organization_repo_count': len(repos_data['organization'])
                }
                
            except Exception as e:
                print(f"    ❌ Error fetching repos for {username}: {str(e)[:50]}...")
                
                # Check if this contributor is also identified as a maintainer
                is_maintainer = any(m[0] == username for m in maintainers)
                maintainer_reasons = []
                if is_maintainer:
                    for m_username, m_data in maintainers:
                        if m_username == username:
                            maintainer_reasons = m_data.get('maintainer_reasons', [])
                            break
                
                maintainer_info = {
                    'username': username,
                    'commits': data['commits'],
                    'emails': list(data['emails']),
                    'has_company_email': bool(company_domain and any(
                        company_domain in email.lower() for email in data['emails']
                    )),
                    'analyzed_repositories': list(data['repositories']),
                    'repo_count_in_analysis': len(data['repositories']),
                    'is_maintainer': is_maintainer,
                    'maintainer_reasons': maintainer_reasons,
                    'personal_repositories': [],
                    'organization_repositories': [],
                    'total_repositories': 0,
                    'personal_repo_count': 0,
                    'organization_repo_count': 0,
                    'error': f"Failed to fetch repositories: {str(e)[:50]}"
                }
            
            maintainers_with_repos.append(maintainer_info)
            
            # Rate limiting
            if i < len(all_contributors):
                time.sleep(0.2)
        
        output_data = {
            'organization_name': target,
            'company_domain': company_domain,
            'analysis_date': datetime.now().isoformat(),
            'total_contributors': len(contributors),
            'total_maintainers': len(maintainers),
            'all_contributors_analyzed': len(all_contributors),
            'maintainers': maintainers_with_repos
        }
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"analysis_{target}_{timestamp}.json"
        
        try:
            # Save timestamped version
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2)
            
            # Save as latest.json for automatic loading
            latest_filename = "latest_analysis.json"
            with open(latest_filename, 'w', encoding='utf-8') as f:
                json.dump(output_data, f, indent=2)
            
            print(f"\n💾 Results saved to: {filename}")
            print(f"   📄 Latest file: {latest_filename}")
            print(f"   🏢 Organization: {target}")
            print(f"   🌐 Domain: {company_domain or 'Not identified'}")
            print(f"   👑 Maintainers: {len(maintainers)}")
            print(f"   🔍 Top contributors analyzed: {len(top_contributors)}")
        except Exception as e:
            print(f"❌ Error saving: {e}")
            return None, None
        
        return filename, output_data
    
    def create_embedded_html(self, json_data: dict) -> str:
        """Create HTML file with embedded JSON data"""
        html_template = "dynamic_cytoscape_graph.html"
        if not os.path.exists(html_template):
            print(f"❌ HTML template not found: {html_template}")
            return None
        
        try:
            # Read the template HTML file
            with open(html_template, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            # Convert JSON data to JavaScript
            json_str = json.dumps(json_data, indent=2)
            embedded_script = f"""
    <script>
        // Embedded analysis data - generated by ShadowHunt
        window.EMBEDDED_DATA = {json_str};
    </script>
</head>"""
            
            # Replace </head> with our embedded script + </head>
            html_content = html_content.replace('</head>', embedded_script)
            
            # Create the embedded HTML filename
            embedded_filename = f"visualization_{json_data['organization_name']}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            
            # Write the new HTML file
            with open(embedded_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return embedded_filename
            
        except Exception as e:
            print(f"❌ Error creating embedded HTML: {e}")
            return None
    
    def open_visualization(self, json_data: dict):
        """Create and open HTML visualization with embedded data"""
        try:
            print(f"\n🌐 Creating ShadowHunt visualization with embedded data...")
            
            # Create HTML file with embedded data
            embedded_html = self.create_embedded_html(json_data)
            
            if embedded_html:
                # Get absolute path and open in browser
                html_abs_path = os.path.abspath(embedded_html)
                webbrowser.open(f"file://{html_abs_path}")
                
                print(f"✅ Visualization opened in browser!")
                print(f"   📄 HTML file: {embedded_html}")
                print(f"   📊 Data: Embedded in HTML (no upload needed)")
                print(f"   🎯 Organization: {json_data['organization_name']}")
            else:
                # Fallback to original method
                html_file = "dynamic_cytoscape_graph.html"
                if os.path.exists(html_file):
                    html_abs_path = os.path.abspath(html_file)
                    webbrowser.open(f"file://{html_abs_path}")
                    print(f"✅ Opened template HTML (manual upload required)")
                
        except Exception as e:
            print(f"❌ Error opening visualization: {e}")


def main():
    print("🚀 ShadowHunt - GitHub Shadow IT & Secret Hunter")
    print("="*60)
    
    token = getpass.getpass("🔑 Enter GitHub token: ").strip()
    if not token:
        print("❌ Token required!")
        sys.exit(1)
    
    analyzer = GitHubContributorAnalyzer(token)
    if not analyzer.validate_token():
        sys.exit(1)
    
    target = input("\n🎯 Enter organization/username: ").strip()
    if not target:
        print("❌ Target required!")
        sys.exit(1)
    
    try:
        max_repos = int(input("📂 Max repositories (default 20): ").strip() or "20")
        max_commits = int(input("📝 Max commits per repo (default 500): ").strip() or "500")
    except ValueError:
        max_repos, max_commits = 20, 500
    
    print(f"\n🎬 Starting analysis...")
    print(f"Target: {target} | Max repos: {max_repos} | Max commits: {max_commits}")
    
    contributors = analyzer.analyze_target(target, max_repos=max_repos, max_commits_per_repo=max_commits)
    analyzer.print_results(contributors, target)
    json_filename, output_data = analyzer.save_results(contributors, target)
    
    if json_filename and output_data:
        analyzer.open_visualization(output_data)
    
    # Optional gitleaks secret scanning
    if json_filename and GitleaksScanner:
        try:
            # Use the same token as the main analyzer
            scanner = GitleaksScanner(github_token=token)
            scanner.scan_from_analysis_file(json_filename)
        except KeyboardInterrupt:
            print(f"\n🛑 Secret scanning interrupted by user")
        except Exception as e:
            print(f"❌ Error during secret scanning: {e}")
    elif not GitleaksScanner:
        print(f"\n⚠️  Gitleaks scanner not available - skipping secret scanning")
    
    print(f"\n✅ Analysis Complete!")


if __name__ == "__main__":
    main() 