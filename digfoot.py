#!/usr/bin/env python3
import sys
import os
import re
import json
import time
import threading
import argparse
from datetime import datetime, timezone
from urllib.parse import quote_plus
from typing import Dict, List, Optional, Tuple

# Check and import required packages
try:
    import requests
    from bs4 import BeautifulSoup
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
    # Optional GUI imports
    try:
        import tkinter as tk
        from tkinter import ttk, scrolledtext, messagebox
    except ImportError:
        pass
except ImportError as e:
    print(f"Error: Missing required package - {str(e)}")
    print("Please install dependencies with:")
    print("pip install requests beautifulsoup4 selenium")
    sys.exit(1)

class DigitalFootprintScanner:
    def __init__(self, email: str, deep_scan: bool = False, gui_mode: bool = False):
        """
        Initialize the scanner with target email and options
        
        Args:
            email: Target email address to investigate
            deep_scan: Whether to perform deep scanning (comments, mentions)
            gui_mode: Whether to run in GUI mode
        """
        self.email = email.lower().strip()
        self.domain = self.email.split('@')[-1]
        self.base_username = self._extract_username()
        self.username_variations = self._generate_variations()
        self.deep_scan = deep_scan
        self.gui_mode = gui_mode
        self.results = {
            'email': self.email,
            'scan_date': datetime.now(timezone.utc).isoformat(),
            'status': 'running',
            'findings': {
                'breaches': [],
                'social_media': {},
                'public_mentions': {},
                'comments_mentions': {},
                'domain_info': {}
            }
        }
        self.progress = {
            'current': 0,
            'total': 100,
            'active_task': None,
            'last_update': time.time()
        }
        self._setup_directories()
        self._init_selenium()
        if not self.gui_mode:
            self._print_header()

    def _print_header(self):
        print(f"""
╔══════════════════════════════════════════════════╗
║           DIGITAL FOOTPRINT SCANNER              ║
╠══════════════════════════════════════════════════╣
║ Target: {self.email.ljust(38)} ║
║ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S').ljust(32)} ║
║ Mode: {'Deep' if self.deep_scan else 'Standard'.ljust(35)} ║
╚══════════════════════════════════════════════════╝
""")

    def _update_progress(self, task_name: Optional[str] = None, increment: int = 0):
        with threading.Lock():
            if task_name:
                self.progress['active_task'] = task_name
            if increment:
                self.progress['current'] += increment
            
            # Only update display every 0.5 seconds max
            if time.time() - self.progress['last_update'] > 0.5:
                if not self.gui_mode:
                    self._print_progress()
                self.progress['last_update'] = time.time()

    def _print_progress(self):
        percent = min(100, int((self.progress['current'] / self.progress['total']) * 100))
        bar = f"[{'#' * (percent//2)}{' ' * (50 - percent//2)}] {percent}%"
        task = f"Current: {self.progress['active_task']}" if self.progress['active_task'] else ""
        print(f"\r{bar} {task.ljust(40)}", end="")

    def _extract_username(self) -> str:
        local = re.sub(r'\+.*$', '', self.email.split('@')[0])
        return re.sub(r'\.(?=[^@]*$)', '', local)

    def _generate_variations(self) -> List[str]:
        variations = set()
        base = self.base_username
        
        # Basic variations
        variations.update([base, base.lower(), base.upper()])
        
        # Common patterns
        patterns = [
            f"{base}123", f"{base}1", f"real{base}",
            f"the{base}", f"{base[:4]}", f"{base[:8]}",
            f"{base}.official", f"{base}.team", f"official.{base}"
        ]
        variations.update(patterns)
        return list(variations)

    def _setup_directories(self):
        os.makedirs('results', exist_ok=True)
        os.makedirs('screenshots', exist_ok=True)

    def _init_selenium(self):
        try:
            options = Options()
            options.add_argument("--headless")
            options.add_argument("--disable-gpu")
            options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
            self.driver = webdriver.Chrome(options=options)
        except Exception as e:
            if not self.gui_mode:
                print(f"\n[!] Warning: Selenium initialization failed - {str(e)}")
                print("[!] Social media checks will be limited without browser automation")
            self.driver = None

    def _safe_request(self, url: str) -> Optional[requests.Response]:
        try:
            time.sleep(0.5)  # Be polite with requests
            return requests.get(url, timeout=10)
        except Exception as e:
            return None

    def check_breaches(self) -> int:
        self._update_progress("Checking data breaches", 5)
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{self.email}"
            response = self._safe_request(url)
            if response and response.status_code == 200:
                self.results['findings']['breaches'] = response.json()
                self._update_progress("Breaches found", 15)
                return len(response.json())
            self._update_progress("No breaches found", 15)
            return 0
        except Exception as e:
            self._update_progress("Breach check failed", 15)
            return 0

    def check_social_media(self) -> int:
        platforms = {
            'Twitter': ('https://twitter.com/{}', self._check_twitter),
            'GitHub': ('https://github.com/{}', self._check_github),
            'Reddit': ('https://www.reddit.com/user/{}', self._check_reddit),
            'Instagram': ('https://instagram.com/{}', self._check_instagram),
            'LinkedIn': ('https://linkedin.com/in/{}', self._check_linkedin),
            'Facebook': ('https://facebook.com/{}', self._check_facebook)
        }
        
        found = 0
        for platform, (url_template, check_func) in platforms.items():
            self._update_progress(f"Checking {platform}", 2)
            for username in self.username_variations[:3]:  # Check top 3 variations
                if check_func(username, url_template):
                    found += 1
                    break
        
        self._update_progress("Social media scan complete", 10)
        return found

    def _check_twitter(self, username: str, url_template: str) -> bool:
        url = url_template.format(username)
        if self.driver:
            try:
                self.driver.get(url)
                time.sleep(2)
                if "Sorry, that page doesn't exist!" not in self.driver.page_source:
                    self.results['findings']['social_media']['Twitter'] = {
                        'url': url,
                        'username': username
                    }
                    if self.deep_scan:
                        self._scan_twitter_comments(username)
                    return True
            except:
                pass
        else:
            response = self._safe_request(url)
            if response and response.status_code == 200:
                self.results['findings']['social_media']['Twitter'] = {
                    'url': url,
                    'username': username
                }
                return True
        return False

    def _scan_twitter_comments(self, username: str):
        """Scan for Twitter comments mentioning the target"""
        if not self.driver:
            return
            
        try:
            self._update_progress("Scanning Twitter comments")
            url = f"https://twitter.com/search?q=from%3A{username}&src=typed_query"
            self.driver.get(url)
            time.sleep(3)
            
            # Extract tweet content
            soup = BeautifulSoup(self.driver.page_source, 'html.parser')
            tweets = []
            for tweet in soup.find_all('div', {'data-testid': 'tweet'}):
                content = tweet.find('div', {'data-testid': 'tweetText'})
                if content:
                    tweets.append(content.get_text(strip=True))
            
            if tweets:
                self.results['findings']['comments_mentions']['Twitter'] = {
                    'count': len(tweets),
                    'sample': tweets[:5]  # Store first 5 tweets as sample
                }
        except Exception as e:
            pass

    def _check_github(self, username: str, url_template: str) -> bool:
        url = url_template.format(username)
        response = self._safe_request(url)
        if response and response.status_code == 200:
            self.results['findings']['social_media']['GitHub'] = {
                'url': url,
                'username': username
            }
            if self.deep_scan:
                self._scan_github_activity(username)
            return True
        return False

    def _scan_github_activity(self, username: str):
        """Scan GitHub for commits, issues, etc."""
        try:
            self._update_progress("Scanning GitHub activity")
            url = f"https://api.github.com/users/{username}/events"
            response = self._safe_request(url)
            if response and response.status_code == 200:
                events = response.json()
                activity = []
                for event in events[:10]:  # Limit to 10 most recent events
                    if event.get('type') in ['PushEvent', 'IssueCommentEvent']:
                        activity.append({
                            'type': event['type'],
                            'repo': event['repo']['name'],
                            'created_at': event['created_at']
                        })
                
                if activity:
                    self.results['findings']['comments_mentions']['GitHub'] = {
                        'activity_count': len(activity),
                        'recent_activity': activity
                    }
        except:
            pass

    def _check_reddit(self, username: str, url_template: str) -> bool:
        url = url_template.format(username)
        response = self._safe_request(url)
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            if not soup.find('div', class_='error-page'):
                self.results['findings']['social_media']['Reddit'] = {
                    'url': url,
                    'username': username
                }
                if self.deep_scan:
                    self._scan_reddit_comments(username)
                return True
        return False

    def _scan_reddit_comments(self, username: str):
        """Scan Reddit comments by the user"""
        try:
            self._update_progress("Scanning Reddit comments")
            url = f"https://www.reddit.com/user/{username}/comments.json?limit=10"
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers)
            if response and response.status_code == 200:
                comments = response.json().get('data', {}).get('children', [])
                if comments:
                    comment_samples = []
                    for comment in comments[:5]:
                        data = comment.get('data', {})
                        comment_samples.append({
                            'subreddit': data.get('subreddit'),
                            'body': data.get('body')[:200] + '...' if data.get('body') else '',
                            'created': data.get('created_utc')
                        })
                    
                    self.results['findings']['comments_mentions']['Reddit'] = {
                        'comment_count': len(comments),
                        'sample_comments': comment_samples
                    }
        except:
            pass

    def _check_instagram(self, username: str, url_template: str) -> bool:
        url = url_template.format(username)
        if self.driver:
            try:
                self.driver.get(url)
                time.sleep(3)
                if "Sorry, this page isn't available." not in self.driver.page_source:
                    self.results['findings']['social_media']['Instagram'] = {
                        'url': url,
                        'username': username
                    }
                    return True
            except:
                pass
        return False

    def _check_linkedin(self, username: str, url_template: str) -> bool:
        url = url_template.format(username)
        response = self._safe_request(url)
        if response:
            # LinkedIn often returns 999 for scrapers
            if response.status_code in [200, 999]:
                soup = BeautifulSoup(response.text, 'html.parser')
                if not soup.find('div', class_='profile-unavailable'):
                    self.results['findings']['social_media']['LinkedIn'] = {
                        'url': url,
                        'username': username
                    }
                    return True
        return False

    def _check_facebook(self, username: str, url_template: str) -> bool:
        url = url_template.format(username)
        response = self._safe_request(url)
        if response and response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            if not (soup.find('title') and 'page not found' in soup.find('title').text.lower()):
                self.results['findings']['social_media']['Facebook'] = {
                    'url': url,
                    'username': username
                }
                return True
        return False

    def search_public_mentions(self) -> int:
        engines = {
            'Google': 'https://www.google.com/search?q={}',
            'Bing': 'https://www.bing.com/search?q={}',
            'DuckDuckGo': 'https://duckduckgo.com/?q={}'
        }
        queries = [
            f'"{self.email}"',
            f'"{self.base_username}"',
            f'site:github.com "{self.email}"',
            f'site:twitter.com "{self.email}"',
            f'site:pastebin.com "{self.email}"',
            f'site:reddit.com "{self.email}"'
        ]
        
        found = 0
        for engine, url in engines.items():
            self._update_progress(f"Searching {engine}", 3)
            engine_results = []
            for query in queries:
                response = self._safe_request(url.format(quote_plus(query)))
                if response and response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    links = []
                    for a in soup.find_all('a', href=True):
                        href = a['href']
                        if href.startswith('http') and not any(x in href for x in ['google', 'bing', 'duckduckgo']):
                            links.append(href)
                    engine_results.extend(links[:3])
            
            if engine_results:
                self.results['findings']['public_mentions'][engine] = engine_results
                found += len(engine_results)
        
        self._update_progress("Public mentions search complete", 15)
        return found

    def analyze_domain(self) -> int:
        self._update_progress("Analyzing domain", 10)
        domain_info = {}
        
        # Basic domain info
        domain_info['domain'] = self.domain
        
        # Check if domain has website
        try:
            response = self._safe_request(f"http://{self.domain}")
            domain_info['website_accessible'] = bool(response and response.status_code == 200)
        except:
            domain_info['website_accessible'] = False
        
        # Additional domain checks
        try:
            # Check for MX records (email hosting)
            import dns.resolver
            try:
                answers = dns.resolver.resolve(self.domain, 'MX')
                domain_info['email_hosted'] = bool(answers)
            except:
                domain_info['email_hosted'] = False
        except ImportError:
            domain_info['email_hosted'] = "Unknown (dnspython not installed)"
        
        self.results['findings']['domain_info'] = domain_info
        self._update_progress("Domain analysis complete", 10)
        return 1

    def run_scan(self) -> Dict:
        try:
            if not self.gui_mode:
                print("\n[+] Starting digital footprint analysis...\n")
            
            # Run all checks
            breach_count = self.check_breaches()
            social_media_count = self.check_social_media()
            mentions_count = self.search_public_mentions()
            domain_analysis = self.analyze_domain()
            
            # Final update
            self._update_progress("Analysis complete", 20)
            if not self.gui_mode:
                print("\n\n[+] Scan completed successfully!")
                print(f"\nSummary of findings for {self.email}:")
                print(f"- Data breaches: {breach_count}")
                print(f"- Social media profiles: {social_media_count}")
                print(f"- Public mentions: {mentions_count}")
                if self.deep_scan and self.results['findings']['comments_mentions']:
                    print(f"- Comments/activity found: {len(self.results['findings']['comments_mentions'])} platforms")
            
            self.results['status'] = 'completed'
            self._save_results()
            return self.results
            
        except KeyboardInterrupt:
            if not self.gui_mode:
                print("\n[!] Scan interrupted by user")
            self.results['status'] = 'interrupted'
            self._save_results()
        except Exception as e:
            if not self.gui_mode:
                print(f"\n[!] Error during scan: {str(e)}")
            self.results['status'] = 'failed'
            self._save_results()
        finally:
            if hasattr(self, 'driver') and self.driver:
                self.driver.quit()

    def _save_results(self):
        filename = f"results/{self.email.replace('@', '_')}_footprint.json"
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        if not self.gui_mode:
            print(f"\n[+] Full results saved to {filename}")
        return filename

class DigitalFootprintGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Digital Footprint Scanner")
        self.root.geometry("800x600")
        self.scanner = None
        self.scan_thread = None
        
        self._setup_ui()
        
    def _setup_ui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Input section
        input_frame = ttk.LabelFrame(main_frame, text="Scan Target", padding="10")
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="Email Address:").grid(row=0, column=0, sticky=tk.W)
        self.email_entry = ttk.Entry(input_frame, width=40)
        self.email_entry.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Options
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding="10")
        options_frame.pack(fill=tk.X, pady=5)
        
        self.deep_scan_var = tk.BooleanVar()
        ttk.Checkbutton(options_frame, text="Deep Scan (comments/activity)", 
                       variable=self.deep_scan_var).pack(anchor=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        ttk.Button(button_frame, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Save Results", command=self.save_results, state=tk.DISABLED).pack(side=tk.LEFT, padx=5)
        self.save_button = ttk.Button(button_frame, text="Export...", command=self.export_results, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        # Progress
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding="10")
        progress_frame.pack(fill=tk.BOTH, expand=True)
        
        self.progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, mode='determinate')
        self.progress_bar.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(progress_frame, text="Ready")
        self.status_label.pack(fill=tk.X)
        
        # Results
        results_frame = ttk.LabelFrame(main_frame, text="Results", padding="10")
        results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, wrap=tk.WORD)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
    def start_scan(self):
        email = self.email_entry.get().strip()
        if not email or '@' not in email:
            messagebox.showerror("Error", "Please enter a valid email address")
            return
            
        self.results_text.delete(1.0, tk.END)
        self.progress_bar['value'] = 0
        self.status_label['text'] = "Starting scan..."
        self.save_button['state'] = tk.DISABLED
        
        deep_scan = self.deep_scan_var.get()
        self.scanner = DigitalFootprintScanner(email, deep_scan, gui_mode=True)
        
        # Run scan in separate thread to keep GUI responsive
        self.scan_thread = threading.Thread(target=self.run_scan_thread, daemon=True)
        self.scan_thread.start()
        
    def run_scan_thread(self):
        results = self.scanner.run_scan()
        self.root.after(0, self.display_results, results)
        
    def display_results(self, results):
        self.progress_bar['value'] = 100
        self.status_label['text'] = "Scan completed"
        self.save_button['state'] = tk.NORMAL
        
        # Display summary
        self.results_text.insert(tk.END, f"Scan Results for {results['email']}\n")
        self.results_text.insert(tk.END, f"Scan Date: {results['scan_date']}\n")
        self.results_text.insert(tk.END, f"Status: {results['status'].capitalize()}\n\n")
        
        # Breaches
        breaches = results['findings']['breaches']
        self.results_text.insert(tk.END, f"Data Breaches: {len(breaches)}\n")
        for breach in breaches[:3]:  # Show first 3 breaches
            self.results_text.insert(tk.END, f"- {breach.get('Name', 'Unknown')}: {breach.get('Description', 'No description')}\n")
        if len(breaches) > 3:
            self.results_text.insert(tk.END, f"- ...and {len(breaches)-3} more\n")
        
        # Social media
        social_media = results['findings']['social_media']
        self.results_text.insert(tk.END, f"\nSocial Media Profiles: {len(social_media)}\n")
        for platform, data in social_media.items():
            self.results_text.insert(tk.END, f"- {platform}: {data['url']}\n")
        
        # Comments/mentions if deep scan
        if self.deep_scan_var.get() and results['findings']['comments_mentions']:
            self.results_text.insert(tk.END, "\nComments/Activity Found:\n")
            for platform, data in results['findings']['comments_mentions'].items():
                self.results_text.insert(tk.END, f"- {platform}: {data.get('count', 0)} items\n")
        
    def save_results(self):
        if self.scanner:
            filename = self.scanner._save_results()
            messagebox.showinfo("Saved", f"Results saved to {filename}")
            
    def export_results(self):
        if not self.scanner:
            return
            
        filename = tk.filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
            title="Save scan results"
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.scanner.results, f, indent=2)
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export: {str(e)}")
    
    def run(self):
        self.root.mainloop()

def main():
    parser = argparse.ArgumentParser(
        description="Digital Footprint Scanner - Investigate online presence of an email address",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('email', nargs='?', help="Email address to investigate")
    parser.add_argument('-d', '--deep', action='store_true', help="Perform deep scan (comments, activity)")
    parser.add_argument('-G', '--gui', action='store_true', help="Launch in GUI mode")
    parser.add_argument('-o', '--output', help="Output file for results (JSON format)")
    
    args = parser.parse_args()
    
    if args.gui:
        gui = DigitalFootprintGUI()
        gui.run()
    else:
        if not args.email:
            parser.print_help()
            sys.exit(1)
            
        scanner = DigitalFootprintScanner(args.email, args.deep)
        results = scanner.run_scan()
        
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    json.dump(results, f, indent=2)
                print(f"\n[+] Results saved to {args.output}")
            except Exception as e:
                print(f"\n[!] Error saving results: {str(e)}")

if __name__ == "__main__":
    main()
