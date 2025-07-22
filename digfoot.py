#!/usr/bin/env python3
import sys
import os
import re
import json
import time
import threading
from datetime import datetime, timezone
from urllib.parse import quote_plus

# Check and import required packages
try:
    import requests
    from bs4 import BeautifulSoup
    from selenium import webdriver
    from selenium.webdriver.chrome.options import Options
except ImportError as e:
    print(f"Error: Missing required package - {str(e)}")
    print("Please install dependencies with:")
    print("pip install requests beautifulsoup4 selenium")
    sys.exit(1)

class DigitalFootprintScanner:
    def __init__(self, email):
        self.email = email.lower().strip()
        self.domain = self.email.split('@')[-1]
        self.base_username = self._extract_username()
        self.username_variations = self._generate_variations()
        self.results = {
            'email': self.email,
            'scan_date': datetime.now(timezone.utc).isoformat(),
            'status': 'running',
            'findings': {
                'breaches': [],
                'social_media': {},
                'public_mentions': {},
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
        self._print_header()

    def _print_header(self):
        print(f"""
╔══════════════════════════════════════════════════╗
║           DIGITAL FOOTPRINT SCANNER              ║
╠══════════════════════════════════════════════════╣
║ Target: {self.email.ljust(38)} ║
║ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S').ljust(32)} ║
╚══════════════════════════════════════════════════╝
""")

    def _update_progress(self, task_name=None, increment=0):
        with threading.Lock():
            if task_name:
                self.progress['active_task'] = task_name
            if increment:
                self.progress['current'] += increment
            
            # Only update display every 0.5 seconds max
            if time.time() - self.progress['last_update'] > 0.5:
                self._print_progress()
                self.progress['last_update'] = time.time()

    def _print_progress(self):
        percent = min(100, int((self.progress['current'] / self.progress['total']) * 100))
        bar = f"[{'#' * (percent//2)}{' ' * (50 - percent//2)}] {percent}%"
        task = f"Current: {self.progress['active_task']}" if self.progress['active_task'] else ""
        print(f"\r{bar} {task.ljust(40)}", end="")

    def _extract_username(self):
        local = re.sub(r'\+.*$', '', self.email.split('@')[0])
        return re.sub(r'\.(?=[^@]*$)', '', local)

    def _generate_variations(self):
        variations = set()
        base = self.base_username
        
        # Basic variations
        variations.update([base, base.lower(), base.upper()])
        
        # Common patterns
        patterns = [
            f"{base}123", f"{base}1", f"real{base}",
            f"the{base}", f"{base[:4]}", f"{base[:8]}"
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
            print(f"\n[!] Warning: Selenium initialization failed - {str(e)}")
            print("[!] Social media checks will be limited without browser automation")
            self.driver = None

    def _safe_request(self, url):
        try:
            time.sleep(0.5)  # Be polite with requests
            return requests.get(url, timeout=10)
        except Exception as e:
            return None

    def check_breaches(self):
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

    def check_social_media(self):
        platforms = {
            'Twitter': 'https://twitter.com/{}',
            'GitHub': 'https://github.com/{}',
            'Reddit': 'https://www.reddit.com/user/{}',
            'Instagram': 'https://instagram.com/{}',
            'LinkedIn': 'https://linkedin.com/in/{}'
        }
        
        found = 0
        for platform, url in platforms.items():
            self._update_progress(f"Checking {platform}", 2)
            for username in self.username_variations[:3]:  # Check top 3 variations
                if self.driver:
                    try:
                        self.driver.get(url.format(username))
                        time.sleep(2)
                        if "not found" not in self.driver.page_source.lower() and \
                           "404" not in self.driver.page_source.lower():
                            self.results['findings']['social_media'][platform] = {
                                'url': url.format(username),
                                'username': username
                            }
                            found += 1
                            break
                    except:
                        continue
                else:
                    response = self._safe_request(url.format(username))
                    if response and response.status_code == 200:
                        self.results['findings']['social_media'][platform] = {
                            'url': url.format(username),
                            'username': username
                        }
                        found += 1
                        break
        self._update_progress("Social media scan complete", 10)
        return found

    def search_public_mentions(self):
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
            f'site:pastebin.com "{self.email}"'
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

    def analyze_domain(self):
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
        
        self.results['findings']['domain_info'] = domain_info
        self._update_progress("Domain analysis complete", 10)
        return 1

    def run_scan(self):
        try:
            print("\n[+] Starting digital footprint analysis...\n")
            
            # Run all checks
            breach_count = self.check_breaches()
            social_media_count = self.check_social_media()
            mentions_count = self.search_public_mentions()
            domain_analysis = self.analyze_domain()
            
            # Final update
            self._update_progress("Analysis complete", 20)
            print("\n\n[+] Scan completed successfully!")
            print(f"\nSummary of findings for {self.email}:")
            print(f"- Data breaches: {breach_count}")
            print(f"- Social media profiles: {social_media_count}")
            print(f"- Public mentions: {mentions_count}")
            
            self.results['status'] = 'completed'
            self._save_results()
            return self.results
            
        except KeyboardInterrupt:
            print("\n[!] Scan interrupted by user")
            self.results['status'] = 'interrupted'
            self._save_results()
        except Exception as e:
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
        print(f"\n[+] Full results saved to {filename}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python digfoot.py <email>")
        sys.exit(1)
    
    email = sys.argv[1]
    scanner = DigitalFootprintScanner(email)
    scanner.run_scan()