# sqlinjfindx
sqlinjfindx is a Python-based tool designed to identify SQL injection vulnerabilities in web applications.


Features
SQL Injection Detection: Detects both regular and blind SQL injection vulnerabilities using pre-defined payloads.
Supports GET and POST Methods: Flexible scanning over different HTTP methods.
Custom Headers: Allows custom headers for API tokens, cookies, or other authorization mechanisms.
Blind SQL Injection Detection: Uses time-based payloads (e.g., SLEEP(5)) to identify blind SQL injection vulnerabilities.
Threading: Multi-threaded scanning for faster execution on multiple URLs.
Verbose Mode: Provides detailed output, including response status and timing.
Multiple Output Formats: Results can be saved as plain text, JSON, or CSV.

--Usage--
Basic Usage
To scan a single URL using GET parameters:


python3 sqlinjfindx.py "http://example.com/index.php?id=1"
This will test the URL for SQL injection vulnerabilities and print the results to the console.


Using POST Requests
To scan a URL that requires POST data, specify the POST method using -m:

python3 sqlinjfindx.py "http://example.com/login.php" -m POST


Verbose Mode
For more detailed output about each request (e.g., status code, response time), use the -v flag:

python3 sqlinjfindx.py "http://example.com/page?id=1" -v



Threading/Concurrency
To scan multiple URLs concurrently, specify the number of threads with -T:

python3 sqlinjfindx.py urls.txt -T 5
This will scan 5 URLs at a time.



--Blind SQL Injection Scanning--
For blind SQL injection detection using time-based payloads, use the --blind flag:


python3 sqlinjfindx.py "http://example.com/page?id=1" --blind


Custom Headers
To pass custom headers (e.g., Authorization tokens, cookies):


python3 sqlinjfindx.py "http://example.com/page?id=1" -H "Authorization=Bearer token123"


You can specify multiple headers using the -H option multiple times:


python3 sqlinjfindx.py "http://example.com/page?id=1" -H "Authorization=Bearer token123" -H "Cookie=sessionid=abc123"



--Output Formats--
You can save the results of your scan in different formats. The tool supports .txt, .json, and .csv.

Plain Text (default):

python3 sqlinjfindx.py "http://example.com/page?id=1" -o results.txt


JSON:


python3 sqlinjfindx.py "http://example.com/page?id=1" -o results.json


CSV:

python3 sqlinjfindx.py "http://example.com/page?id=1" -o results.csv

