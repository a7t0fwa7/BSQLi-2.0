

# BSQLi 2.0 - Advanced SQL Injection Testing Tool

BSQLi 2.0 is an advanced SQL injection testing tool designed to help security researchers and penetration testers identify potential SQL injection vulnerabilities in web applications.

## Table of Contents

- [BSQLi 2.0 - Advanced SQL Injection Testing Tool](#bsqli-20---advanced-sql-injection-testing-tool)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Usage](#usage)
  - [Features](#features)
  - [Options](#options)
  - [Methodology](#methodology)
  - [Examples](#examples)
  - [Output](#output)
  - [Safety and Legal Considerations](#safety-and-legal-considerations)

## Installation

1. Clone the repository:
```

   git clone https://github.com/YourUsername/BSQLi.git
   cd BSQLi

```

2. Install the required dependencies:
```

   pip install -r requirements.txt

```

## Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

## Usage

Basic usage:
```

python bsqli2.0.py -u `<URL>` -p <PAYLOADS_FILE>

```

## Features

- Multi-threaded testing for faster execution
- Automatic payload generation
- Website crawling to discover additional URLs
- Response time analysis to detect time-based SQLi
- Results saving in CSV or JSON format
- Integration with SQLite database for result storage
- Proxy support for request routing
- Custom User-Agent setting
- Verbose logging for detailed output

## Options

- `-u, --url`: Single URL to scan or base URL for crawling
- `-l, --list`: Text file containing a list of URLs to scan
- `-p, --payloads`: Text file containing the payloads to append to the URLs
- `-c, --cookie`: Cookie to include in the GET request
- `-t, --threads`: Number of concurrent threads (default: 40)
- `-T, --timeout`: Timeout for each request in seconds (default: 30)
- `-o, --output`: Output file to save results (CSV or JSON format)
- `-ua, --user-agent`: User-Agent string to use (default: "BSQLi Tester")
- `-x, --proxy`: Proxy to use for requests (e.g., http://127.0.0.1:8080)
- `-d, --delay`: Add a random delay between requests (in seconds)
- `-v, --verbose`: Enable verbose output
- `--crawl`: Crawl the website for additional URLs
- `--generate-payloads`: Automatically generate payloads
- `--use-db`: Store results in SQLite database

## Methodology

BSQLi 2.0 employs a comprehensive methodology to detect SQL injection vulnerabilities:

1. **URL Collection**:
   - Single URL: Provided directly via the `-u` option.
   - Multiple URLs: Loaded from a file using the `-l` option.
   - Crawling: When `--crawl` is enabled, the tool discovers additional URLs by crawling the target website.

2. **Payload Preparation**:
   - Custom Payloads: Loaded from a file specified with the `-p` option.
   - Auto-generated Payloads: Created when `--generate-payloads` is used, including variations of common SQL injection patterns.

3. **Injection Testing**:
   - For each URL and payload combination:
     a. Construct the test URL by appending the payload.
     b. Send an HTTP GET request to the test URL.
     c. Measure the response time.
     d. Analyze the response for indicators of vulnerability.

4. **Vulnerability Detection**:
   - Time-based: Identifies potential vulnerabilities when response time exceeds a threshold (default 10 seconds).
   - Error-based: Looks for SQL error messages in the response content.
   - Behavioral analysis: Compares responses to identify anomalies indicative of successful injection.

5. **Result Analysis**:
   - Clustering: Applies K-means clustering to response times to identify outliers.
   - Visualization: Generates a graph of response times to visually represent potential vulnerabilities.

6. **Reporting**:
   - Console Output: Provides real-time feedback on tested URLs and their vulnerability status.
   - File Output: Saves detailed results in CSV or JSON format for further analysis.
   - Database Storage: Optionally stores results in an SQLite database for persistent record-keeping.

7. **Advanced Techniques**:
   - Multi-threading: Utilizes concurrent requests to speed up the testing process.
   - Proxy Support: Allows routing requests through a proxy for anonymity or further manipulation.
   - Random Delays: Introduces random delays between requests to avoid detection by rate-limiting mechanisms.

By following this methodology, BSQLi 2.0 aims to provide a thorough and efficient approach to identifying SQL injection vulnerabilities in web applications.

## Examples

1. Test a single URL with a payload file:
```

   python bsqli2.0.py -u http://example.com/page.php?id=1 -p payloads.txt

```

2. Test multiple URLs from a file, using automatic payload generation:
```

   python bsqli2.0.py -l urls.txt --generate-payloads -o results.csv

```

3. Crawl a website and test discovered URLs:
```

   python bsqli2.0.py -u http://example.com --crawl -p payloads.txt -o results.json

```

4. Use a proxy and custom User-Agent:
```

   python bsqli2.0.py -u http://example.com/page.php?id=1 -p payloads.txt -x http://127.0.0.1:8080 -ua "Mozilla/5.0"

```

## Output

The tool provides three types of output:

1. Console output: Displays real-time results and summary.
2. File output: Saves detailed results in CSV or JSON format.
3. Graph output: Generates a response time analysis graph (saved as PNG).

## Safety and Legal Considerations

- Always obtain explicit permission before testing any website or application.
- Use this tool only on systems you own or have permission to test.
- Misuse of this tool may be illegal and punishable by law.
- The developers are not responsible for any misuse or damage caused by this tool.

