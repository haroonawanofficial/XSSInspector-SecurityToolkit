# XSSInspector
The XSSInspector is a powerful security tool designed to find Cross-Site Scripting (XSS) threats—a pervasive and dangerous issue in web applications. This open-source solution simplifies XSS vulnerability identification and mitigation, serving as a valuable asset for security experts and developers.

## Basic Usages for Newbies
- **How to Run** python or python3 xssinspector.py --domain testphp.vulnweb.com --sources wayback --use-filters 95 --report testphp.html
- **How to Run** python or python3 xssinspector.py --domain testphp.vulnweb.com --sources wayback --use-filters 95 --report testphp.html --thread 20 (if you have fast system)
  
## Features

- **URL Processor**: XSS Inspector can perform data cleansing and url check for .asp, .php, .cgi and more....

- **Heuristic-Based Logic**: XSS Inspector can determine if an endpoint exists using heuristics. By leveraging assumptions and advanced reasoning, it verifies the endpoint and attempts to inject payloads to assess whether the remote target is vulnerable.

- **URL Crawling**: XSS Inspector supports various methods of collecting URLs, including Common Crawl, Wayback Machine, and OTX Alienvault.

- **Multi-Threading**: Utilize the power of multi-threading to scan a large number of URLs quickly.

- **Payload Testing**: The tool includes a variety of XSS payloads to test web applications for vulnerabilities.

- **Subdomain Discovery**: The tool collects and includes the results of subdomains in the final list of URLs as not only the URLs associated with the target domain but also its subdomains.

- **Multi Processing**: Built-in python's multiprocessing advantage, which is better suited for CPU-bound tasks like scanning multiple URLs for vulnerabilities.
  
- **Multi Threading**: Built-in python's advantage to use default threads 50 but it goes upto 100 if CPU supports that much suited for tasks like scanning multiple URLs for vulnerabilities.

- **URL Record Tracker**: Keep tracking if we are same link with payloads or obfuscation or not; provides solid information.
  
- **SQLite**: Sqllite is a self-contained, serverless, and zero-configuration database engine that is used in embedded systems, mobile devices, desktop applications, and small-scale database applications.

- **SQLite Database File (xss_vulnerabilities.db) for XSSInspector**:


1. xss_vulnerabilities.db is an SQLite database used to store information about detected XSS vulnerabilities during the scanning process.
2. Structured Storage: The database provides structured storage for vulnerabilities and their associated URLs.
3. Persistence: Data stored in the database persists across multiple runs of the scanning tool, allowing for historical tracking of security findings.
4. Ease of Querying: SQLite supports SQL queries, making it easy to retrieve and analyze stored data.
5. Security Findings: Vulnerable URLs and related details are stored in the database, including the URL itself and other relevant information.
6. Centralized Storage: All security findings are kept in one centralized location, facilitating efficient vulnerability management.
7. Historical Data: The database accumulates historical data on detected vulnerabilities, enabling trend analysis and reporting over time.
8. Reporting and Compliance: Structured data in the database aids in generating comprehensive reports and compliance documentation.

  
- **Final Report**: The tool generates detailed HTML reports with identified vulnerabilities, making it easier to address security concerns.

## False Positive Reducation

1. In an effort to reduce false positives when hunting for XSS vulnerabilities, this tool employs a False Positive Damping approach.
2. It automatically sends a HEAD request to the URL and checks the `Content-Type` header of the response. 
3. The tool examines `Content-Type` header indicates that the URL points to a non-HTML or non-PHP file (e.g., images, non-web content), the tool bypasses the URL link.
4. Parameter Analysis: For each URL, it analysis the query parameters to identify parameters that may be related to file handling. This includes parameters such as "file," "path," "image," "download," etc.
5. Parameter Whitelisting: It creats whitelist parameters that are known to be safe and not associated with file handling. 
6. Filtering: Before testing a payload against a URL, it checks if any of the query parameters match the file-related keywords. 

   
## Heuristic & Obfuscation Structure and Logic:
- Enhanced Detection Accuracy: The heuristic logic fine-tunes the scanner to detect XSS vulnerabilities more accurately by concentrating on common attack patterns.
- Reduced False Positives: The heuristic logic helps minimize false positives by identifying potential vulnerabilities based on known attack indicators.
- Evasion and Bypass Capabilities: Obfuscation logic strengthens the scanner's evasion techniques, making it harder for security mechanisms to thwart attacks.
- Comprehensive Testing: With obfuscation techniques, the scanner thoroughly tests potential vulnerabilities by employing multiple payload variations.
- Improved Reliability: The combination of heuristic and obfuscation logic ensures a more reliable and effective XSS scanner, resulting in precise vulnerability identification and decreased security risks.

## Obfuscations with Bypassing (96 special modes are supported built-in)

- Parameter pollution built-in; software auto use it when necessary.
- Obfuscate with hexadecimal escape sequences (e.g., \xHH)
- Obfuscate with Unicode escape sequences (e.g., \uHHHH)
- Base64 encode the payload
- Encode the payload in UTF-16
- Encode the payload with ROT13
- Obfuscate with percent-encoded characters (e.g., %HH)
- Obfuscate with HTML entity references (e.g., &-xHH;)
- Replace 'a' with null character '\x00a' and 'l' with '\x00c' (if a string)
- Encode the payload in UTF-16LE
- Encode the payload in UTF-32LE
- Reverse the payload
- Convert payload to uppercase
- Convert payload to lowercase
- Swap case of the payload characters
- Obfuscate with hexadecimal escape sequences (e.g., \xHH)
- Obfuscate with Unicode escape sequences (e.g., \uHHHH)
- Encode the payload in UTF-32BE
- Obfuscate with Unicode escape sequences (e.g., \uHHHH)
- Obfuscate with hexadecimal escape sequences (e.g., \xHHHHHHHH)
- Obfuscate with hexadecimal escape sequences (e.g., \xHH)
- Obfuscate with hexadecimal escape sequences (e.g., \xHH)
- Obfuscate with Unicode escape sequences (e.g., \uHHHH)
- Join words with plus symbols
- Remove null characters (if a string)
- Obfuscate with hexadecimal escape sequences (e.g., \xHH)
- Replace '<' with '&lt;' and '>' with '&gt;'
- Replace double quotes and single quotes with HTML entity references
- Obfuscate with backslashes (e.g., \char)
- Obfuscate with double backslashes (e.g., \\char)
- Obfuscate with percent-encoded characters (e.g., %uHHHH)
- Obfuscate with percent-encoded characters (e.g., %HH)
- Obfuscate with Unicode escape sequences (e.g., \UHHHHHHHH)
- Obfuscate with percent-encoded characters (e.g., %HH; )
- Obfuscate with percent-encoded characters (e.g., %uHHHH; )
- Obfuscate with percent-encoded characters (e.g., %HH )
- Obfuscate with HTML entity references (e.g., &-xHH;)
- Replace '1' with 'I' and '0' with 'O' (if a string)
- Obfuscate with percent-encoded characters (e.g., %HH)
- Obfuscate with HTML entity references (e.g., &-xHH;)
- Replace 'a' with null character '\x00a' and 'l' with '\x00c' (if a string)
- Encode the payload in UTF-16LE
- Encode the payload in UTF-32LE
- Obfuscate with percent-encoded characters (e.g., %uHHHH; )
- Replace '<' with '&lt;' and '>' with '&gt;'
- Encode the payload in UTF-32BE
- Remove null characters (if a string)
- Obfuscate with HTML entities for special characters
- Obfuscate with hexadecimal escape sequences (e.g., \xHH)
- Obfuscate with octal escape sequences (e.g., \ooo)
- Obfuscate with Unicode escape sequences (e.g., \uHHHH)
- Obfuscate with HTML entity references (e.g., &-xHH;)
- Obfuscate with URL encoding
- Obfuscate with base64 encoding
- Obfuscate with double URL encoding
- Obfuscate with HTML entity references (e.g., &-HHHH;)
- Obfuscate with HTML entity references (e.g., &amp;HHHH;)
- Obfuscate with mixed character encoding (e.g., %uHH00)
- Obfuscate with URL encoding, lowercase
- Obfuscate with URL encoding, uppercase
- Obfuscate with hexadecimal escape sequences, space-separated (e.g., \xHH )
- Obfuscate with Unicode escape sequences, space-separated (e.g., \uHHHH )
- Obfuscate with base64 encoding, stripping padding characters
- Obfuscate with HTML entity references, breaking it into multiple entities
- Obfuscate with HTML entity references, breaking it into multiple entities
- Obfuscate with HTML entity references, mixing it with hexadecimal encoding
- Obfuscate with base64 encoding, using an alternate encoding scheme
- Obfuscate with base64 encoding, using an alternate encoding scheme and stripping padding characters
- Obfuscate with hexadecimal escape sequences, combining with spaces (e.g., \xHH\xHH)
- Obfuscate with Unicode escape sequences, combining with spaces (e.g., \uHHHH\uHHHH)
- Obfuscate with base64 encoding, using an alternate encoding scheme and adding custom padding
- Obfuscate with hexadecimal escape sequences, using curly braces (e.g., \x{HH})
- Obfuscate with Unicode escape sequences, using curly braces (e.g., \u{HHHH})
- Obfuscate with hexadecimal escape sequences, combining with curly braces (e.g., \x{HH}\x{HH})
- Obfuscate with Unicode escape sequences, combining with curly braces (e.g., \u{HHHH}\u{HHHH})
- Obfuscate with hexadecimal escape sequences, using parentheses (e.g., \x(HH))
- Obfuscate with Unicode escape sequences, using parentheses (e.g., \u(HHHH))
- Obfuscate with hexadecimal escape sequences, combining with parentheses (e.g., \x(HH)\x(HH))
- Obfuscate with Unicode escape sequences, combining with parentheses (e.g., \u(HHHH)\u(HHHH))
- Obfuscate with hexadecimal escape sequences, using square brackets (e.g., \x[HH])
- Obfuscate with Unicode escape sequences, using square brackets (e.g., \u[HHHH])
- Obfuscate with hexadecimal escape sequences, combining with square brackets (e.g., \x[HH]\x[HH])
- Obfuscate with Unicode escape sequences, combining with square brackets (e.g., \u[HHHH]\u[HHHH])
- Obfuscate with hexadecimal escape sequences, using angle brackets (e.g., \x<HH>)
- Obfuscate with Unicode escape sequences, using angle brackets (e.g., \u<HHHH>)
- Obfuscate with hexadecimal escape sequences, combining with angle brackets (e.g., \x<HH>\x<HH>)
- Obfuscate with Unicode escape sequences, combining with angle brackets (e.g., \u<HHHH>\u<HHHH>)
- Obfuscate with hexadecimal escape sequences, using square brackets and spaces (e.g., \x[HH] )
- Obfuscate with Unicode escape sequences, using square brackets and spaces (e.g., \u[HHHH] )
- Obfuscate with hexadecimal escape sequences, combining with square brackets and spaces (e.g., \x[HH] \x[HH] )
- Obfuscate with Unicode escape sequences, combining with square brackets and spaces (e.g., \u[HHHH] \u[HHHH] )
- Obfuscate with hexadecimal escape sequences, using angle brackets and spaces (e.g., \x<HH> )
- Obfuscate with Unicode escape sequences, using angle brackets and spaces (e.g., \u<HHHH> )
- Obfuscate with hexadecimal escape sequences, combining with angle brackets and spaces (e.g., \x<HH> \x<HH> )
- Obfuscate with Unicode escape sequences, combining with angle brackets and spaces (e.g., \u<HHHH> \u<HHHH> )

## Screenshots

![Alt text](https://i.ibb.co/m80rg2C/upme.png)



## Benchmark

- **Concurrency**: The code use multithreading and multiprocessing enhances performance by enabling concurrent execution of tasks.
 
- **I/O and Network Efficiency**: The code use network requests, optimizing I/O and network operations including managing network latency, connection reuse.

- **Performance**: Multiprocessing is suitable for CPU-bound tasks, while multithreading is effective for I/O-bound tasks, which code automatically decides.

- **Tuning**: The code adjusts itself for threads and processes based on the specific hardware and network present which optimize performance.


## Usage

1. Clone the repository.
2. Install the required dependencies.
3. Specify the target domain or provide a list of URLs.
4. Run the tool with the desired options.

## Usage Example

```bash
python3 XSSInspector.py -t 50 --output vulnerable.txt -s --deepcrawl --report report_template.html -d testphp.vulnweb.com
