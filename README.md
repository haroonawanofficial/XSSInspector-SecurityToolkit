# XSSInspector
The XSSInspector is a powerful security tool designed to find Cross-Site Scripting (XSS) threats—a pervasive and dangerous issue in web applications. This open-source solution simplifies XSS vulnerability identification and mitigation, serving as a valuable asset for security experts and developers.

## Functionality
XSS Inspector is a powerful tool for identifying and reporting Cross-Site Scripting (XSS) vulnerabilities in web applications. It scans URLs for potential security issues, helping developers and security professionals identify and mitigate XSS threats.

## Features

- **URL Crawling**: XSS Inspector supports various methods of collecting URLs, including Common Crawl, Wayback Machine, and OTX Alienvault.

- **Multi-Threading**: Utilize the power of multi-threading to scan a large number of URLs quickly.

- **Payload Testing**: The tool includes a variety of XSS payloads to test web applications for vulnerabilities.

- **Subdomain Discovery**: The tool collects and includes the results of subdomains in the final list of URLs as not only the URLs associated with the target domain but also its subdomains.

- **Multi Processing**: Built-in python's multiprocessing advantage, which is better suited for CPU-bound tasks like scanning multiple URLs for vulnerabilities.
  
- **Multi Threading**: Built-in python's advantage to use default threads 50 but it goes upto 100 if CPU supports that much suited for tasks like scanning multiple URLs for vulnerabilities.

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

   
## Enahcned Heuristic & Obfuscation Structure and Logic:
- Enhanced Detection Accuracy: The heuristic logic fine-tunes the scanner to detect XSS vulnerabilities more accurately by concentrating on common attack patterns.
- Reduced False Positives: The heuristic logic helps minimize false positives by identifying potential vulnerabilities based on known attack indicators.
- Evasion and Bypass Capabilities: Obfuscation logic strengthens the scanner's evasion techniques, making it harder for security mechanisms to thwart attacks.
- Comprehensive Testing: With obfuscation techniques, the scanner thoroughly tests potential vulnerabilities by employing multiple payload variations.
- Improved Reliability: The combination of heuristic and obfuscation logic ensures a more reliable and effective XSS scanner, resulting in precise vulnerability identification and decreased security risks.

## Obfuscations with Bypassing (71 special modes are supported built-in)

- Parameter pollution built-in; software auto use it when necessary.
- Replace "alert" with "confirm": Replaces "alert" with "confirm" in the payload.
- Hex encoding: Encodes characters in the payload as hexadecimal escape sequences.
- Unicode encoding: Encodes characters in the payload as Unicode escape sequences.
- Base64 encoding: Encodes the payload using Base64 and decodes it back to a string.
- UTF-16 encoding: Encodes the payload using UTF-16 with error handling.
- ROT13 encoding: Applies ROT13 transformation to the payload.
- Percent encoding: Encodes characters in the payload as percent-encoded ASCII.
- HTML Entity encoding: Encodes characters as HTML entities.
- Null Byte encoding: Replaces 'a' with '\x00a' and 'l' with '\x00c'.
- Base64 encoding: Encodes the payload using Base64 (deprecated).
- UTF-16 Little-Endian encoding: Encodes using UTF-16 little-endian with error handling.
- UTF-32 Little-Endian encoding: Encodes using UTF-32 little-endian with error handling.
- Reverse the payload: Reverses the order of characters in the payload.
- Convert to uppercase: Changes the payload to uppercase.
- Convert to lowercase: Changes the payload to lowercase.
- Swap case: Swaps the case of characters in the payload.
- Percent-Encoded Unicode: Encodes characters as percent-encoded Unicode.
- Percent-Encoded ASCII: Encodes characters as percent-encoded ASCII.
- Uppercase Percent-Encoded Unicode: Encodes characters as uppercase percent-encoded Unicode.
- Percent Encoding with Spaces: Encodes characters as percent-encoded ASCII with spaces.
- Unicode Percent Encoding with Spaces: Encodes characters as Unicode escape sequences with spaces.
- HTML Entity Encoding for < and >: Encodes '<' as '<' and '>' as '>'.
- HTML Entity Encoding for " and ': Encodes double quotes as '"' and single quotes as '''.
- Single Backslash Escaping: Adds a single backslash before each character.
- Double Backslash Escaping: Adds double backslashes before each character.
- Hexadecimal Percent Encoding: Encodes characters as hexadecimal percent-encoded ASCII.
- Unicode Escape Sequence: Encodes characters as Unicode escape sequences.
- UTF-32 Big-Endian Encoding: Encodes the payload using UTF-32 big-endian with error handling.
- Hexadecimal Unicode Encoding: Encodes characters as hexadecimal Unicode escape sequences.
- Double Hex Encoding: Encodes characters with double hexadecimal escape sequences.
- Double Hex Encoding with Spaces: Encodes characters with double hexadecimal escape sequences and spaces.
- Double Unicode Encoding with Spaces: Encodes characters with double Unicode escape sequences and spaces.
- HTML Entity Encoding for <, >, and &: Encodes '<' as '<', '>' as '>', and '&' as '&'.
- Remove Line Breaks: Removes newline characters.
- Replace Tabs with Space: Replaces tab characters with spaces.
- Replace Line Breaks with Space: Replaces newline and carriage return characters with spaces.
- Uppercase Percent-Encoded Unicode with Spaces: Encodes characters as uppercase percent-encoded Unicode with spaces.
- Hexadecimal Unicode Encoding with Spaces: Encodes characters as hexadecimal Unicode escape sequences with spaces.
- Double Hex Encoding with Semicolon: Encodes characters with double hexadecimal escape sequences and semicolons.
- Double Unicode Encoding with Semicolon: Encodes characters with double Unicode escape sequences and semicolons.
- Uppercase Percent-Encoded Unicode with Semicolon: Encodes characters as uppercase percent-encoded Unicode with semicolons.
- Hexadecimal Unicode Encoding with Semicolon: Encodes characters as hexadecimal Unicode escape sequences with semicolons.
- Double Hex Encoding with Semicolon: Encodes characters with double hexadecimal escape sequences and semicolons.
- Double Unicode Encoding with Semicolon: Encodes characters with double Unicode escape sequences and semicolons.
- Remove Null Bytes: Removes null bytes from the payload.
- Using the '+' operator to break down payload.


## POC of XSSInspector

1. This proof of concept demonstrates a method for processing a large number of URLs rapidly and detecting cross-site scripting (XSS) vulnerabilities and their types in real-time.
2. It showcases how XSSInspector can process 6887 URLs within seconds and identify potential security issues as they occur.
3. It removes duplicates.
4. It performs lightning-fast processing.
5. It automatically crawls URLs for vulnerable links and forms.

## Working Screenshots

- Windows/Mac/Linux GUI:

![Alt text](https://i.ibb.co/fN7wy3Q/xssinecptorgui.png)

- Example Running from Windows:

![Alt text](https://i.ibb.co/n6GJSJ1/Untitled.png)

- Stored XSS (server side):

![Alt text](https://i.ibb.co/Y3grD7q/Untitled2.png)

- Reflected XSS (client side):

![Alt text](https://i.ibb.co/Brp2tDn/refected-xssinspector.png)


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
