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

## False Positive Damp Approach

1. In an effort to reduce false positives when hunting for XSS vulnerabilities, this tool employs a False Positive Damping approach.
2. It automatically sends a HEAD request to the URL and checks the `Content-Type` header of the response. 
3. The tool examines `Content-Type` header indicates that the URL points to a non-HTML or non-PHP file (e.g., images, non-web content), the tool bypasses the URL link.
4. Parameter Analysis: For each URL, it analysis the query parameters to identify parameters that may be related to file handling. This includes parameters such as "file," "path," "image," "download," etc.
5. Parameter Whitelisting: It creats whitelist parameters that are known to be safe and not associated with file handling. 
6. Filtering: Before testing a payload against a URL, it checks if any of the query parameters match the file-related keywords. 

   
## Heuristic Logic:
XSSInspector heuristic logic into the scanner allows it to analyze response content for indicators like "alert" messages and script tags, thus making it more adept at identifying potential XSS vulnerabilities. By focusing on these common XSS patterns, the scanner is more efficient in its detection approach, reducing false positives and enhancing its precision.

## Obfuscation Logic:
XSSInspector obfuscation logic introduces various encoding techniques, including hex encoding, unicode encoding, base64 encoding, double encoding, and more, to generate a wide range of obfuscated payloads. This diversification of payloads significantly improves the scanner's evasion capabilities by making it challenging for security filters to detect and mitigate attacks.

## Obfuscation Security Testing

- - No Obfuscation: This method keeps the payload as it is without any changes.
- Replace "alert" with "confirm": If the payload contains the word "alert," it replaces it with "confirm."
- Hex Encoding: Encodes the payload characters in hexadecimal format (e.g., \x41 for 'A').
- Unicode Encoding: Encodes the payload characters in Unicode format (e.g., \u0041 for 'A').
- Base64 Encoding: Encodes the payload using Base64 encoding.
- UTF-16 Encoding (with error handling): Encodes the payload using UTF-16 encoding with error handling to handle character encoding issues.
- UTF-32 Encoding (with error handling): Encodes the payload using UTF-32 encoding with error handling.
- ROT13 Encoding (with error handling): Applies ROT13 encoding to the payload with error handling.
- Percent Encoding: Encodes the payload using percent encoding (e.g., %20 for space).
- HTML Entity Encoding: Replaces special characters in the payload with their corresponding HTML entities (e.g., &lt; for '<' and &gt; for '>').
- Null Byte Encoding: Replaces 'a' with '\x00a' and 'l' with '\x00c' in the payload.
vBase64 Encoding: Encodes the payload using Base64 encoding.
- UTF-16 Little-Endian Encoding: Encodes the payload using UTF-16 Little-Endian encoding.
- UTF-32 Little-Endian Encoding: Encodes the payload using UTF-32 Little-Endian encoding.
- Reverse the Payload: Reverses the characters in the payload.
- Convert to Uppercase: Changes the payload to uppercase.
- Convert to Lowercase: Changes the payload to lowercase.
- Swap Case: Swaps the case of characters in the payload (e.g., 'AaBb' becomes 'aAbB').
- Uppercase Percent-Encoded Unicode: Encodes characters in the payload using uppercase Unicode percent encoding with 8-character hexadecimal values.
- Lowercase Percent-Encoded Unicode: Encodes characters in the payload using lowercase Unicode percent encoding with 8-character hexadecimal values.
- Percent Encoding with Spaces: Encodes the payload using percent encoding and adds a space character after each encoded character.
- Unicode Percent Encoding with Spaces: Encodes the payload using Unicode percent encoding with 4-character hexadecimal values and adds a space character after each encoded character.
- HTML Entity Encoding for < and >: Replaces the < and > characters in the payload with their corresponding HTML entity codes.
- HTML Entity Encoding for " and ': Replaces double quotes (") and single quotes (') in the payload with their respective HTML entity codes.
- Single Backslash Escaping: Escapes each character in the payload with a single backslash, such as \a, \b, \c, etc.
- Double Backslash Escaping: Escapes each character in the payload with two backslashes, like \\a, \\b, \\c, etc.
- Percent Encoding with Spaces: Encodes the payload characters using percent encoding and adds a space character after each encoded character.
- HTML Entity Encoding with Spaces: Uses HTML entity encoding with 4-character hexadecimal values and adds a space character after each encoded character.

## XSSInsecptor Obfuscation & Heuristic Benefits:

- Enhanced Detection Accuracy: The heuristic logic fine-tunes the scanner to detect XSS vulnerabilities more accurately by concentrating on common attack patterns.
- Reduced False Positives: The heuristic logic helps minimize false positives by identifying potential vulnerabilities based on known attack indicators.
- Evasion and Bypass Capabilities: Obfuscation logic strengthens the scanner's evasion techniques, making it harder for security mechanisms to thwart attacks.
- Comprehensive Testing: With obfuscation techniques, the scanner thoroughly tests potential vulnerabilities by employing multiple payload variations.
- Improved Reliability: The combination of heuristic and obfuscation logic ensures a more reliable and effective XSS scanner, resulting in precise vulnerability identification and decreased security risks.


## POC of XSSInspector

1. This proof of concept demonstrates a method for processing a large number of URLs rapidly and detecting cross-site scripting (XSS) vulnerabilities and their types in real-time.
2. It showcases how XSSInspector can process 6887 URLs within seconds and identify potential security issues as they occur.
3. It removes duplicates.
4. It performs lightning-fast processing.
5. It automatically crawls URLs for vulnerable links and forms.

## Working Screenshots

- Windows/Mac/Linux GUI:

![Alt text](https://i.ibb.co/sWLnP0m/xssinecptorgui.png)

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
