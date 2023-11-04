# XSSInspector
The XSSInspector is a powerful security tool designed to find Cross-Site Scripting (XSS) threats—a pervasive and dangerous issue in web applications. This open-source solution simplifies XSS vulnerability identification and mitigation, serving as a valuable asset for security experts and developers.

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

## Obfuscations with Bypassing (92 special modes are supported built-in)

- Parameter pollution built-in; software auto use it when necessary.
- 1. Obfuscate with hexadecimal escape sequences (e.g., \xHH)
- 2. Obfuscate with Unicode escape sequences (e.g., \uHHHH)
- 3. Base64 encode the payload
- 4. Encode the payload in UTF-16
- 5. Encode the payload with ROT13
- 6. Obfuscate with percent-encoded characters (e.g., %HH)
- 7. Obfuscate with HTML entity references (e.g., &-xHH;)
- 8. Replace 'a' with null character '\x00a' and 'l' with '\x00c' (if a string)
- 9. Encode the payload in UTF-16LE
- 10. Encode the payload in UTF-32LE
- 11. Reverse the payload
- 12. Convert payload to uppercase
- 13. Convert payload to lowercase
- 14. Swap case of the payload characters
- 15. Obfuscate with hexadecimal escape sequences (e.g., \xHH)
- 16. Obfuscate with Unicode escape sequences (e.g., \uHHHH)
- 17. Encode the payload in UTF-32BE
- 18. Obfuscate with Unicode escape sequences (e.g., \uHHHH)
- 19. Obfuscate with hexadecimal escape sequences (e.g., \xHHHHHHHH)
- 20. Obfuscate with hexadecimal escape sequences (e.g., \xHH)
- 21. Obfuscate with hexadecimal escape sequences (e.g., \xHH)
- 22. Obfuscate with Unicode escape sequences (e.g., \uHHHH)
- 23. Join words with plus symbols
- 24. Remove null characters (if a string)
- 25. Obfuscate with hexadecimal escape sequences (e.g., \xHH)
- 26. Replace '<' with '&lt;' and '>' with '&gt;'
- 27. Replace double quotes and single quotes with HTML entity references
- 28. Obfuscate with backslashes (e.g., \char)
- 29. Obfuscate with double backslashes (e.g., \\char)
- 30. Obfuscate with percent-encoded characters (e.g., %uHHHH)
- 31. Obfuscate with percent-encoded characters (e.g., %HH)
- 32. Obfuscate with Unicode escape sequences (e.g., \UHHHHHHHH)
- 33. Obfuscate with percent-encoded characters (e.g., %HH; )
- 34. Obfuscate with percent-encoded characters (e.g., %uHHHH; )
- 35. Obfuscate with percent-encoded characters (e.g., %HH )
- 36. Obfuscate with HTML entity references (e.g., &-xHH;)
- 37. Replace '1' with 'I' and '0' with 'O' (if a string)
- 38. Obfuscate with percent-encoded characters (e.g., %HH)
- 39. Obfuscate with HTML entity references (e.g., &-xHH;)
- 40. Replace 'a' with null character '\x00a' and 'l' with '\x00c' (if a string)
- 41. Encode the payload in UTF-16LE
- 42. Encode the payload in UTF-32LE
- 43. Obfuscate with percent-encoded characters (e.g., %uHHHH; )
- 44. Replace '<' with '&lt;' and '>' with '&gt;'
- 45. Encode the payload in UTF-32BE
- 46. Remove null characters (if a string)
- 47. Obfuscate with HTML entities for special characters
- 48. Obfuscate with hexadecimal escape sequences (e.g., \xHH)
- 49. Obfuscate with octal escape sequences (e.g., \ooo)
- 50. Obfuscate with Unicode escape sequences (e.g., \uHHHH)
- 51. Obfuscate with HTML entity references (e.g., &-xHH;)
- 52. Obfuscate with URL encoding
- 53. Obfuscate with base64 encoding
- 54. Obfuscate with double URL encoding
- 55. Obfuscate with HTML entity references (e.g., &-HHHH;)
- 56. Obfuscate with HTML entity references (e.g., &amp;HHHH;)
- 57. Obfuscate with mixed character encoding (e.g., %uHH00)
- 58. Obfuscate with URL encoding, lowercase
- 59. Obfuscate with URL encoding, uppercase
- 60. Obfuscate with hexadecimal escape sequences, space-separated (e.g., \xHH )
- 61. Obfuscate with Unicode escape sequences, space-separated (e.g., \uHHHH )
- 62. Obfuscate with base64 encoding, stripping padding characters
- 63. Obfuscate with HTML entity references, breaking it into multiple entities
- 64. Obfuscate with HTML entity references, breaking it into multiple entities
- 65. Obfuscate with HTML entity references, mixing it with hexadecimal encoding
- 66. Obfuscate with base64 encoding, using an alternate encoding scheme
- 67. Obfuscate with base64 encoding, using an alternate encoding scheme and stripping padding characters
- 68. Obfuscate with hexadecimal escape sequences, combining with spaces (e.g., \xHH\xHH)
- 69. Obfuscate with Unicode escape sequences, combining with spaces (e.g., \uHHHH\uHHHH)
- 70. Obfuscate with base64 encoding, using an alternate encoding scheme and adding custom padding
- 71. Obfuscate with hexadecimal escape sequences, using curly braces (e.g., \x{HH})
- 72. Obfuscate with Unicode escape sequences, using curly braces (e.g., \u{HHHH})
- 73. Obfuscate with hexadecimal escape sequences, combining with curly braces (e.g., \x{HH}\x{HH})
- 74. Obfuscate with Unicode escape sequences, combining with curly braces (e.g., \u{HHHH}\u{HHHH})
- 75. Obfuscate with hexadecimal escape sequences, using parentheses (e.g., \x(HH))
- 76. Obfuscate with Unicode escape sequences, using parentheses (e.g., \u(HHHH))
- 77. Obfuscate with hexadecimal escape sequences, combining with parentheses (e.g., \x(HH)\x(HH))
- 78. Obfuscate with Unicode escape sequences, combining with parentheses (e.g., \u(HHHH)\u(HHHH))
- 79. Obfuscate with hexadecimal escape sequences, using square brackets (e.g., \x[HH])
- 80. Obfuscate with Unicode escape sequences, using square brackets (e.g., \u[HHHH])
- 81. Obfuscate with hexadecimal escape sequences, combining with square brackets (e.g., \x[HH]\x[HH])
- 82. Obfuscate with Unicode escape sequences, combining with square brackets (e.g., \u[HHHH]\u[HHHH])
- 83. Obfuscate with hexadecimal escape sequences, using angle brackets (e.g., \x<HH>)
- 84. Obfuscate with Unicode escape sequences, using angle brackets (e.g., \u<HHHH>)
- 85. Obfuscate with hexadecimal escape sequences, combining with angle brackets (e.g., \x<HH>\x<HH>)
- 86. Obfuscate with Unicode escape sequences, combining with angle brackets (e.g., \u<HHHH>\u<HHHH>)
- 87. Obfuscate with hexadecimal escape sequences, using square brackets and spaces (e.g., \x[HH] )
- 88. Obfuscate with Unicode escape sequences, using square brackets and spaces (e.g., \u[HHHH] )
- 89. Obfuscate with hexadecimal escape sequences, combining with square brackets and spaces (e.g., \x[HH] \x[HH] )
- 90. Obfuscate with Unicode escape sequences, combining with square brackets and spaces (e.g., \u[HHHH] \u[HHHH] )
- 91. Obfuscate with hexadecimal escape sequences, using angle brackets and spaces (e.g., \x<HH> )
- 92. Obfuscate with Unicode escape sequences, using angle brackets and spaces (e.g., \u<HHHH> )
- 93. Obfuscate with hexadecimal escape sequences, combining with angle brackets and spaces (e.g., \x<HH> \x<HH> )
- 94. Obfuscate with Unicode escape sequences, combining with angle brackets and spaces (e.g., \u<HHHH> \u<HHHH> )

## Screenshots

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
