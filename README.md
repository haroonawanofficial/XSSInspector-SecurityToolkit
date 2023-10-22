# XSSInspector
The Advanced XSS Reporter is a powerful security tool designed to combat Cross-Site Scripting (XSS) threats—a pervasive and dangerous issue in web applications. This open-source solution simplifies XSS vulnerability identification and mitigation, serving as a valuable asset for security experts and developers.

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


## Usage

1. Clone the repository.
2. Install the required dependencies.
3. Specify the target domain or provide a list of URLs.
4. Run the tool with the desired options.

## Usage Example

```bash
python xssinspector.py -s --deepcrawl -o vulnerableurls.txt -d example.com -t 50 --report report.html
