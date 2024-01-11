import requests

def check_xss(url, xss_payloads):
    try:
        for payload in xss_payloads:
            full_url = f"{url}{payload}"
            response = requests.get(full_url)

            if payload in response.text:
                print(f"XSS vulnerability found in: {full_url}")
            else:
                print(f"No XSS vulnerability found in: {full_url}")

    except requests.RequestException as e:
        print(f"Error checking for XSS: {e}")

def check_sql_injection(url, sql_payloads):
    try:
        for payload in sql_payloads:
            full_url = f"{url}?id={payload}"
            response = requests.get(full_url)

            if "error" in response.text.lower() or "exception" in response.text.lower():
                print(f"SQL Injection vulnerability found in: {full_url}")
            else:
                print(f"No SQL Injection vulnerability found in: {full_url}")

    except requests.RequestException as e:
        print(f"Error checking for SQL Injection: {e}")

if __name__ == "__main__":
    target_url = input("Enter the target URL: ")
    xss_payloads_file = input("Enter the path to the XSS payload file: ")
    sql_payloads_file = input("Enter the path to the SQL Injection payload file: ")

    # Read XSS payloads from the file
    with open(xss_payloads_file, 'r') as xss_file:
        xss_payloads = xss_file.read().splitlines()

    # Read SQL Injection payloads from the file
    with open(sql_payloads_file, 'r') as sql_file:
        sql_payloads = sql_file.read().splitlines()

    # Check for XSS vulnerability
    check_xss(target_url, xss_payloads)

    # Check for SQL Injection vulnerability
    check_sql_injection(target_url, sql_payloads)
