import requests
# Membuat Fungsi Pengecekan dengan Payload XSS
def check_xss(url, xss_payloads):
    try:
        # Iterasi melalui setiap payload XSS
        for payload in xss_payloads:
            # Membentuk URL dengan menambahkan payload XSS
            full_url = f"{url}{payload}"
            
            # Mengirim permintaan GET ke URL dengan payload
            response = requests.get(full_url)

            # Memeriksa apakah payload terdapat dalam teks respons halaman
            if payload in response.text:
                print(f"XSS vulnerability found in: {full_url}")
            else:
                print(f"No XSS vulnerability found in: {full_url}")

    except requests.RequestException as e:
        print(f"Error checking for XSS: {e}")
        
# Membuat Fungsi Pengecekan dengan Payload SQL
def check_sql_injection(url, sql_payloads):
    try:
        # Iterasi melalui setiap payload SQL Injection
        for payload in sql_payloads:
            # Membentuk URL dengan menambahkan parameter id dan payload SQL Injection
            full_url = f"{url}?id={payload}"
            
            # Mengirim permintaan GET ke URL dengan payload
            response = requests.get(full_url)

            # Memeriksa apakah teks "error" atau "exception" terkandung dalam teks respons halaman
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

    # Membaca payload XSS dari file
    with open(xss_payloads_file, 'r') as xss_file:
        xss_payloads = xss_file.read().splitlines()

    # Membaca payload SQL dari file
    with open(sql_payloads_file, 'r') as sql_file:
        sql_payloads = sql_file.read().splitlines()

    # Memanggil fungsi check XSS untuk menjalankan program
    check_xss(target_url, xss_payloads)

    # Memanggil fungsi check SQL untuk menjalankan program
    check_sql_injection(target_url, sql_payloads)
