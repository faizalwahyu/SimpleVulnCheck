import requests
import re
import os
import urllib.parse
import time
from colorama import init, Fore

# Inisialisasi colorama (Untuk membedakan warna ditemukan kerentanan atau tidak)
init(autoreset=True)

#Validasi input user
def get_valid_input(prompt, is_file_path=False):
    while True:
        user_input = input(prompt)
        if is_file_path and not os.path.isfile(user_input):
            print(Fore.RED + "Path file tidak valid. Harap masukkan path file yang valid.")
        elif not user_input:
            print(Fore.RED + "Input tidak boleh kosong. Harap masukkan input yang valid.")
        else:
            return user_input

def print_and_write(file, message, color=Fore.GREEN):
    print(color + message)
    file.write(message + '\n')

#Fungsi Cek Kerentanan XSS URL
def check_xss(url, xss_payloads, output_file):
    try:
        session = requests.Session()
        response = session.get(url)

        if response.status_code != 200:
            print(Fore.RED + f"Error mengakses URL: {url}")
            return

        with open(output_file, 'w') as result_file:
            for payload in xss_payloads:
                encoded_payload = urllib.parse.quote(payload)
                modified_payload = f'{encoded_payload}'
                full_url = f"{url}?cat={modified_payload}"

                response = session.get(full_url)

                time.sleep(1)

                if payload in response.text:
                    # Jika payload ditemukan, print dengan warna merah
                    print_and_write(result_file, f"Kerentanan XSS ditemukan pada: {full_url} dengan payload: {payload}", color=Fore.RED)
                else:
                    # Jika payload tidak ditemukan, print dengan warna hijau
                    print_and_write(result_file, f"Tidak ditemukan Kerentanan XSS pada: {full_url} dengan payload: {payload}", color=Fore.GREEN)

        print(Fore.GREEN + f"Hasil scan disimpan di: {output_file}")

    except requests.RequestException as e:
        print(Fore.RED + f"Error saat pemeriksaan XSS: {e}")

#Fungsi Cek Kerentanan XSS dari Form
def check_xss_input_fields(url, xss_payloads, output_file):
    try:
        session = requests.Session()
        response = session.get(url)

        if response.status_code == 200:
            html_content = response.text
            input_fields = extract_input_fields(html_content)

            if input_fields:
                print(Fore.CYAN + "Input fields found on the page:")
                for field in input_fields:
                    print(field)

                print(Fore.YELLOW + "Performing XSS check on each input field:")

                with open(output_file, 'w') as result_file:
                    for field in input_fields:
                        input_field_name = field['name']

                        for payload in xss_payloads:
                            modified_payload = f'{payload}'
                            modified_form_data = {input_field_name: modified_payload}
                            response = session.post(url, data=modified_form_data)

                            time.sleep(1)

                            if payload in response.text:
                                finding = f"Kerentanan XSS ditemukan pada: '{input_field_name}' dengan payload: {payload}"
                                print_and_write(result_file, finding, color=Fore.RED)
                            else:
                                finding = f"Tidak ditemukan Kerentanan XSS pada: '{input_field_name}' dengan payload: {payload}"
                                print_and_write(result_file, finding, color=Fore.GREEN)

                print(Fore.GREEN + f"XSS input field check results saved in: {output_file}")

            else:
                print(Fore.GREEN + f"Hasil scan disimpan di: {output_file}")
        else:
            print(Fore.RED + f"Error untuk mengakses URL: {url}")

    except requests.RequestException as e:
        print(Fore.RED + f"Error saat pemeriksaan XSS: {e}")

#Fungsi Cek Kerentanan SQL Injection
def check_sql_injection(url, sql_payloads, output_file):
    try:
        session = requests.Session()
        with open(output_file, 'w') as result_file:
            for payload in sql_payloads:
                modified_url = f"{url}?id={payload}"
                response = session.get(modified_url)

                if "error" in response.text.lower() or "exception" in response.text.lower():
                    # Jika payload ditemukan, print dengan warna hijau
                    print_and_write(result_file, f"Kerentanan SQL Injection ditemukan pada: {modified_url} dengan payload: {payload}")
                else:
                    if "desired_behavior_indicator" in response.text.lower():
                        # Jika payload ditemukan, print dengan warna hijau
                        print_and_write(result_file, f"Kerentanan SQL Injection ditemukan pada: {modified_url} dengan payload: {payload}")
                    else:
                        # Jika payload tidak ditemukan, print dengan warna kuning
                        print_and_write(result_file, f"Tidak ditemukan Kerentanan SQL Injection pada: {modified_url} dengan payload: {payload}", color=Fore.YELLOW)

        print(Fore.GREEN + f"Hasil scan disimpan di: {output_file}")

    except requests.RequestException as e:
        print(Fore.RED + f"Error saat memeriksa SQL Injection: {e}")

#Fungsi Ekstraksi Form dari URL
def extract_input_fields(html_content):
    input_fields = []
    pattern = re.compile(r'<input.*?name=[\'"](.*?)[\'"].*?>', re.DOTALL | re.IGNORECASE)
    matches = pattern.finditer(html_content)

    for match in matches:
        field_name = match.group(1)
        input_fields.append({'name': field_name})

    return input_fields

if __name__ == "__main__":
    print(Fore.YELLOW + "Pilih jenis kerentanan yang akan di-scan:")
    print(Fore.CYAN + "1. XSS (URL)")
    print(Fore.CYAN + "2. XSS (Form)")
    print(Fore.CYAN + "3. SQL Injection")

    choice = input("Masukkan pilihan Anda (1, 2, atau 3): ")

    output_file_name = get_valid_input("Masukkan nama file output (Tanpa Ekstensi): ")

    script_directory = os.path.dirname(os.path.realpath(__file__))
    output_file = os.path.join(script_directory, f"{output_file_name}.txt")

    if choice == "1":
        target_url = get_valid_input("Masukkan target URL untuk XSS: ")
        xss_payloads_file = get_valid_input("Masukkan path file payload XSS (Payload_XSS.txt) : ", is_file_path=True)

        with open(xss_payloads_file, 'r') as xss_file:
            xss_payloads = xss_file.read().splitlines()

        check_xss(target_url, xss_payloads, output_file)

    elif choice == "2":
        target_url = get_valid_input("Masukkan target URL untuk XSS Form: ")
        xss_payloads_file = get_valid_input("Masukkan path file payload XSS (Payload_XSS.txt) : ", is_file_path=True)

        with open(xss_payloads_file, 'r') as xss_file:
            xss_payloads = xss_file.read().splitlines()

        check_xss_input_fields(target_url, xss_payloads, output_file)

    elif choice == "3":
        target_url_sql = get_valid_input("Masukkan target URL untuk SQL Injection: ")
        sql_payloads_file = get_valid_input("Masukkan path file payload SQL Injection (Payload_SQL.txt) : ", is_file_path=True)

        with open(sql_payloads_file, 'r') as sql_file:
            sql_payloads = sql_file.read().splitlines()

        check_sql_injection(target_url_sql, sql_payloads, output_file)

    else:
        print(Fore.RED + "Pilihan tidak valid. Harap masukkan '1' untuk XSS (URL), '2' untuk XSS (Form), atau '3' untuk SQL Injection.")
