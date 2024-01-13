# Mengimpor modul yang dibutuhkan
import requests
import re
import os
import urllib.parse
import time
from colorama import init, Fore

# Inisialisasi colorama (Untuk membedakan warna ditemukan kerentanan atau tidak)
init(autoreset=True)

# Validasi input user
def get_valid_input(prompt, is_file_path=False):
    while True:
        user_input = input(prompt)
        if is_file_path and not os.path.isfile(user_input):
            print(Fore.RED + "Path file tidak valid. Harap masukkan path file yang valid.")
        elif not user_input:
            print(Fore.RED + "Input tidak boleh kosong. Harap masukkan input yang valid.")
        else:
            return user_input

# Fungsi untuk mencetak pesan ke layar dan menulisnya ke file
def print_and_write(file, message, color=Fore.GREEN):
    print(color + message)
    file.write(message + '\n')

# Fungsi Cek Kerentanan XSS URL
def check_xss(url, xss_payloads, output_file):
    try:
        # Membuat sesi HTTP
        session = requests.Session()
        # Mengirimkan permintaan GET ke URL target
        response = session.get(url)

        # Memeriksa apakah responsenya sukses (status code 200 OK)
        if response.status_code != 200:
            print(Fore.RED + f"Error mengakses URL: {url}")
            return

        # Membuka file untuk menyimpan hasil scan
        with open(output_file, 'w') as result_file:
            # Iterasi melalui setiap payload XSS
            for payload in xss_payloads:
                # Melakukan encoding pada payload
                encoded_payload = urllib.parse.quote(payload)
                modified_payload = f'{encoded_payload}'
                full_url = f"{url}?cat={modified_payload}"

                # Mengirimkan permintaan GET dengan payload XSS yang dimodifikasi
                response = session.get(full_url)

                # Menunggu sejenak untuk memberi waktu eksekusi JavaScript yang bersifat asinkron
                time.sleep(1)

                # Memeriksa apakah payload XSS dapat ditemukan dalam respons
                if payload in response.text:
                    # Jika payload ditemukan, mencetak dengan warna merah
                    print_and_write(result_file, f"Kerentanan XSS ditemukan pada: {full_url} dengan payload: {payload}", color=Fore.RED)
                else:
                    # Jika payload tidak ditemukan, mencetak dengan warna hijau
                    print_and_write(result_file, f"Tidak ditemukan Kerentanan XSS pada: {full_url} dengan payload: {payload}", color=Fore.GREEN)

        # Menyampaikan pesan bahwa hasil scan telah disimpan
        print(Fore.GREEN + f"Hasil scan disimpan di: {output_file}")

    except requests.RequestException as e:
        # Menangkap dan mencetak kesalahan jika ada masalah pada permintaan HTTP
        print(Fore.RED + f"Error saat pemeriksaan XSS: {e}")

# Fungsi Cek Kerentanan XSS dari Form
def check_xss_input_fields(url, xss_payloads, output_file):
    try:
        # Membuat sesi HTTP
        session = requests.Session()
        # Mengirimkan permintaan GET ke URL target
        response = session.get(url)

        # Memeriksa apakah responsenya sukses (status code 200 OK)
        if response.status_code == 200:
            # Mengambil isi HTML dari respons
            html_content = response.text
            # Ekstraksi input fields dari form dalam HTML
            input_fields = extract_input_fields(html_content)

            # Memeriksa apakah ada input fields yang ditemukan
            if input_fields:
                # Mencetak nama-nama input fields yang ditemukan
                print(Fore.CYAN + "Input fields found on the page:")
                for field in input_fields:
                    print(field)

                # Mencetak pesan untuk memberitahu bahwa pemeriksaan XSS pada setiap input field akan dilakukan
                print(Fore.YELLOW + "Performing XSS check on each input field:")

                # Membuka file untuk menyimpan hasil scan
                with open(output_file, 'w') as result_file:
                    # Iterasi melalui setiap input field
                    for field in input_fields:
                        input_field_name = field['name']

                        # Iterasi melalui setiap payload XSS
                        for payload in xss_payloads:
                            modified_payload = f'{payload}'
                            modified_form_data = {input_field_name: modified_payload}
                            # Mengirimkan permintaan POST dengan payload XSS yang dimodifikasi
                            response = session.post(url, data=modified_form_data)

                            # Menunggu sejenak untuk memberi waktu eksekusi JavaScript yang bersifat asinkron
                            time.sleep(1)

                            # Memeriksa apakah payload XSS dapat ditemukan dalam respons
                            if payload in response.text:
                                # Jika payload ditemukan, mencetak dengan warna merah
                                finding = f"Kerentanan XSS ditemukan pada input field '{input_field_name}' dengan payload: {payload}"
                                print_and_write(result_file, finding, color=Fore.RED)
                            else:
                                # Jika payload tidak ditemukan, mencetak dengan warna hijau
                                finding = f"Tidak ditemukan Kerentanan XSS pada input field '{input_field_name}' dengan payload: {payload}"
                                print_and_write(result_file, finding, color=Fore.GREEN)

                # Menyampaikan pesan bahwa hasil scan telah disimpan
                print(Fore.GREEN + f"XSS input field check results saved in: {output_file}")

            else:
                # Jika tidak ada input fields yang ditemukan
                print(Fore.RED + "No input fields found on the page.")
        else:
            # Jika responsenya bukan 200 OK
            print(Fore.RED + f"Error accessing URL: {url}")

    except requests.RequestException as e:
        # Menangkap dan mencetak kesalahan jika ada masalah pada permintaan HTTP
        print(Fore.RED + f"Error checking XSS: {e}")

# Fungsi Cek Kerentanan SQL Injection
def check_sql_injection(url, sql_payloads, output_file):
    try:
        # Membuat sesi HTTP
        session = requests.Session()
        # Membuka file untuk menyimpan hasil scan
        with open(output_file, 'w') as result_file:
            # Iterasi melalui setiap payload SQL Injection
            for payload in sql_payloads:
                # Membuat URL yang dimodifikasi dengan menambahkan payload sebagai parameter 'id'
                modified_url = f"{url}?id={payload}"
                # Mengirimkan permintaan GET dengan payload SQL Injection yang dimodifikasi
                response = session.get(modified_url)

                # Memeriksa apakah terdapat indikasi error dalam respons (case insensitive)
                if "error" in response.text.lower() or "exception" in response.text.lower():
                    # Jika payload ditemukan, mencetak dengan warna merah
                    print_and_write(result_file, f"Kerentanan SQL Injection ditemukan pada: {modified_url} dengan payload: {payload}", color=Fore.RED)
                else:
                    # Jika payload tidak ditemukan, memeriksa indikasi perilaku yang diinginkan dalam respons (case insensitive)
                    if "desired_behavior_indicator" in response.text.lower():
                        # Jika payload ditemukan, mencetak dengan warna merah
                        print_and_write(result_file, f"Kerentanan SQL Injection ditemukan pada: {modified_url} dengan payload: {payload}", color=Fore.RED)
                    else:
                        # Jika payload tidak ditemukan, mencetak dengan warna hijau
                        print_and_write(result_file, f"Tidak ditemukan Kerentanan SQL Injection pada: {modified_url} dengan payload: {payload}", color=Fore.GREEN)

        # Menyampaikan pesan bahwa hasil scan telah disimpan
        print(Fore.GREEN + f"Hasil scan disimpan di: {output_file}")

    except requests.RequestException as e:
        # Menangkap dan mencetak kesalahan jika ada masalah pada permintaan HTTP
        print(Fore.RED + f"Error saat memeriksa SQL Injection: {e}")


# Fungsi Ekstraksi Form dari URL
def extract_input_fields(html_content):
    input_fields = []
    # Pola regex untuk mengekstrak input fields dari HTML
    pattern = re.compile(r'<input.*?name=[\'"](.*?)[\'"].*?>', re.DOTALL | re.IGNORECASE)
    # Mencari semua kecocokan dalam isi HTML
    matches = pattern.finditer(html_content)

    # Iterasi melalui setiap kecocokan
    for match in matches:
        # Mendapatkan nama input field dari grup pengecualian dalam pola regex
        field_name = match.group(1)
        # Menambahkan nama input field ke dalam list
        input_fields.append({'name': field_name})

    return input_fields

# Blok Utama
if __name__ == "__main__":
    # Menampilkan pilihan jenis kerentanan yang akan di-scan
    print(Fore.YELLOW + "Pilih jenis kerentanan yang akan di-scan:")
    print(Fore.CYAN + "1. XSS (URL)")
    print(Fore.CYAN + "2. XSS (Form)")
    print(Fore.CYAN + "3. SQL Injection")

    # Menerima input pilihan dari pengguna
    choice = input("Masukkan pilihan Anda (1, 2, atau 3): ")

    # Meminta input nama file output tanpa ekstensi
    output_file_name = get_valid_input("Masukkan nama file output (Tanpa Ekstensi): ")

    # Mendapatkan direktori tempat skrip ini berada
    script_directory = os.path.dirname(os.path.realpath(__file__))
    # Menggabungkan direktori dengan nama file output
    output_file = os.path.join(script_directory, f"{output_file_name}.txt")

    # Menjalankan fungsi sesuai dengan pilihan pengguna
    if choice == "1":
        target_url = get_valid_input("Masukkan target URL untuk XSS: ")
        xss_payloads_file = get_valid_input("Masukkan path file payload XSS (Payload_XSS.txt) : ", is_file_path=True)

        # Membaca payload XSS dari file
        with open(xss_payloads_file, 'r') as xss_file:
            xss_payloads = xss_file.read().splitlines()

        # Menjalankan fungsi untuk memeriksa kerentanan XSS pada URL
        check_xss(target_url, xss_payloads, output_file)

    elif choice == "2":
        target_url = get_valid_input("Masukkan target URL untuk XSS Form: ")
        xss_payloads_file = get_valid_input("Masukkan path file payload XSS (Payload_XSS.txt) : ", is_file_path=True)

        # Membaca payload XSS dari file
        with open(xss_payloads_file, 'r') as xss_file:
            xss_payloads = xss_file.read().splitlines()

        # Menjalankan fungsi untuk memeriksa kerentanan XSS pada form
        check_xss_input_fields(target_url, xss_payloads, output_file)

    elif choice == "3":
        target_url_sql = get_valid_input("Masukkan target URL untuk SQL Injection: ")
        sql_payloads_file = get_valid_input("Masukkan path file payload SQL Injection (Payload_SQL.txt) : ", is_file_path=True)

        # Membaca payload SQL Injection dari file
        with open(sql_payloads_file, 'r') as sql_file:
            sql_payloads = sql_file.read().splitlines()

        # Menjalankan fungsi untuk memeriksa kerentanan SQL Injection pada URL
        check_sql_injection(target_url_sql, sql_payloads, output_file)

    else:
        # Jika pilihan tidak valid
        print(Fore.RED + "Pilihan tidak valid. Harap masukkan '1' untuk XSS (URL), '2' untuk XSS (Form), atau '3' untuk SQL Injection.")
