**XSS dan SQL Injection Scan**

1. Sebelum menjalankan program, komputer harus terinstall python3 dan untuk memaksimalkan penggunaan dapat diunduh library python3-colorama

   pip3 install colorama

2. Untuk melakukan running dapat diunduh file dengan menjalankan 

   git clone https://github.com/faizalwahyu/SimpleVulnCheck

3. Untuk melakukkan running program dapat menggunakan Python3

   python3 simplevulncheck.py

Keterangan : 
1. Program yang dibuat akan memberikan 3 opsi yaitu :	a. XSS scan dengan URL	b. XSS scan dengan Form	c. SQL Injection scan

2. Setiap Opsi akan diminta untuk memasukkan informasi URL Target dan Payload yang digunakan

3. Program akan memberikan output dengan keterangan : Warna Merah mengindikasikan terdapat kerentanan dan Warna Hijau tidak ada kerentanan

4. Selain itu juga program akan menghasilkan output berupa file txt sesuai dengan letak program dijalankan
