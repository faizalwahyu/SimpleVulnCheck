**XSS dan SQL Injection Scan**

1. Before running the program, Python3 must be installed on your computer. To optimize usage, you can also install the Python library colorama by running:

   pip3 install colorama

2. To run the program, first download the files by executing:n 

   git clone https://github.com/faizalwahyu/SimpleVulnCheck

3. To run the program, use Python3:

   python3 simplevulncheck.py

Description:

The program provides 3 options:
    a. XSS scan using URL
    b. XSS scan using Form
    c. SQL Injection scan

For each option, you will be asked to enter the Target URL and the Payload to be used.

The program outputs results with color indications:

   a. Red color indicates a vulnerability is found

   b. Green color indicates no vulnerability detected

Additionally, the program generates a text output file in the same directory where the program is run.
