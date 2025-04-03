# Kṣetra-jñam-v2 (The knower of the field)

---
![ksetra_jnam](https://github.com/user-attachments/assets/9e3bfdab-c601-4a2e-8a01-59bbf2223406)
---
## Kṣetra-jñam-v2: A Web App Vulnerability Scanner

### Disclaimer:

Kṣetra-jñam (the knower of the field) is a web application vulnerability scanner that uses both GUI and CLI interfaces to detects and report on security issues based on OWASP Top 10 and beyond. With multiple scanning algorithms and customizable reporting, it helps developers and security teams identify and address critical security risks. Developed by Asim Tara Pathak.

## Features:
- **30+ Vulnerability Checks**:
  - OWASP Top 10 vulnerabilities
  - Server misconfigurations
  - Cryptographic weakness, etc.
- **Multiple Report Formats**: PDF, HTML, JSON, CSV
- **Advanced Scanning**:
  - Port scanning (with Nmap integration)
  - Technology fingerprinting
  - Authentication testing

## Installation:

**Note**: Python-3 must be installed in your device
**Install Nmap (for port scanning):**
Windows: Download from https://nmap.org
Linux/Mac: sudo apt-get install nmap or brew install nmap

1. Clone the Ksetra-jnam-v2 repository to your local machine
```
  gh repo clone asimtarapathak/Ksetra-Jnam_v2
```
2. Extract the file and Navigate to the Ksetra-jnam directory:
```
  cd Ksetra-Jnam_v2
```
3. Run cmd and Install the required dependencies using pip:
```
  pip install -r requirements.txt
```
![image](https://github.com/user-attachments/assets/3fe5dba9-f39c-45c5-8811-fac2c5d4b792)


## Usage:

Ksetra-jnam-v2 takes URL as input/argunment starting with format 'http or https://'. -h option can be used to see the usage menu.
```
 python Ksetra-jnam_v2.0_cli.py -h
```
![image](https://github.com/user-attachments/assets/de738786-1a36-4f35-b339-2398949cacac)
---

Scanning web app or URL and saving report:
```
Examples:
  1. python Ksetra-jnam_v2.0_cli.py -v -r -a http://testphp.vulnweb.com/login.php

  2. python Ksetra-jnam_v2.0_cli.py -v -r -a --format html -o http://testphp.vulnweb.com/login.php
```
---
![image](https://github.com/user-attachments/assets/d8646280-237e-4384-8909-74113b6251ac)
![image](https://github.com/user-attachments/assets/6b859f92-e771-4e66-8b7d-e0eaf0c31a23)
![image](https://github.com/user-attachments/assets/b8a337da-a5c8-4b69-858d-827fd37b5c86)
---

Screenshot of Report generated by Ksetra-jnam-v2:
---
![image](https://github.com/user-attachments/assets/d7567fc8-0275-4b3b-8785-b5603d9b6684)
![image](https://github.com/user-attachments/assets/4cdc450a-a862-4008-8e15-e3b877334f65)
---

**Screenshot of GUI version of Kṣetra-jñam-v2:**
---
![image](https://github.com/user-attachments/assets/fdeea6b2-dc67-460a-9e95-95f0e3f19a54)
---

Thank you for using Kṣetra-jñam! If you have any queries or feedback, please don't hesitate to reach out. :)
