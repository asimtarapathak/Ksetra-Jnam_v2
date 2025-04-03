import requests
from bs4 import BeautifulSoup
import socket
import ssl
from urllib.parse import urlparse, urljoin
import re
import threading
import logging
import argparse
import json
import time
import os
from datetime import datetime
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from fpdf import FPDF, HTMLMixin
from colorama import Fore, Back, Style, init
import dns.resolver
import xml.etree.ElementTree as ET
import csv
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
import nmap
import whois
import random
import string
from tqdm import tqdm
import locale

locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')  # Force UTF-8 locale

# Initialize colorama
init(autoreset=True)

# Configure logging
logger = logging.getLogger()
log_format = '%(message)s'  # No date/time

# Constants
VERSION = "2.0.0"
BANNER = f"""
██╗  ██╗███████╗███████╗████████╗██████╗  █████╗            ██╗███╗   ██╗ █████╗ ███╗   ███╗
██║ ██╔╝██╔════╝██╔════╝╚══██╔══╝██╔══██╗██╔══██╗           ██║████╗  ██║██╔══██╗████╗ ████║
█████╔╝ ███████╗█████╗     ██║   ██████╔╝███████║█████╗     ██║██╔██╗ ██║███████║██╔████╔██║
██╔═██╗ ╚════██║██╔══╝     ██║   ██╔══██╗██╔══██║╚════╝██   ██║██║╚██╗██║██╔══██║██║╚██╔╝██║
██║  ██╗███████║███████╗   ██║   ██║  ██║██║  ██║      ╚█████╔╝██║ ╚████║██║  ██║██║ ╚═╝ ██║
╚═╝  ╚═╝╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝       ╚════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝     ╚═╝
"""

DESCRIPTION = f"""
Kṣetra-jñam (the knower of the field) v{VERSION}
A comprehensive web application vulnerability scanner with GUI and CLI interfaces.
Detects OWASP Top 10 vulnerabilities and more with multiple scanning algorithms.

-> Made by Asim Tara Pathak
"""

# Custom PDF class with HTML support
class PDF(FPDF, HTMLMixin):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'Ksetra-Jnam - Vulnerability Assessment Report', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

# Function to configure logging based on verbosity
def configure_logging(verbose):
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=log_level, format=log_format)

# Retry configuration for network requests
def get_session_with_retries():
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"]
    )
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

# Function to validate URL format
def validate_url(url):
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = f"http://{url}"
            parsed_url = urlparse(url)
        
        if not parsed_url.netloc:
            try:
                socket.inet_aton(url)
                return True, url
            except socket.error:
                return False, url
        return bool(parsed_url.scheme) and bool(parsed_url.netloc), url
    except Exception as e:
        return False, url

# Function to generate random user agent
def get_random_user_agent():
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
    ]
    return random.choice(user_agents)

# Function to check if URL is alive
def check_url_availability(url, session):
    try:
        headers = {'User-Agent': get_random_user_agent()}
        response = session.head(url, headers=headers, timeout=10, allow_redirects=True)
        return response.status_code < 400
    except requests.RequestException:
        return False

# Enhanced report generation
def generate_report(vulnerabilities, target, report_format='pdf', output_dir='reports'):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"vulnerability_report_{timestamp}"
    
    if report_format.lower() == 'pdf':
        generate_pdf_report(vulnerabilities, target, os.path.join(output_dir, f"{filename}.pdf"))
    elif report_format.lower() == 'html':
        generate_html_report(vulnerabilities, target, os.path.join(output_dir, f"{filename}.html"))
    elif report_format.lower() == 'json':
        generate_json_report(vulnerabilities, target, os.path.join(output_dir, f"{filename}.json"))
    elif report_format.lower() == 'csv':
        generate_csv_report(vulnerabilities, target, os.path.join(output_dir, f"{filename}.csv"))
    else:
        logger.error(f"Unsupported report format: {report_format}")
        return None
    
    return os.path.join(output_dir, f"{filename}.{report_format.lower()}")

def generate_pdf_report(vulnerabilities, target, output_path):
    pdf = PDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # Report header
    pdf.set_font('Arial', 'B', 16)
    pdf.cell(0, 10, 'Ksetra-Jnam - Vulnerability Assessment Report', 0, 1, 'C')
    pdf.ln(10)
    
    # Scan metadata
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Scan Details', 0, 1)
    pdf.set_font('Arial', '', 10)
    pdf.cell(0, 6, f'Target: {target}', 0, 1)
    pdf.cell(0, 6, f'Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1)
    pdf.cell(0, 6, f'Total vulnerabilities found: {len([v for v in vulnerabilities if v["result"] != "Safe"])}', 0, 1)
    pdf.ln(10)
    
    # Vulnerability summary
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Vulnerability Summary', 0, 1)
    
    # Summary table
    pdf.set_font('Arial', 'B', 10)
    pdf.cell(60, 6, 'Vulnerability', 1, 0, 'C')
    pdf.cell(30, 6, 'Status', 1, 0, 'C')
    pdf.cell(30, 6, 'Severity', 1, 1, 'C')
    
    pdf.set_font('Arial', '', 10)
    for vuln in vulnerabilities:
        severity = "High" if vuln["result"] == "Vulnerable" else "Low" if vuln["result"] == "Safe" else "Info"
        pdf.cell(60, 6, vuln["check_name"], 1)
        pdf.cell(30, 6, vuln["result"], 1)
        pdf.cell(30, 6, severity, 1)
        pdf.ln()
    
    pdf.ln(10)
    
    # Detailed findings
    pdf.set_font('Arial', 'B', 12)
    pdf.cell(0, 10, 'Detailed Findings', 0, 1)
    
    for i, vuln in enumerate(vulnerabilities, 1):
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(0, 6, f'{i}. {vuln["check_name"]}', 0, 1)
        pdf.set_font('Arial', '', 10)
        
        # Status with color indication
        status_color = (255, 0, 0) if vuln["result"] == "Vulnerable" else (0, 128, 0) if vuln["result"] == "Safe" else (0, 0, 255)
        pdf.set_text_color(*status_color)
        pdf.cell(0, 6, f'Status: {vuln["result"]}', 0, 1)
        pdf.set_text_color(0, 0, 0)
        
        # Details
        pdf.multi_cell(0, 6, f'Details: {vuln["details"]}')
        pdf.ln(5)
    
    # Footer with scan metadata
    pdf.set_font('Arial', 'I', 8)
    # pdf.cell(0, 10, f'Generated by Kṣetra-jñam v{VERSION} on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 0, 'C')
    pdf.cell(0, 10, f'Generated by Kshetra-jnam v{VERSION}...', 0, 0, 'C')

    pdf.output(output_path)
    logger.info(f"\n{Fore.GREEN}Report generated: {output_path}{Style.RESET_ALL}")

def generate_html_report(vulnerabilities, target, output_path):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    critical_count = len([v for v in vulnerabilities if v["result"] == "Vulnerable"])
    warning_count = len([v for v in vulnerabilities if v["result"] == "Warning"])
    safe_count = len([v for v in vulnerabilities if v["result"] == "Safe"])
    
    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ksetra-Jnam - Vulnerability Assessment Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; margin: 0; padding: 20px; color: #333; }}
        .header {{ text-align: center; margin-bottom: 30px; }}
        .scan-info {{ margin-bottom: 20px; }}
        .summary {{ margin-bottom: 30px; }}
        .vulnerability {{ margin-bottom: 20px; border: 1px solid #ddd; padding: 15px; border-radius: 5px; }}
        .vulnerability-title {{ font-weight: bold; font-size: 1.2em; margin-bottom: 10px; }}
        .vulnerable {{ color: #d9534f; }}
        .safe {{ color: #5cb85c; }}
        .warning {{ color: #f0ad4e; }}
        .info {{ color: #5bc0de; }}
        .severity {{ display: inline-block; padding: 3px 8px; border-radius: 3px; font-weight: bold; }}
        .severity-high {{ background-color: #d9534f; color: white; }}
        .severity-medium {{ background-color: #f0ad4e; color: white; }}
        .severity-low {{ background-color: #5cb85c; color: white; }}
        .severity-info {{ background-color: #5bc0de; color: white; }}
        .details {{ margin-top: 10px; }}
        .summary-card {{ display: inline-block; padding: 15px; margin: 0 10px 10px 0; border-radius: 5px; color: white; }}
        .critical {{ background-color: #d9534f; }}
        .warnings {{ background-color: #f0ad4e; }}
        .safe {{ background-color: #5cb85c; }}
        .footer {{ margin-top: 30px; text-align: center; font-size: 0.9em; color: #777; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Ksetra-Jnam - Vulnerability Assessment Report</h1>
    </div>
    
    <div class="scan-info">
        <h2>Scan Information</h2>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Scan Date:</strong> {timestamp}</p>
        <p><strong>Scanner Version:</strong> Kṣetra-jñam v{VERSION}</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <div>
            <span class="summary-card critical">Critical: {critical_count}</span>
            <span class="summary-card warnings">Warnings: {warning_count}</span>
            <span class="summary-card safe">Safe: {safe_count}</span>
        </div>
    </div>
    
    <div class="findings">
        <h2>Detailed Findings</h2>
    """

    for i, vuln in enumerate(vulnerabilities, 1):
        severity_class = "vulnerable" if vuln["result"] == "Vulnerable" else "safe" if vuln["result"] == "Safe" else "warning"
        severity_level = "high" if vuln["result"] == "Vulnerable" else "low" if vuln["result"] == "Safe" else "medium"
        
        html_content += f"""
        <div class="vulnerability">
            <div class="vulnerability-title">
                {i}. {vuln["check_name"]}
                <span class="{severity_class}">({vuln["result"]})</span>
                <span class="severity severity-{severity_level}">{severity_level.upper()}</span>
            </div>
            <div class="details">
                <p>{vuln["details"]}</p>
            </div>
        </div>
        """

    html_content += f"""
    </div>
    
    <div class="footer">
        <p>Report generated by Kṣetra-jñam v{VERSION} on {timestamp}</p>
    </div>
</body>
</html>
    """

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger.info(f"\n{Fore.GREEN}HTML report generated: {output_path}{Style.RESET_ALL}")
    return output_path

def generate_json_report(vulnerabilities, target, output_path):
    report_data = {
        "metadata": {
            "scanner": "Kṣetra-jñam",
            "version": VERSION,
            "target": target,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "statistics": {
                "total": len(vulnerabilities),
                "vulnerable": len([v for v in vulnerabilities if v["result"] == "Vulnerable"]),
                "warnings": len([v for v in vulnerabilities if v["result"] == "Warning"]),
                "safe": len([v for v in vulnerabilities if v["result"] == "Safe"])
            }
        },
        "findings": vulnerabilities
    }
    
    with open(output_path, 'w') as f:
        json.dump(report_data, f, indent=2)
    
    logger.info(f"\n{Fore.GREEN}JSON report generated: {output_path}{Style.RESET_ALL}")
    return output_path

def generate_csv_report(vulnerabilities, target, output_path):
    with open(output_path, 'w', newline='') as csvfile:
        fieldnames = ['check_name', 'result', 'details', 'severity']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        
        writer.writeheader()
        for vuln in vulnerabilities:
            severity = "High" if vuln["result"] == "Vulnerable" else "Low" if vuln["result"] == "Safe" else "Medium"
            writer.writerow({
                'check_name': vuln["check_name"],
                'result': vuln["result"],
                'details': vuln["details"],
                'severity': severity
            })
    
    logger.info(f"\n{Fore.GREEN}CSV report generated: {output_path}{Style.RESET_ALL}")
    return output_path

# Enhanced vulnerability check functions

def check_broken_access_control(url, session):
    logger.info(f"\n{Fore.BLUE}[Broken Access Control Check] Testing {url} for access control issues...{Style.RESET_ALL}")
    try:
        test_urls = [
            "/admin", "/dashboard", "/config", "/wp-admin", "/administrator",
            "/phpmyadmin", "/dbadmin", "/mysql", "/sqladmin"
        ]
        
        results = []
        for test_path in test_urls:
            test_url = urljoin(url, test_path)
            try:
                response = session.get(test_url, timeout=10, allow_redirects=False)
                
                if response.status_code == 200:
                    results.append(f"Accessible admin panel found at {test_url}")
                elif response.status_code == 403:
                    results.append(f"Access denied (403) for {test_url} - proper access control in place")
                elif 300 <= response.status_code < 400:
                    results.append(f"Redirect ({response.status_code}) for {test_url} - may indicate access control")
                
            except Exception as e:
                logger.debug(f"Error checking {test_url}: {str(e)}")
        
        if results:
            return {
                "check_name": "Broken Access Control", 
                "result": "Vulnerable" if any("Accessible admin panel" in r for r in results) else "Warning",
                "details": "\n".join(results)
            }
        else:
            return {
                "check_name": "Broken Access Control", 
                "result": "Safe", 
                "details": "No common admin paths accessible without authentication"
            }
    except Exception as e:
        logger.error(f"[Broken Access Control Check] Error: {e}")
        return {
            "check_name": "Broken Access Control", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_cryptographic_failures(url, session):
    logger.info(f"\n{Fore.BLUE}[Cryptographic Failures Check] Testing {url} for cryptographic issues...{Style.RESET_ALL}")
    try:
        issues = []
        
        # Check if HTTPS is used
        if not url.startswith("https://"):
            issues.append("Website does not use HTTPS for secure communication.")
        else:
            # Check SSL/TLS configuration
            try:
                hostname = urlparse(url).netloc
                context = ssl.create_default_context()
                with socket.create_connection((hostname, 443)) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        
                        # Check certificate expiration
                        expiry_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if expiry_date < datetime.now():
                            issues.append("SSL certificate has expired.")
                        elif (expiry_date - datetime.now()).days < 30:
                            issues.append(f"SSL certificate expires soon ({expiry_date.strftime('%Y-%m-%d')}).")
                        
                        # Check protocol version
                        if ssock.version() in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
                            issues.append(f"Insecure protocol version detected: {ssock.version()}")
                        
                        # Check cipher strength
                        cipher = ssock.cipher()
                        if cipher and 'ADH' in cipher[0] or 'AECDH' in cipher[0]:
                            issues.append(f"Insecure cipher suite detected: {cipher[0]}")
            
            except ssl.SSLError as e:
                issues.append(f"SSL/TLS error: {str(e)}")
        
        if issues:
            return {
                "check_name": "Cryptographic Failures", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "Cryptographic Failures", 
                "result": "Safe", 
                "details": "No cryptographic issues detected. HTTPS is properly configured."
            }
    except Exception as e:
        logger.error(f"[Cryptographic Failures Check] Error: {e}")
        return {
            "check_name": "Cryptographic Failures", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_sql_injection(url, session):
    logger.info(f"\n{Fore.BLUE}[SQL Injection Check] Testing {url} for SQL Injection vulnerabilities...{Style.RESET_ALL}")
    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        test_payloads = [
            "' OR '1'='1", 
            "' OR 1=1 --", 
            "\" OR \"\"=\"", 
            "1; DROP TABLE users", 
            "1' UNION SELECT 1,2,3--",
            "1' WAITFOR DELAY '0:0:10'--"
        ]

        vulnerabilities = []
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            form_data = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                if name and input_tag.get('type') in ('text', 'password', 'search', None):
                    form_data[name] = random.choice(test_payloads)
            
            if form_data:
                full_url = urljoin(url, action) if action else url
                
                try:
                    if method == 'get':
                        response = session.get(full_url, params=form_data, timeout=10)
                    else:
                        response = session.post(full_url, data=form_data, timeout=10)
                    
                    error_indicators = [
                        "SQL syntax",
                        "MySQL error",
                        "ORA-",
                        "unclosed quotation mark",
                        "syntax error",
                        "unexpected end",
                        "SQL Server",
                        "PostgreSQL",
                        "ODBC",
                        "JDBC",
                        "database error"
                    ]
                    
                    if any(indicator.lower() in response.text.lower() for indicator in error_indicators):
                        vuln_details = f"Potential SQL Injection in form at {full_url} with payloads: {form_data}"
                        vulnerabilities.append(vuln_details)
                
                except Exception as e:
                    logger.debug(f"Error testing form at {full_url}: {str(e)}")
        
        if vulnerabilities:
            return {
                "check_name": "SQL Injection", 
                "result": "Vulnerable", 
                "details": "\n".join(vulnerabilities)
            }
        else:
            return {
                "check_name": "SQL Injection", 
                "result": "Safe", 
                "details": "No SQL Injection vulnerabilities detected in forms."
            }
    except Exception as e:
        logger.error(f"[SQL Injection Check] Error: {e}")
        return {
            "check_name": "SQL Injection", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_xss(url, session):
    logger.info(f"\n{Fore.BLUE}[XSS Check] Testing {url} for Cross-Site Scripting vulnerabilities...{Style.RESET_ALL}")
    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        test_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "\"><script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<svg/onload=alert('XSS')>"
        ]

        vulnerabilities = []
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            form_data = {}
            for input_tag in inputs:
                name = input_tag.get('name')
                if name and input_tag.get('type') in ('text', 'password', 'search', None):
                    form_data[name] = random.choice(test_payloads)
            
            if form_data:
                full_url = urljoin(url, action) if action else url
                
                try:
                    if method == 'get':
                        response = session.get(full_url, params=form_data, timeout=10)
                    else:
                        response = session.post(full_url, data=form_data, timeout=10)
                    
                    # Check if payload appears in response unencoded
                    for payload in test_payloads:
                        if payload in response.text:
                            vuln_details = f"Potential XSS in form at {full_url} with payload: {payload}"
                            vulnerabilities.append(vuln_details)
                
                except Exception as e:
                    logger.debug(f"Error testing form at {full_url}: {str(e)}")
        
        # Also check URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                param_name = param.split('=')[0]
                test_url = url.replace(param, f"{param_name}={random.choice(test_payloads)}")
                try:
                    response = session.get(test_url, timeout=10)
                    for payload in test_payloads:
                        if payload in response.text:
                            vuln_details = f"Potential XSS in URL parameter {param_name} with payload: {payload}"
                            vulnerabilities.append(vuln_details)
                except Exception as e:
                    logger.debug(f"Error testing URL parameter {param_name}: {str(e)}")
        
        if vulnerabilities:
            return {
                "check_name": "Cross-Site Scripting (XSS)", 
                "result": "Vulnerable", 
                "details": "\n".join(vulnerabilities)
            }
        else:
            return {
                "check_name": "Cross-Site Scripting (XSS)", 
                "result": "Safe", 
                "details": "No XSS vulnerabilities detected in forms or URL parameters."
            }
    except Exception as e:
        logger.error(f"[XSS Check] Error: {e}")
        return {
            "check_name": "Cross-Site Scripting (XSS)", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_command_injection(url, session):
    logger.info(f"\n{Fore.BLUE}[Command Injection Check] Testing {url} for Command Injection...{Style.RESET_ALL}")
    try:
        test_payloads = [
            "; ls",
            "| ls",
            "&& ls",
            "|| ls",
            "$(ls)",
            "`ls`",
            "<?php system('ls'); ?>",
            "| dir",
            "&& dir",
            "|| dir"
        ]

        vulnerabilities = []
        
        # Test URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                param_name = param.split('=')[0]
                for payload in test_payloads:
                    test_url = url.replace(param, f"{param_name}={payload}")
                    try:
                        response = session.get(test_url, timeout=10)
                        if "bin" in response.text or "ls" in response.text or "Directory of" in response.text:
                            vuln_details = f"Potential command injection in parameter {param_name} with payload: {payload}"
                            vulnerabilities.append(vuln_details)
                    except Exception as e:
                        logger.debug(f"Error testing parameter {param_name}: {str(e)}")
        
        # Test forms
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')

        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for payload in test_payloads:
                form_data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name and input_tag.get('type') in ('text', 'password', 'search', None):
                        form_data[name] = payload
                
                if form_data:
                    full_url = urljoin(url, action) if action else url
                    
                    try:
                        if method == 'get':
                            response = session.get(full_url, params=form_data, timeout=10)
                        else:
                            response = session.post(full_url, data=form_data, timeout=10)
                        
                        if "bin" in response.text or "ls" in response.text or "Directory of" in response.text:
                            vuln_details = f"Potential command injection in form at {full_url} with payload: {payload}"
                            vulnerabilities.append(vuln_details)
                    
                    except Exception as e:
                        logger.debug(f"Error testing form at {full_url}: {str(e)}")
        
        if vulnerabilities:
            return {
                "check_name": "Command Injection", 
                "result": "Vulnerable", 
                "details": "\n".join(vulnerabilities)
            }
        else:
            return {
                "check_name": "Command Injection", 
                "result": "Safe", 
                "details": "No command injection vulnerabilities detected."
            }
    except Exception as e:
        logger.error(f"[Command Injection Check] Error: {e}")
        return {
            "check_name": "Command Injection", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_insecure_design(url, session):
    logger.info(f"\n{Fore.BLUE}[Insecure Design Check] Testing {url} for insecure design...{Style.RESET_ALL}")
    try:
        issues = []
        
        # Check for autocomplete on password fields
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        password_fields = soup.find_all('input', {'type': 'password'})
        
        for field in password_fields:
            if field.get('autocomplete') != 'off':
                issues.append("Password field has autocomplete enabled (security risk).")
        
        # Check for predictable resource locations
        common_files = [
            "/robots.txt", "/sitemap.xml", "/.git/config", "/.env",
            "/.htaccess", "/phpinfo.php", "/test.php", "/debug.php"
        ]
        
        for file in common_files:
            test_url = urljoin(url, file)
            try:
                response = session.get(test_url, timeout=5)
                if response.status_code == 200:
                    issues.append(f"Sensitive file accessible: {test_url}")
            except:
                pass
        
        # Check for information disclosure in error messages
        test_url = urljoin(url, "/nonexistent-page-" + ''.join(random.choices(string.ascii_lowercase, k=8)))
        try:
            response = session.get(test_url, timeout=5)
            if "stack trace" in response.text.lower() or "database error" in response.text.lower():
                issues.append("Detailed error messages disclosed (potential information leak).")
        except:
            pass
        
        if issues:
            return {
                "check_name": "Insecure Design", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "Insecure Design", 
                "result": "Safe", 
                "details": "No obvious insecure design patterns detected."
            }
    except Exception as e:
        logger.error(f"[Insecure Design Check] Error: {e}")
        return {
            "check_name": "Insecure Design", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_security_misconfiguration(url, session):
    logger.info(f"\n{Fore.BLUE}[Security Misconfiguration Check] Testing {url} for misconfigurations...{Style.RESET_ALL}")
    try:
        issues = []
        
        # Check HTTP headers
        headers_response = check_http_headers(url, session)
        if headers_response["result"] == "Vulnerable":
            issues.append(headers_response["details"])
        
        # Check directory listing
        test_dirs = ["/images", "/assets", "/static", "/uploads"]
        for directory in test_dirs:
            test_url = urljoin(url, directory)
            try:
                response = session.get(test_url, timeout=5)
                if "Index of" in response.text or "<title>Directory listing for" in response.text.lower():
                    issues.append(f"Directory listing enabled at {test_url}")
            except:
                pass
        
        # Check for default files
        default_files = [
            "/readme.md", "/README.txt", "/CHANGELOG.txt",
            "/license.txt", "/LICENSE.md", "/INSTALL.txt"
        ]
        for file in default_files:
            test_url = urljoin(url, file)
            try:
                response = session.get(test_url, timeout=5)
                if response.status_code == 200:
                    issues.append(f"Default file accessible: {test_url}")
            except:
                pass
        
        # Check for server information disclosure
        response = session.get(url, timeout=10)
        server_header = response.headers.get('Server', '').lower()
        if 'apache' in server_header or 'nginx' in server_header or 'iis' in server_header:
            issues.append(f"Server information disclosed in headers: {response.headers.get('Server')}")
        
        if issues:
            return {
                "check_name": "Security Misconfiguration", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "Security Misconfiguration", 
                "result": "Safe", 
                "details": "No obvious security misconfigurations detected."
            }
    except Exception as e:
        logger.error(f"[Security Misconfiguration Check] Error: {e}")
        return {
            "check_name": "Security Misconfiguration", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_outdated_components(url, session):
    logger.info(f"\n{Fore.BLUE}[Vulnerable Components Check] Testing {url} for outdated components...{Style.RESET_ALL}")
    try:
        issues = []
        
        response = session.get(url, timeout=10)
        
        # Check headers for version information
        if 'X-Powered-By' in response.headers:
            issues.append(f"Technology disclosure in X-Powered-By header: {response.headers['X-Powered-By']}")
        
        if 'Server' in response.headers:
            issues.append(f"Server version disclosed: {response.headers['Server']}")
        
        # Check for common JavaScript libraries with known vulnerabilities
        common_libs = {
            "jquery.js": "Check jQuery version for known vulnerabilities",
            "bootstrap.js": "Check Bootstrap version for known vulnerabilities",
            "angular.js": "Check AngularJS version for known vulnerabilities",
            "react.js": "Check React version for known vulnerabilities",
            "vue.js": "Check Vue.js version for known vulnerabilities"
        }
        
        soup = BeautifulSoup(response.text, 'html.parser')
        script_tags = soup.find_all('script', src=True)
        
        for script in script_tags:
            src = script['src'].lower()
            for lib in common_libs:
                if lib in src:
                    issues.append(f"Potential outdated library: {lib} - {common_libs[lib]}")
        
        # Check for WordPress (if detected)
        if "wp-content" in response.text or "wp-includes" in response.text:
            issues.append("WordPress detected - check for outdated plugins/themes/core")
        
        if issues:
            return {
                "check_name": "Outdated Components", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "Outdated Components", 
                "result": "Safe", 
                "details": "No obviously outdated components detected (manual verification recommended)."
            }
    except Exception as e:
        logger.error(f"[Outdated Components Check] Error: {e}")
        return {
            "check_name": "Outdated Components", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_authentication_failures(url, session):
    logger.info(f"\n{Fore.BLUE}[Authentication Failures Check] Testing {url} for authentication weaknesses...{Style.RESET_ALL}")
    try:
        issues = []
        
        # Check for login page
        login_urls = ["/login", "/signin", "/auth", "/admin/login"]
        login_found = False
        
        for login_path in login_urls:
            test_url = urljoin(url, login_path)
            try:
                response = session.get(test_url, timeout=5)
                if "login" in response.text.lower() or "sign in" in response.text.lower():
                    login_found = True
                    break
            except:
                pass
        
        if login_found:
            # Test for weak password policy
            test_data = {
                "username": "test",
                "password": "123456"
            }
            
            try:
                response = session.post(test_url, data=test_data, timeout=10)
                if "invalid password" not in response.text.lower() and "incorrect credentials" not in response.text.lower():
                    issues.append("Weak password policy may be in place (accepted simple password)")
            except:
                pass
            
            # Check for brute force protection
            try:
                for _ in range(5):
                    response = session.post(test_url, data={"username": "invalid", "password": "invalid"}, timeout=5)
                
                if "too many attempts" not in response.text.lower() and "locked out" not in response.text.lower():
                    issues.append("No apparent brute force protection detected")
            except:
                pass
            
            # Check for password in URL
            if "password=" in response.text.lower():
                issues.append("Password may be exposed in URL parameters")
        
        else:
            return {
                "check_name": "Authentication Failures", 
                "result": "Info", 
                "details": "No standard login page detected - authentication check skipped."
            }
        
        if issues:
            return {
                "check_name": "Authentication Failures", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "Authentication Failures", 
                "result": "Safe", 
                "details": "No obvious authentication weaknesses detected."
            }
    except Exception as e:
        logger.error(f"[Authentication Failures Check] Error: {e}")
        return {
            "check_name": "Authentication Failures", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_data_integrity(url, session):
    logger.info(f"\n{Fore.BLUE}[Data Integrity Check] Testing {url} for data integrity failures...{Style.RESET_ALL}")
    try:
        issues = []
        
        # Check for lack of CSRF tokens
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            if form.find('input', {'name': 'csrf_token'}) is None and \
               form.find('input', {'name': '_token'}) is None and \
               form.find('input', {'name': 'csrf'}) is None:
                action = form.get('action', '')
                issues.append(f"Potential missing CSRF token in form with action: {action}")
        
        # Check for insecure direct object references
        # This would require knowledge of the application's object reference patterns
        # So we'll just check for common patterns in URLs
        test_urls = [
            "/user/1", "/account/1", "/profile/1", "/document/1"
        ]
        
        for test_path in test_urls:
            test_url = urljoin(url, test_path)
            try:
                response = session.get(test_url, timeout=5)
                if response.status_code == 200:
                    issues.append(f"Potential Insecure Direct Object Reference at {test_url}")
            except:
                pass
        
        if issues:
            return {
                "check_name": "Data Integrity", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "Data Integrity", 
                "result": "Safe", 
                "details": "No obvious data integrity issues detected (limited automated checks performed)."
            }
    except Exception as e:
        logger.error(f"[Data Integrity Check] Error: {e}")
        return {
            "check_name": "Data Integrity", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_logging(url, session):
    logger.info(f"\n{Fore.BLUE}[Security Logging Check] Testing {url} for logging and monitoring failures...{Style.RESET_ALL}")
    try:
        issues = []
        
        # Generate a test error
        test_url = urljoin(url, "/test-error-" + ''.join(random.choices(string.ascii_lowercase, k=8)))
        try:
            response = session.get(test_url, timeout=5)
            
            # Check if error is reflected back to user
            if "404" not in response.text and "not found" not in response.text.lower():
                issues.append("Detailed error messages returned to user (potential information leak)")
        except:
            pass
        
        # Check login failure logging by attempting a failed login
        login_urls = ["/login", "/signin", "/auth", "/admin/login"]
        for login_path in login_urls:
            test_url = urljoin(url, login_path)
            try:
                response = session.get(test_url, timeout=5)
                if "login" in response.text.lower() or "sign in" in response.text.lower():
                    # Attempt failed login
                    test_data = {
                        "username": "invalid_user_" + ''.join(random.choices(string.ascii_lowercase, k=8)),
                        "password": "invalid_password_" + ''.join(random.choices(string.ascii_lowercase, k=8))
                    }
                    response = session.post(test_url, data=test_data, timeout=5)
                    
                    # Check if there's any indication the attempt was logged
                    if "attempt logged" not in response.text.lower() and "suspicious activity" not in response.text.lower():
                        issues.append("No apparent logging of failed login attempts")
                    break
            except:
                pass
        
        if issues:
            return {
                "check_name": "Logging Failures", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "Logging Failures", 
                "result": "Safe", 
                "details": "No obvious logging failures detected (limited automated checks performed)."
            }
    except Exception as e:
        logger.error(f"[Logging Check] Error: {e}")
        return {
            "check_name": "Logging Failures", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_ssrf(url, session):
    logger.info(f"\n{Fore.BLUE}[SSRF Check] Testing {url} for SSRF vulnerabilities...{Style.RESET_ALL}")
    try:
        test_urls = [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://169.254.169.254/latest/meta-data",
            "http://metadata.google.internal",
            "http://localhost",
            "http://0.0.0.0",
            "http://example.com"
        ]
        
        vulnerabilities = []
        
        # First check if there are any parameters that might be vulnerable
        parsed_url = urlparse(url)
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                param_name = param.split('=')[0]
                for payload_url in test_urls:
                    test_url = url.replace(param, f"{param_name}={payload_url}")
                    try:
                        response = session.get(test_url, timeout=10)
                        if response.status_code == 200:
                            if payload_url in response.text or "localhost" in response.text or "127.0.0.1" in response.text:
                                vulnerabilities.append(f"Potential SSRF in parameter {param_name} with payload: {payload_url}")
                    except:
                        pass
        
        # Also check forms
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for payload_url in test_urls:
                form_data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name and input_tag.get('type') in ('text', 'url', None):
                        form_data[name] = payload_url
                
                if form_data:
                    full_url = urljoin(url, action) if action else url
                    
                    try:
                        if method == 'get':
                            response = session.get(full_url, params=form_data, timeout=10)
                        else:
                            response = session.post(full_url, data=form_data, timeout=10)
                        
                        if response.status_code == 200:
                            if payload_url in response.text or "localhost" in response.text or "127.0.0.1" in response.text:
                                vulnerabilities.append(f"Potential SSRF in form at {full_url} with payload: {payload_url}")
                    except:
                        pass
        
        if vulnerabilities:
            return {
                "check_name": "SSRF", 
                "result": "Vulnerable", 
                "details": "\n".join(vulnerabilities)
            }
        else:
            return {
                "check_name": "SSRF", 
                "result": "Safe", 
                "details": "No SSRF vulnerabilities detected."
            }
    except Exception as e:
        logger.error(f"[SSRF Check] Error: {e}")
        return {
            "check_name": "SSRF", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_http_headers(url, session):
    logger.info(f"\n{Fore.BLUE}[HTTP Headers Check] Testing {url} for missing security headers...{Style.RESET_ALL}")
    try:
        response = session.get(url, timeout=10)
        headers = response.headers
        
        missing_headers = []
        insecure_headers = []
        
        # List of security headers to check
        security_headers = {
            'Strict-Transport-Security': {
                'required': url.startswith('https://'),
                'secure_values': ['max-age=31536000', 'includeSubDomains', 'preload']
            },
            'X-Content-Type-Options': {
                'required': True,
                'secure_values': ['nosniff']
            },
            'X-Frame-Options': {
                'required': True,
                'secure_values': ['DENY', 'SAMEORIGIN']
            },
            'Content-Security-Policy': {
                'required': True,
                'secure_values': ["default-src 'self'"]
            },
            'X-XSS-Protection': {
                'required': True,
                'secure_values': ['1; mode=block']
            },
            'Referrer-Policy': {
                'required': False,
                'secure_values': ['no-referrer', 'no-referrer-when-downgrade', 'strict-origin-when-cross-origin']
            },
            'Feature-Policy': {
                'required': False,
                'secure_values': []
            },
            'Permissions-Policy': {
                'required': False,
                'secure_values': []
            }
        }
        
        for header, config in security_headers.items():
            if config['required'] and header not in headers:
                missing_headers.append(header)
            elif header in headers:
                header_value = headers[header]
                if config['secure_values'] and not any(secure_value in header_value for secure_value in config['secure_values']):
                    insecure_headers.append(f"{header}: {header_value} (insecure configuration)")
        
        issues = []
        if missing_headers:
            issues.append("Missing security headers: " + ", ".join(missing_headers))
        if insecure_headers:
            issues.append("Insecure header configurations:\n- " + "\n- ".join(insecure_headers))
        
        if issues:
            return {
                "check_name": "HTTP Headers", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "HTTP Headers", 
                "result": "Safe", 
                "details": "All critical security headers are present and properly configured."
            }
    except Exception as e:
        logger.error(f"[HTTP Headers Check] Error: {e}")
        return {
            "check_name": "HTTP Headers", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_idor(url, session):
    logger.info(f"\n{Fore.BLUE}[IDOR Check] Testing {url} for Insecure Direct Object References...{Style.RESET_ALL}")
    try:
        issues = []
        
        # Check for common patterns in URLs
        test_patterns = [
            "/user/1", "/account/1", "/profile/1", "/document/1",
            "/order/1", "/invoice/1", "/file/1", "/message/1"
        ]
        
        for pattern in test_patterns:
            test_url = urljoin(url, pattern)
            try:
                response = session.get(test_url, timeout=5)
                if response.status_code == 200:
                    issues.append(f"Potential IDOR vulnerability at {test_url}")
            except:
                pass
        
        # Also check for numeric IDs in parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    param_name, param_value = param.split('=', 1)
                    if param_value.isdigit():
                        # Try incrementing/decrementing the ID
                        new_value = str(int(param_value) + 1)
                        test_url = url.replace(param, f"{param_name}={new_value}")
                        try:
                            response = session.get(test_url, timeout=5)
                            if response.status_code == 200:
                                issues.append(f"Potential IDOR vulnerability in parameter {param_name} at {test_url}")
                        except:
                            pass
        
        if issues:
            return {
                "check_name": "Insecure Direct Object References (IDOR)", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "Insecure Direct Object References (IDOR)", 
                "result": "Safe", 
                "details": "No obvious IDOR vulnerabilities detected."
            }
    except Exception as e:
        logger.error(f"[IDOR Check] Error: {e}")
        return {
            "check_name": "Insecure Direct Object References (IDOR)", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_file_inclusion(url, session):
    logger.info(f"\n{Fore.BLUE}[File Inclusion Check] Testing {url} for Local/Remote File Inclusion...{Style.RESET_ALL}")
    try:
        test_payloads = [
            "/etc/passwd",
            "../../../../etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "http://example.com/malicious.txt"
        ]
        
        vulnerabilities = []
        
        # Check URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    param_name = param.split('=')[0]
                    for payload in test_payloads:
                        test_url = url.replace(param, f"{param_name}={payload}")
                        try:
                            response = session.get(test_url, timeout=10)
                            if "root:" in response.text or "[boot loader]" in response.text:
                                vulnerabilities.append(f"Potential file inclusion in parameter {param_name} with payload: {payload}")
                        except:
                            pass
        
        # Check forms
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for payload in test_payloads:
                form_data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name and input_tag.get('type') in ('text', 'file', None):
                        form_data[name] = payload
                
                if form_data:
                    full_url = urljoin(url, action) if action else url
                    
                    try:
                        if method == 'get':
                            response = session.get(full_url, params=form_data, timeout=10)
                        else:
                            response = session.post(full_url, data=form_data, timeout=10)
                        
                        if "root:" in response.text or "[boot loader]" in response.text:
                            vulnerabilities.append(f"Potential file inclusion in form at {full_url} with payload: {payload}")
                    except:
                        pass
        
        if vulnerabilities:
            return {
                "check_name": "File Inclusion", 
                "result": "Vulnerable", 
                "details": "\n".join(vulnerabilities)
            }
        else:
            return {
                "check_name": "File Inclusion", 
                "result": "Safe", 
                "details": "No file inclusion vulnerabilities detected."
            }
    except Exception as e:
        logger.error(f"[File Inclusion Check] Error: {e}")
        return {
            "check_name": "File Inclusion", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_cors(url, session):
    logger.info(f"\n{Fore.BLUE}[CORS Check] Testing {url} for misconfigured CORS policies...{Style.RESET_ALL}")
    try:
        # Test for overly permissive CORS
        headers = {
            'Origin': 'https://evil.com',
            'Access-Control-Request-Method': 'GET'
        }
        
        # First send OPTIONS request to check CORS headers
        try:
            response = session.options(url, headers=headers, timeout=10)
            cors_headers = {
                'Access-Control-Allow-Origin': response.headers.get('Access-Control-Allow-Origin'),
                'Access-Control-Allow-Credentials': response.headers.get('Access-Control-Allow-Credentials'),
                'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods')
            }
            
            issues = []
            if cors_headers['Access-Control-Allow-Origin'] == '*' and cors_headers['Access-Control-Allow-Credentials'] == 'true':
                issues.append("Insecure CORS configuration: Allows credentials with wildcard origin")
            elif cors_headers['Access-Control-Allow-Origin'] == 'https://evil.com':
                issues.append("Insecure CORS configuration: Reflects arbitrary origin")
            
            if issues:
                return {
                    "check_name": "CORS Misconfiguration", 
                    "result": "Vulnerable", 
                    "details": "\n".join(issues)
                }
            else:
                return {
                    "check_name": "CORS Misconfiguration", 
                    "result": "Safe", 
                    "details": "No obvious CORS misconfigurations detected."
                }
        except requests.exceptions.RequestException:
            # If OPTIONS not allowed, try with GET
            response = session.get(url, headers={'Origin': 'https://evil.com'}, timeout=10)
            if response.headers.get('Access-Control-Allow-Origin') == 'https://evil.com':
                return {
                    "check_name": "CORS Misconfiguration", 
                    "result": "Vulnerable", 
                    "details": "Reflects arbitrary origin in CORS headers"
                }
            else:
                return {
                    "check_name": "CORS Misconfiguration", 
                    "result": "Safe", 
                    "details": "No obvious CORS misconfigurations detected."
                }
    except Exception as e:
        logger.error(f"[CORS Check] Error: {e}")
        return {
            "check_name": "CORS Misconfiguration", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_xml_external_entities(url, session):
    logger.info(f"\n{Fore.BLUE}[XXE Check] Testing {url} for XML External Entity vulnerabilities...{Style.RESET_ALL}")
    try:
        # Check if XML is accepted
        headers = {'Content-Type': 'application/xml'}
        test_payload = """<?xml version="1.0"?><root><test>value</test></root>"""
        
        # First try POST request
        try:
            response = session.post(url, headers=headers, data=test_payload, timeout=10)
            if response.status_code == 200:
                # Now test for XXE
                xxe_payload = """<?xml version="1.0"?>
                <!DOCTYPE root [
                <!ENTITY xxe SYSTEM "file:///etc/passwd">
                ]>
                <root>&xxe;</root>"""
                
                response = session.post(url, headers=headers, data=xxe_payload, timeout=10)
                if "root:" in response.text:
                    return {
                        "check_name": "XML External Entities (XXE)", 
                        "result": "Vulnerable", 
                        "details": "XXE vulnerability detected - was able to read /etc/passwd"
                    }
        except:
            pass
        
        # Also check URL parameters for XML processing
        parsed_url = urlparse(url)
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    param_name = param.split('=')[0]
                    test_url = url.replace(param, f"{param_name}={test_payload}")
                    try:
                        response = session.get(test_url, timeout=10)
                        if "XML" in response.headers.get('Content-Type', '') or "<root>" in response.text:
                            # Test for XXE in parameter
                            xxe_test_url = url.replace(param, f"{param_name}={xxe_payload}")
                            response = session.get(xxe_test_url, timeout=10)
                            if "root:" in response.text:
                                return {
                                    "check_name": "XML External Entities (XXE)", 
                                    "result": "Vulnerable", 
                                    "details": f"XXE vulnerability detected in parameter {param_name} - was able to read /etc/passwd"
                                }
                    except:
                        pass
        
        return {
            "check_name": "XML External Entities (XXE)", 
            "result": "Safe", 
            "details": "No XXE vulnerabilities detected."
        }
    except Exception as e:
        logger.error(f"[XXE Check] Error: {e}")
        return {
            "check_name": "XML External Entities (XXE)", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_dom_based_xss(url, session):
    logger.info(f"\n{Fore.BLUE}[DOM-based XSS Check] Testing {url} for DOM-based XSS vulnerabilities...{Style.RESET_ALL}")
    try:
        response = session.get(url, timeout=10)
        
        # Look for common DOM XSS sinks
        dom_xss_patterns = [
            r"document\.write\(.*\)",
            r"innerHTML\s*=",
            r"outerHTML\s*=",
            r"eval\(.*\)",
            r"setTimeout\(.*\)",
            r"setInterval\(.*\)",
            r"location\.hash",
            r"location\.search",
            r"window\.name"
        ]
        
        vulnerabilities = []
        for pattern in dom_xss_patterns:
            if re.search(pattern, response.text):
                vulnerabilities.append(f"Potential DOM-based XSS sink found: {pattern}")
        
        if vulnerabilities:
            return {
                "check_name": "DOM-based XSS", 
                "result": "Vulnerable", 
                "details": "\n".join(vulnerabilities)
            }
        else:
            return {
                "check_name": "DOM-based XSS", 
                "result": "Safe", 
                "details": "No obvious DOM-based XSS vulnerabilities detected."
            }
    except Exception as e:
        logger.error(f"[DOM-based XSS Check] Error: {e}")
        return {
            "check_name": "DOM-based XSS", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_insecure_deserialization(url, session):
    logger.info(f"\n{Fore.BLUE}[Insecure Deserialization Check] Testing {url} for insecure deserialization...{Style.RESET_ALL}")
    try:
        # This is difficult to test automatically, so we'll look for common indicators
        issues = []
        
        # Check for Java serialized objects
        java_serialized_magic_bytes = ["ac ed", "rO0"]
        response = session.get(url, timeout=10)
        
        for magic in java_serialized_magic_bytes:
            if magic in response.text:
                issues.append(f"Potential Java serialized object detected (magic bytes: {magic})")
        
        # Check for .NET ViewState
        if "__VIEWSTATE" in response.text:
            issues.append("ASP.NET ViewState detected - check for insecure deserialization")
        
        # Check for Python pickle
        if "pickle" in response.text.lower():
            issues.append("Python pickle module reference detected - potential insecure deserialization")
        
        if issues:
            return {
                "check_name": "Insecure Deserialization", 
                "result": "Warning", 
                "details": "\n".join(issues) + "\nNote: Insecure deserialization is difficult to detect automatically and requires manual testing."
            }
        else:
            return {
                "check_name": "Insecure Deserialization", 
                "result": "Safe", 
                "details": "No obvious insecure deserialization vectors detected (limited automated checks performed)."
            }
    except Exception as e:
        logger.error(f"[Insecure Deserialization Check] Error: {e}")
        return {
            "check_name": "Insecure Deserialization", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_server_side_request_forgery(url, session):
    logger.info(f"\n{Fore.BLUE}[Server-Side Request Forgery Check] Testing {url} for SSRF vulnerabilities...{Style.RESET_ALL}")
    try:
        # This is similar to our earlier SSRF check but more comprehensive
        test_urls = [
            "http://localhost:8080",
            "http://127.0.0.1:8080",
            "http://169.254.169.254/latest/meta-data",
            "http://metadata.google.internal",
            "http://localhost",
            "http://0.0.0.0",
            "http://example.com"
        ]
        
        vulnerabilities = []
        
        # Check URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    param_name = param.split('=')[0]
                    for payload_url in test_urls:
                        test_url = url.replace(param, f"{param_name}={payload_url}")
                        try:
                            response = session.get(test_url, timeout=10)
                            if response.status_code == 200:
                                if payload_url in response.text or "localhost" in response.text or "127.0.0.1" in response.text:
                                    vulnerabilities.append(f"Potential SSRF in parameter {param_name} with payload: {payload_url}")
                        except:
                            pass
        
        # Check forms
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for payload_url in test_urls:
                form_data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name and input_tag.get('type') in ('text', 'url', None):
                        form_data[name] = payload_url
                
                if form_data:
                    full_url = urljoin(url, action) if action else url
                    
                    try:
                        if method == 'get':
                            response = session.get(full_url, params=form_data, timeout=10)
                        else:
                            response = session.post(full_url, data=form_data, timeout=10)
                        
                        if response.status_code == 200:
                            if payload_url in response.text or "localhost" in response.text or "127.0.0.1" in response.text:
                                vulnerabilities.append(f"Potential SSRF in form at {full_url} with payload: {payload_url}")
                    except:
                        pass
        
        if vulnerabilities:
            return {
                "check_name": "Server-Side Request Forgery (SSRF)", 
                "result": "Vulnerable", 
                "details": "\n".join(vulnerabilities)
            }
        else:
            return {
                "check_name": "Server-Side Request Forgery (SSRF)", 
                "result": "Safe", 
                "details": "No SSRF vulnerabilities detected."
            }
    except Exception as e:
        logger.error(f"[SSRF Check] Error: {e}")
        return {
            "check_name": "Server-Side Request Forgery (SSRF)", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_api_security(url, session):
    logger.info(f"\n{Fore.BLUE}[API Security Check] Testing {url} for common API vulnerabilities...{Style.RESET_ALL}")
    try:
        issues = []
        
        # Check for common API endpoints
        api_endpoints = [
            "/api", "/graphql", "/rest", "/v1", "/v2",
            "/api/users", "/api/products", "/api/auth"
        ]
        
        for endpoint in api_endpoints:
            test_url = urljoin(url, endpoint)
            try:
                response = session.get(test_url, timeout=5)
                if response.status_code == 200:
                    # Check for common API responses
                    if "application/json" in response.headers.get('Content-Type', ''):
                        # Check for authentication requirements
                        if "error" not in response.text.lower() and "unauthorized" not in response.text.lower():
                            issues.append(f"API endpoint {test_url} may not require authentication")
                        
                        # Check for excessive data exposure
                        json_data = response.json()
                        if isinstance(json_data, list) and len(json_data) > 100:
                            issues.append(f"API endpoint {test_url} may expose excessive data (returned {len(json_data)} items)")
            except:
                pass
        
        # Check for GraphQL introspection
        test_url = urljoin(url, "/graphql")
        try:
            introspection_query = {"query": "{__schema {types {name fields {name}}}}"}
            response = session.post(test_url, json=introspection_query, timeout=10)
            if response.status_code == 200 and "__schema" in response.text:
                issues.append("GraphQL introspection enabled - potential information disclosure")
        except:
            pass
        
        if issues:
            return {
                "check_name": "API Security", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "API Security", 
                "result": "Safe", 
                "details": "No obvious API security issues detected (limited automated checks performed)."
            }
    except Exception as e:
        logger.error(f"[API Security Check] Error: {e}")
        return {
            "check_name": "API Security", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_rate_limiting(url, session):
    logger.info(f"\n{Fore.BLUE}[Rate Limiting Check] Testing {url} for lack of rate limiting...{Style.RESET_ALL}")
    try:
        # Try making multiple requests quickly
        test_url = urljoin(url, "/login")  # Typically a sensitive endpoint
        try:
            session.get(test_url, timeout=5)  # First request to ensure endpoint exists
        except:
            test_url = url  # Fall back to main URL if /login doesn't exist
        
        delays = []
        for i in range(5):
            start_time = time.time()
            response = session.get(test_url, timeout=5)
            end_time = time.time()
            delays.append(end_time - start_time)
            time.sleep(0.5)  # Small delay between requests
        
        # Check if response times increase significantly (potential rate limiting)
        if len(delays) > 1 and (max(delays) - min(delays)) > 1.0:
            return {
                "check_name": "Rate Limiting", 
                "result": "Safe", 
                "details": "Potential rate limiting detected (response times increased with multiple requests)."
            }
        else:
            # Now try actual brute force
            try:
                for i in range(10):
                    session.get(test_url, timeout=5)
                
                return {
                    "check_name": "Rate Limiting", 
                    "result": "Vulnerable", 
                    "details": "No rate limiting detected - was able to make 10 quick requests without blocking."
                }
            except Exception as e:
                return {
                    "check_name": "Rate Limiting", 
                    "result": "Safe", 
                    "details": f"Potential rate limiting detected (error on multiple requests: {str(e)})"
                }
    except Exception as e:
        logger.error(f"[Rate Limiting Check] Error: {e}")
        return {
            "check_name": "Rate Limiting", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_dns_security(url, session):
    logger.info(f"\n{Fore.BLUE}[DNS Security Check] Testing DNS configuration for {url}...{Style.RESET_ALL}")
    try:
        issues = []
        domain = urlparse(url).netloc
        
        # Check for DNSSEC
        try:
            answers = dns.resolver.resolve(domain, 'DNSKEY')
            if not answers:
                issues.append("DNSSEC not configured (DNSKEY record missing)")
        except:
            issues.append("DNSSEC not configured or not properly configured")
        
        # Check for SPF record
        try:
            answers = dns.resolver.resolve(domain, 'TXT')
            spf_found = any('v=spf1' in str(r) for r in answers)
            if not spf_found:
                issues.append("SPF record missing (email spoofing risk)")
        except:
            issues.append("SPF record missing (email spoofing risk)")
        
        # Check for DMARC record
        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
            dmarc_found = any('v=DMARC1' in str(r) for r in answers)
            if not dmarc_found:
                issues.append("DMARC record missing (email spoofing risk)")
        except:
            issues.append("DMARC record missing (email spoofing risk)")
        
        # Check for DKIM (this is domain-specific)
        
        if issues:
            return {
                "check_name": "DNS Security", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "DNS Security", 
                "result": "Safe", 
                "details": "Basic DNS security measures (DNSSEC, SPF, DMARC) are configured."
            }
    except Exception as e:
        logger.error(f"[DNS Security Check] Error: {e}")
        return {
            "check_name": "DNS Security", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_email_security(url, session):
    logger.info(f"\n{Fore.BLUE}[Email Security Check] Testing email-related security for {url}...{Style.RESET_ALL}")
    try:
        issues = []
        domain = urlparse(url).netloc
        
        # Check for SMTP TLS
        try:
            with socket.create_connection((f"smtp.{domain}", 25)) as sock:
                resp = sock.recv(1024)
                if b'STARTTLS' not in resp:
                    issues.append("SMTP server does not advertise STARTTLS (email interception risk)")
        except:
            issues.append("Could not verify SMTP TLS configuration")
        
        # Check for open relays (basic check)
        try:
            with socket.create_connection((f"smtp.{domain}", 25)) as sock:
                sock.send(b"EHLO example.com\r\n")
                resp = sock.recv(1024)
                if b'250' in resp:
                    sock.send(b"MAIL FROM:<test@example.com>\r\n")
                    resp = sock.recv(1024)
                    if b'250' in resp:
                        sock.send(b"RCPT TO:<test@example.org>\r\n")
                        resp = sock.recv(1024)
                        if b'250' in resp:
                            issues.append("SMTP server may be an open relay")
        except:
            pass
        
        # Check for email-related security headers in web responses
        response = session.get(url, timeout=10)
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Content-Security-Policy'
        ]
        
        for header in security_headers:
            if header not in response.headers:
                issues.append(f"Missing security header: {header} (phishing protection)")
        
        if issues:
            return {
                "check_name": "Email Security", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "Email Security", 
                "result": "Safe", 
                "details": "Basic email security measures are in place."
            }
    except Exception as e:
        logger.error(f"[Email Security Check] Error: {e}")
        return {
            "check_name": "Email Security", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_clickjacking(url, session):
    logger.info(f"\n{Fore.BLUE}[Clickjacking Check] Testing {url} for clickjacking vulnerabilities...{Style.RESET_ALL}")
    try:
        response = session.get(url, timeout=10)
        
        # Check for X-Frame-Options header
        if 'X-Frame-Options' not in response.headers:
            return {
                "check_name": "Clickjacking", 
                "result": "Vulnerable", 
                "details": "Missing X-Frame-Options header - site may be vulnerable to clickjacking."
            }
        else:
            xfo = response.headers['X-Frame-Options']
            if xfo.upper() not in ('DENY', 'SAMEORIGIN'):
                return {
                    "check_name": "Clickjacking", 
                    "result": "Vulnerable", 
                    "details": f"X-Frame-Options header has potentially insecure value: {xfo}"
                }
        
        # Check for Content-Security-Policy frame-ancestors
        if 'Content-Security-Policy' in response.headers:
            csp = response.headers['Content-Security-Policy']
            if 'frame-ancestors' not in csp.lower():
                return {
                    "check_name": "Clickjacking", 
                    "result": "Warning", 
                    "details": "Content-Security-Policy present but missing frame-ancestors directive."
                }
        
        return {
            "check_name": "Clickjacking", 
            "result": "Safe", 
            "details": "Proper clickjacking protections detected (X-Frame-Options or CSP frame-ancestors)."
        }
    except Exception as e:
        logger.error(f"[Clickjacking Check] Error: {e}")
        return {
            "check_name": "Clickjacking", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_host_header_injection(url, session):
    try:
        test_host = "evil.com"  # This stays INSIDE the function
        parsed = urlparse(url)
        headers = {'Host': test_host}
        
        response = session.get(
            f"{parsed.scheme}://{parsed.netloc}",
            headers=headers,
            timeout=10,
            allow_redirects=False
        )
        
        if test_host in response.text:
            return {"check_name": "Host Header Injection", "result": "Vulnerable", "details": "Host header reflected in response"}
        return {"check_name": "Host Header Injection", "result": "Safe", "details": "No host header injection detected"}
        
    except Exception as e:
        return {"check_name": "Host Header Injection", "result": "Error", "details": f"Test failed: {str(e)}"}

def check_server_side_template_injection(url, session):
    logger.info(f"\n{Fore.BLUE}[SSTI Check] Testing {url} for Server-Side Template Injection...{Style.RESET_ALL}")
    try:
        # Test for common template engines
        test_payloads = {
            'Twig': '{{7*7}}',
            'Jinja2': '{{7*7}}',
            'Django': '{%%20debug%20%}',
            'ERB': '<%=7*7%>',
            'Freemarker': '${7*7}',
            'Velocity': '#set($x=7*7)${x}'
        }
        
        vulnerabilities = []
        
        # Check URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    param_name = param.split('=')[0]
                    for engine, payload in test_payloads.items():
                        test_url = url.replace(param, f"{param_name}={payload}")
                        try:
                            response = session.get(test_url, timeout=10)
                            if '49' in response.text or 'debug' in response.text.lower():
                                vulnerabilities.append(f"Potential {engine} SSTI in parameter {param_name}")
                        except:
                            pass
        
        # Check forms
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for engine, payload in test_payloads.items():
                form_data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name and input_tag.get('type') in ('text', None):
                        form_data[name] = payload
                
                if form_data:
                    full_url = urljoin(url, action) if action else url
                    
                    try:
                        if method == 'get':
                            response = session.get(full_url, params=form_data, timeout=10)
                        else:
                            response = session.post(full_url, data=form_data, timeout=10)
                        
                        if '49' in response.text or 'debug' in response.text.lower():
                            vulnerabilities.append(f"Potential {engine} SSTI in form at {full_url}")
                    except:
                        pass
        
        if vulnerabilities:
            return {
                "check_name": "Server-Side Template Injection (SSTI)", 
                "result": "Vulnerable", 
                "details": "\n".join(vulnerabilities)
            }
        else:
            return {
                "check_name": "Server-Side Template Injection (SSTI)", 
                "result": "Safe", 
                "details": "No SSTI vulnerabilities detected."
            }
    except Exception as e:
        logger.error(f"[SSTI Check] Error: {e}")
        return {
            "check_name": "Server-Side Template Injection (SSTI)", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_http_request_smuggling(url, session):
    logger.info(f"\n{Fore.BLUE}[HTTP Request Smuggling Check] Testing {url} for HTTP request smuggling...{Style.RESET_ALL}")
    try:
        # This is a complex vulnerability to test for automatically
        # We'll just check for some basic indicators
        
        # Check if server supports HTTP/1.1
        try:
            response = session.get(url, timeout=10)
            if response.raw.version == 11:
                return {
                    "check_name": "HTTP Request Smuggling", 
                    "result": "Info", 
                    "details": "Server supports HTTP/1.1 - manual testing recommended for request smuggling vulnerabilities."
                }
            else:
                return {
                    "check_name": "HTTP Request Smuggling", 
                    "result": "Safe", 
                    "details": "Server does not use HTTP/1.1 - lower risk of request smuggling."
                }
        except:
            return {
                "check_name": "HTTP Request Smuggling", 
                "result": "Error", 
                "details": "Could not determine HTTP version."
            }
    except Exception as e:
        logger.error(f"[HTTP Request Smuggling Check] Error: {e}")
        return {
            "check_name": "HTTP Request Smuggling", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_web_cache_deception(url, session):
    logger.info(f"\n{Fore.BLUE}[Web Cache Deception Check] Testing {url} for web cache deception...{Style.RESET_ALL}")
    try:
        # Test by adding .css to a sensitive URL
        test_url = urljoin(url, "/account/profile.css")
        try:
            response = session.get(test_url, timeout=10)
            
            if response.status_code == 200:
                # Check if this is actually CSS content
                if 'text/css' not in response.headers.get('Content-Type', ''):
                    return {
                        "check_name": "Web Cache Deception", 
                        "result": "Vulnerable", 
                        "details": f"Server returned non-CSS content for {test_url} - potential cache deception vulnerability."
                    }
            
            return {
                "check_name": "Web Cache Deception", 
                "result": "Safe", 
                "details": "No web cache deception vulnerabilities detected."
            }
        except requests.exceptions.RequestException as e:
            return {
                "check_name": "Web Cache Deception", 
                "result": "Error", 
                "details": f"Test request failed: {e}"
            }
    except Exception as e:
        logger.error(f"[Web Cache Deception Check] Error: {e}")
        return {
            "check_name": "Web Cache Deception", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_subdomain_takeover(url, session):
    logger.info(f"\n{Fore.BLUE}[Subdomain Takeover Check] Testing {url} for subdomain takeover vulnerabilities...{Style.RESET_ALL}")
    try:
        domain = urlparse(url).netloc
        
        # This would normally require a list of common subdomains to check
        # For this example, we'll just check a few common ones
        common_subdomains = [
            "www", "mail", "webmail", "blog", "dev", "test",
            "staging", "api", "m", "mobile", "admin"
        ]
        
        issues = []
        
        for sub in common_subdomains:
            test_domain = f"{sub}.{domain}"
            try:
                # First check DNS
                try:
                    dns.resolver.resolve(test_domain, 'A')
                except dns.resolver.NXDOMAIN:
                    continue  # Subdomain doesn't exist
                except:
                    pass  # Other DNS error
                
                # Now check HTTP
                test_url = f"http://{test_domain}"
                try:
                    response = session.get(test_url, timeout=5, allow_redirects=False)
                    
                    # Check for common takeover indicators
                    if response.status_code in [404, 502, 503]:
                        # Check for services that might have this issue
                        if "NoSuchBucket" in response.text or "The specified bucket does not exist" in response.text:
                            issues.append(f"Potential AWS S3 subdomain takeover at {test_domain}")
                        elif "There isn't a GitHub Pages site here" in response.text:
                            issues.append(f"Potential GitHub Pages subdomain takeover at {test_domain}")
                        elif "herokucdn.com" in response.text and "No such app" in response.text:
                            issues.append(f"Potential Heroku subdomain takeover at {test_domain}")
                        elif "The requested URL was not found on this server" in response.text:
                            issues.append(f"Potential generic subdomain takeover at {test_domain}")
                except:
                    pass
            except:
                pass
        
        if issues:
            return {
                "check_name": "Subdomain Takeover", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "Subdomain Takeover", 
                "result": "Safe", 
                "details": "No obvious subdomain takeover vulnerabilities detected (limited automated checks performed)."
            }
    except Exception as e:
        logger.error(f"[Subdomain Takeover Check] Error: {e}")
        return {
            "check_name": "Subdomain Takeover", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_open_redirect(url, session):
    logger.info(f"\n{Fore.BLUE}[Open Redirect Check] Testing {url} for open redirect vulnerabilities...{Style.RESET_ALL}")
    try:
        test_urls = [
            "https://evil.com",
            "http://evil.com",
            "//evil.com",
            "/\\evil.com"
        ]
        
        vulnerabilities = []
        
        # Check URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    param_name = param.split('=')[0]
                    if any(kw in param_name.lower() for kw in ['url', 'redirect', 'next', 'return']):
                        for test_redirect in test_urls:
                            test_url = url.replace(param, f"{param_name}={test_redirect}")
                            try:
                                response = session.get(test_url, timeout=10, allow_redirects=False)
                                if 300 <= response.status_code < 400:
                                    location = response.headers.get('Location', '')
                                    if 'evil.com' in location:
                                        vulnerabilities.append(f"Open redirect in parameter {param_name} to {location}")
                            except:
                                pass
        
        if vulnerabilities:
            return {
                "check_name": "Open Redirect", 
                "result": "Vulnerable", 
                "details": "\n".join(vulnerabilities)
            }
        else:
            return {
                "check_name": "Open Redirect", 
                "result": "Safe", 
                "details": "No open redirect vulnerabilities detected."
            }
    except Exception as e:
        logger.error(f"[Open Redirect Check] Error: {e}")
        return {
            "check_name": "Open Redirect", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_domain_security(url, session):
    logger.info(f"\n{Fore.BLUE}[Domain Security Check] Testing domain security for {url}...{Style.RESET_ALL}")
    try:
        domain = urlparse(url).netloc
        issues = []
        
        # Get WHOIS information
        try:
            domain_info = whois.whois(domain)
            
            # Check domain expiration
            if domain_info.expiration_date:
                if isinstance(domain_info.expiration_date, list):
                    expiry_date = domain_info.expiration_date[0]
                else:
                    expiry_date = domain_info.expiration_date
                
                if expiry_date < datetime.now():
                    issues.append(f"Domain has expired! Expiry date: {expiry_date}")
                elif (expiry_date - datetime.now()).days < 30:
                    issues.append(f"Domain expires soon ({expiry_date.strftime('%Y-%m-%d')}) - renew now!")
            
            # Check domain age
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                domain_age = (datetime.now() - creation_date).days
                if domain_age < 30:
                    issues.append(f"Domain is very new ({domain_age} days old) - may be suspicious.")
            
            # Check registrar
            if domain_info.registrar:
                if "GoDaddy" in domain_info.registrar or "Namecheap" in domain_info.registrar:
                    pass  # Common registrars
                else:
                    issues.append(f"Domain registered with {domain_info.registrar} - verify this is expected.")
        
        except Exception as e:
            issues.append(f"Could not retrieve WHOIS information: {str(e)}")
        
        if issues:
            return {
                "check_name": "Domain Security", 
                "result": "Warning", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "Domain Security", 
                "result": "Safe", 
                "details": "No obvious domain security issues detected."
            }
    except Exception as e:
        logger.error(f"[Domain Security Check] Error: {e}")
        return {
            "check_name": "Domain Security", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_web_sockets(url, session):
    logger.info(f"\n{Fore.BLUE}[WebSockets Check] Testing {url} for WebSocket security issues...{Style.RESET_ALL}")
    try:
        # This is difficult to test automatically without a proper WebSocket client
        # We'll just check if the site uses WebSockets at all
        response = session.get(url, timeout=10)
        
        if "ws://" in response.text or "wss://" in response.text or "WebSocket" in response.text:
            return {
                "check_name": "WebSocket Security", 
                "result": "Info", 
                "details": "WebSockets detected - manual testing recommended for security issues."
            }
        else:
            return {
                "check_name": "WebSocket Security", 
                "result": "Safe", 
                "details": "No WebSocket usage detected."
            }
    except Exception as e:
        logger.error(f"[WebSockets Check] Error: {e}")
        return {
            "check_name": "WebSocket Security", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_webdav(url, session):
    logger.info(f"\n{Fore.BLUE}[WebDAV Check] Testing {url} for WebDAV misconfigurations...{Style.RESET_ALL}")
    try:
        # Check for OPTIONS method
        try:
            response = session.options(url, timeout=10)
            if 'dav' in response.headers.get('allow', '').lower() or 'dav' in response.headers.get('server', '').lower():
                return {
                    "check_name": "WebDAV", 
                    "result": "Warning", 
                    "details": "WebDAV enabled - ensure proper authentication and authorization is configured."
                }
        except:
            pass
        
        # Check for common WebDAV paths
        test_paths = [
            "/webdav", "/dav", "/share", "/remote.php/webdav"
        ]
        
        for path in test_paths:
            test_url = urljoin(url, path)
            try:
                response = session.get(test_url, timeout=5)
                if 'dav' in response.headers.get('server', '').lower() or 'webdav' in response.text.lower():
                    return {
                        "check_name": "WebDAV", 
                        "result": "Warning", 
                        "details": f"WebDAV detected at {test_url} - ensure proper authentication and authorization is configured."
                    }
            except:
                pass
        
        return {
            "check_name": "WebDAV", 
            "result": "Safe", 
            "details": "No WebDAV detected or WebDAV properly secured."
        }
    except Exception as e:
        logger.error(f"[WebDAV Check] Error: {e}")
        return {
            "check_name": "WebDAV", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_http_methods(url, session):
    logger.info(f"\n{Fore.BLUE}[HTTP Methods Check] Testing {url} for risky HTTP methods...{Style.RESET_ALL}")
    try:
        # Check supported methods
        try:
            response = session.options(url, timeout=10)
            allowed_methods = response.headers.get('allow', '').split(',')
            allowed_methods = [m.strip().upper() for m in allowed_methods]
            
            risky_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
            found_risky = [m for m in risky_methods if m in allowed_methods]
            
            if found_risky:
                return {
                    "check_name": "HTTP Methods", 
                    "result": "Warning", 
                    "details": f"Potentially risky HTTP methods enabled: {', '.join(found_risky)}"
                }
            else:
                return {
                    "check_name": "HTTP Methods", 
                    "result": "Safe", 
                    "details": f"Only standard HTTP methods enabled: {', '.join(allowed_methods)}"
                }
        except requests.exceptions.RequestException as e:
            return {
                "check_name": "HTTP Methods", 
                "result": "Error", 
                "details": f"Could not determine allowed HTTP methods: {e}"
            }
    except Exception as e:
        logger.error(f"[HTTP Methods Check] Error: {e}")
        return {
            "check_name": "HTTP Methods", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_port_scan(url, session):
    logger.info(f"\n{Fore.BLUE}[Port Scan] Scanning common ports for {url}...{Style.RESET_ALL}")
    try:
        domain = urlparse(url).netloc
        open_ports = []
        
        # Common web ports to check
        ports_to_scan = [80, 443, 8080, 8443, 8000, 8888, 8008]
        
        nm = nmap.PortScanner()
        for port in ports_to_scan:
            try:
                nm.scan(hosts=domain, ports=str(port), arguments='-T4')
                if domain in nm.all_hosts():
                    if nm[domain]['tcp'][port]['state'] == 'open':
                        service = nm[domain]['tcp'][port]['name']
                        open_ports.append(f"Port {port} ({service}) is open")
            except:
                pass
        
        if open_ports:
            return {
                "check_name": "Port Scan", 
                "result": "Info", 
                "details": "\n".join(open_ports)
            }
        else:
            return {
                "check_name": "Port Scan", 
                "result": "Safe", 
                "details": "No unexpected open ports detected."
            }
    except Exception as e:
        logger.error(f"[Port Scan] Error: {e}")
        return {
            "check_name": "Port Scan", 
            "result": "Error", 
            "details": f"Error during scan: {e}"
        }

def check_directory_traversal(url, session):
    logger.info(f"\n{Fore.BLUE}[Directory Traversal Check] Testing {url} for directory traversal vulnerabilities...{Style.RESET_ALL}")
    try:
        test_payloads = [
            "../../../../etc/passwd",
            "../../../../etc/hosts",
            "../../../../Windows/System32/drivers/etc/hosts",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts"
        ]
        
        vulnerabilities = []
        
        # Check URL parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            for param in parsed_url.query.split('&'):
                if '=' in param:
                    param_name = param.split('=')[0]
                    for payload in test_payloads:
                        test_url = url.replace(param, f"{param_name}={payload}")
                        try:
                            response = session.get(test_url, timeout=10)
                            if "root:" in response.text or "[boot loader]" in response.text:
                                vulnerabilities.append(f"Potential directory traversal in parameter {param_name} with payload: {payload}")
                        except:
                            pass
        
        # Check forms
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        for form in forms:
            action = form.get('action')
            method = form.get('method', 'get').lower()
            inputs = form.find_all('input')
            
            for payload in test_payloads:
                form_data = {}
                for input_tag in inputs:
                    name = input_tag.get('name')
                    if name and input_tag.get('type') in ('text', 'file', None):
                        form_data[name] = payload
                
                if form_data:
                    full_url = urljoin(url, action) if action else url
                    
                    try:
                        if method == 'get':
                            response = session.get(full_url, params=form_data, timeout=10)
                        else:
                            response = session.post(full_url, data=form_data, timeout=10)
                        
                        if "root:" in response.text or "[boot loader]" in response.text:
                            vulnerabilities.append(f"Potential directory traversal in form at {full_url} with payload: {payload}")
                    except:
                        pass
        
        if vulnerabilities:
            return {
                "check_name": "Directory Traversal", 
                "result": "Vulnerable", 
                "details": "\n".join(vulnerabilities)
            }
        else:
            return {
                "check_name": "Directory Traversal", 
                "result": "Safe", 
                "details": "No directory traversal vulnerabilities detected."
            }
    except Exception as e:
        logger.error(f"[Directory Traversal Check] Error: {e}")
        return {
            "check_name": "Directory Traversal", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_csrf(url, session):
    logger.info(f"\n{Fore.BLUE}[CSRF Check] Testing {url} for CSRF vulnerabilities...{Style.RESET_ALL}")
    try:
        response = session.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        vulnerabilities = []
        
        for form in forms:
            # Check for CSRF token
            csrf_token = form.find('input', {'name': 'csrf_token'}) or \
                         form.find('input', {'name': '_token'}) or \
                         form.find('input', {'name': 'csrf'})
            
            if not csrf_token:
                action = form.get('action', '')
                method = form.get('method', 'get').lower()
                if method == 'post':
                    vulnerabilities.append(f"Potential CSRF vulnerability in form with action: {action} (no CSRF token found)")
        
        if vulnerabilities:
            return {
                "check_name": "Cross-Site Request Forgery (CSRF)", 
                "result": "Vulnerable", 
                "details": "\n".join(vulnerabilities)
            }
        else:
            return {
                "check_name": "Cross-Site Request Forgery (CSRF)", 
                "result": "Safe", 
                "details": "All forms appear to have CSRF protections."
            }
    except Exception as e:
        logger.error(f"[CSRF Check] Error: {e}")
        return {
            "check_name": "Cross-Site Request Forgery (CSRF)", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_security_txt(url, session):
    logger.info(f"\n{Fore.BLUE}[security.txt Check] Testing {url} for security.txt file...{Style.RESET_ALL}")
    try:
        test_paths = [
            "/.well-known/security.txt",
            "/security.txt"
        ]
        
        for path in test_paths:
            test_url = urljoin(url, path)
            try:
                response = session.get(test_url, timeout=5)
                if response.status_code == 200 and "contact" in response.text.lower():
                    return {
                        "check_name": "security.txt", 
                        "result": "Safe", 
                        "details": f"security.txt file found at {test_url}"
                    }
            except:
                pass
        
        return {
            "check_name": "security.txt", 
            "result": "Warning", 
            "details": "No security.txt file found - consider adding one to /.well-known/security.txt"
        }
    except Exception as e:
        logger.error(f"[security.txt Check] Error: {e}")
        return {
            "check_name": "security.txt", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_robots_txt(url, session):
    logger.info(f"\n{Fore.BLUE}[robots.txt Check] Testing {url} for robots.txt file...{Style.RESET_ALL}")
    try:
        test_url = urljoin(url, "/robots.txt")
        try:
            response = session.get(test_url, timeout=5)
            if response.status_code == 200:
                # Check for sensitive paths in robots.txt
                sensitive_keywords = ['admin', 'login', 'config', 'backup', 'sql', 'db']
                sensitive_paths = []
                
                for line in response.text.split('\n'):
                    if line.lower().startswith('disallow:'):
                        path = line[len('disallow:'):].strip()
                        if any(kw in path.lower() for kw in sensitive_keywords):
                            sensitive_paths.append(path)
                
                if sensitive_paths:
                    return {
                        "check_name": "robots.txt", 
                        "result": "Warning", 
                        "details": f"robots.txt found at {test_url} and contains sensitive paths:\n" + "\n".join(sensitive_paths)
                    }
                else:
                    return {
                        "check_name": "robots.txt", 
                        "result": "Safe", 
                        "details": f"robots.txt found at {test_url} with no obviously sensitive paths"
                    }
        except:
            pass
        
        return {
            "check_name": "robots.txt", 
            "result": "Info", 
            "details": "No robots.txt file found"
        }
    except Exception as e:
        logger.error(f"[robots.txt Check] Error: {e}")
        return {
            "check_name": "robots.txt", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_sensitive_data_exposure(url, session):
    logger.info(f"\n{Fore.BLUE}[Sensitive Data Exposure Check] Testing {url} for sensitive data exposure...{Style.RESET_ALL}")
    try:
        issues = []
        
        # Check for common sensitive files
        sensitive_files = [
            "/.env", "/config.php", "/database.yml", "/.git/config",
            "/.htpasswd", "/web.config", "/phpinfo.php", "/.DS_Store"
        ]
        
        for file in sensitive_files:
            test_url = urljoin(url, file)
            try:
                response = session.get(test_url, timeout=5)
                if response.status_code == 200:
                    # Check for common patterns in sensitive files
                    if file == "/.env" and ("DB_" in response.text or "PASSWORD" in response.text):
                        issues.append(f"Sensitive environment file exposed at {test_url}")
                    elif file == "/config.php" and ("password" in response.text.lower() or "secret" in response.text.lower()):
                        issues.append(f"Sensitive config file exposed at {test_url}")
                    elif file == "/.git/config" and "[core]" in response.text:
                        issues.append(f"Git config file exposed at {test_url}")
                    else:
                        issues.append(f"File exposed at {test_url} - verify if sensitive")
            except:
                pass
        
        # Check for API keys in source code
        response = session.get(url, timeout=10)
        api_key_patterns = [
            r'[A-Za-z0-9]{32}',  # Generic 32-char key
            r'sk_live_[A-Za-z0-9]{32}',  # Stripe
            r'AKIA[A-Z0-9]{16}',  # AWS
            r'ghp_[A-Za-z0-9]{36}',  # GitHub
            r'AIza[A-Za-z0-9_\-]{35}'  # Google API
        ]
        
        for pattern in api_key_patterns:
            if re.search(pattern, response.text):
                issues.append(f"Potential API key found in page source (pattern: {pattern})")
        
        if issues:
            return {
                "check_name": "Sensitive Data Exposure", 
                "result": "Vulnerable", 
                "details": "\n".join(issues)
            }
        else:
            return {
                "check_name": "Sensitive Data Exposure", 
                "result": "Safe", 
                "details": "No obvious sensitive data exposure detected."
            }
    except Exception as e:
        logger.error(f"[Sensitive Data Exposure Check] Error: {e}")
        return {
            "check_name": "Sensitive Data Exposure", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_http_parameter_pollution(url, session):
    logger.info(f"\n{Fore.BLUE}[HTTP Parameter Pollution Check] Testing {url} for HPP vulnerabilities...{Style.RESET_ALL}")
    try:
        # This is difficult to test automatically, so we'll just check for duplicate parameters
        parsed_url = urlparse(url)
        if parsed_url.query:
            params = parsed_url.query.split('&')
            param_names = [p.split('=')[0] for p in params]
            
            # Check for duplicate parameters
            if len(param_names) != len(set(param_names)):
                return {
                    "check_name": "HTTP Parameter Pollution", 
                    "result": "Warning", 
                    "details": "Duplicate parameters found in URL - potential for HPP vulnerabilities."
                }
        
        return {
            "check_name": "HTTP Parameter Pollution", 
            "result": "Safe", 
            "details": "No obvious HTTP Parameter Pollution vulnerabilities detected."
        }
    except Exception as e:
        logger.error(f"[HTTP Parameter Pollution Check] Error: {e}")
        return {
            "check_name": "HTTP Parameter Pollution", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_web_fingerprinting(url, session):
    logger.info(f"\n{Fore.BLUE}[Web Fingerprinting] Identifying technologies used by {url}...{Style.RESET_ALL}")
    try:
        response = session.get(url, timeout=10)
        technologies = []
        
        # Check server header
        server = response.headers.get('Server', '')
        if server:
            technologies.append(f"Server: {server}")
        
        # Check X-Powered-By header
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            technologies.append(f"Powered by: {powered_by}")
        
        # Check common framework indicators
        if 'X-Drupal-Cache' in response.headers:
            technologies.append("Drupal CMS detected")
        if 'X-Generator' in response.headers and 'Drupal' in response.headers['X-Generator']:
            technologies.append("Drupal CMS confirmed")
        if 'wp-content' in response.text:
            technologies.append("WordPress detected")
        if '/_next/' in response.text:
            technologies.append("Next.js detected")
        if 'React' in response.text or 'react-dom' in response.text:
            technologies.append("React detected")
        if 'Vue' in response.text or 'vue.js' in response.text:
            technologies.append("Vue.js detected")
        if 'Angular' in response.text or 'ng-app' in response.text:
            technologies.append("Angular detected")
        if 'jQuery' in response.text:
            technologies.append("jQuery detected")
        if 'laravel' in response.text.lower():
            technologies.append("Laravel detected")
        if 'django' in response.text.lower():
            technologies.append("Django detected")
        if 'flask' in response.text.lower():
            technologies.append("Flask detected")
        if 'express' in response.text.lower():
            technologies.append("Express.js detected")
        
        # Check cookies for framework indicators
        cookies = response.headers.get('Set-Cookie', '')
        if 'laravel_session' in cookies:
            technologies.append("Laravel confirmed (session cookie)")
        if 'wordpress_' in cookies:
            technologies.append("WordPress confirmed (cookie)")
        if 'django' in cookies.lower():
            technologies.append("Django confirmed (cookie)")
        
        if technologies:
            return {
                "check_name": "Web Fingerprinting", 
                "result": "Info", 
                "details": "Technologies detected:\n" + "\n".join(technologies)
            }
        else:
            return {
                "check_name": "Web Fingerprinting", 
                "result": "Info", 
                "details": "No obvious technologies identified."
            }
    except Exception as e:
        logger.error(f"[Web Fingerprinting] Error: {e}")
        return {
            "check_name": "Web Fingerprinting", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

def check_known_vulnerabilities(url, session):
    logger.info(f"\n{Fore.BLUE}[Known Vulnerabilities Check] Checking {url} for known vulnerabilities...{Style.RESET_ALL}")
    try:
        # First identify technologies
        fingerprint = check_web_fingerprinting(url, session)
        if fingerprint["result"] == "Error":
            return fingerprint
        
        technologies = fingerprint["details"].split('\n')
        
        # This would normally involve querying a vulnerability database
        # For this example, we'll just check for some common vulnerable versions
        
        issues = []
        
        for tech in technologies:
            if 'WordPress' in tech:
                issues.append("WordPress detected - check for outdated plugins/themes/core")
            if 'Drupal' in tech and '7.' in tech:
                issues.append("Drupal 7 detected - consider upgrading to Drupal 9/10")
            if 'Apache' in tech and '2.2.' in tech:
                issues.append("Apache 2.2 detected - consider upgrading to 2.4")
            if 'nginx' in tech.lower() and '1.18.' in tech.lower():
                issues.append("nginx 1.18 detected - consider upgrading to latest stable")
            if 'PHP' in tech and ('5.6' in tech or '7.0' in tech or '7.1' in tech):
                issues.append(f"Outdated PHP version detected ({tech}) - consider upgrading")
        
        if issues:
            return {
                "check_name": "Known Vulnerabilities", 
                "result": "Warning", 
                "details": "\n".join(issues) + "\nNote: For comprehensive vulnerability checking, use a dedicated vulnerability scanner."
            }
        else:
            return {
                "check_name": "Known Vulnerabilities", 
                "result": "Safe", 
                "details": "No obvious known vulnerabilities detected (limited automated checks performed)."
            }
    except Exception as e:
        logger.error(f"[Known Vulnerabilities Check] Error: {e}")
        return {
            "check_name": "Known Vulnerabilities", 
            "result": "Error", 
            "details": f"Error during check: {e}"
        }

# Function to run all vulnerability checks
def vulnerability_scan(url, verbose, advanced):
    configure_logging(verbose)
    logger.info(f"\n{Fore.YELLOW}{'='*50}")
    logger.info(f"{Fore.YELLOW}[+] Starting vulnerability scan on: {url}")
    logger.info(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
    
    # Validate and potentially fix URL
    is_valid, fixed_url = validate_url(url)
    if not is_valid:
        logger.error(f"{Fore.RED}Error: Invalid URL format - {url}{Style.RESET_ALL}")
        return []
    
    url = fixed_url
    
    # Check if URL is alive
    session = get_session_with_retries()
    if not check_url_availability(url, session):
        logger.error(f"{Fore.RED}Error: Target URL is not responding - {url}{Style.RESET_ALL}")
        return []
    
    vulnerabilities = []
    
    # List of all vulnerability checks
    basic_checks = [
        check_broken_access_control,
        check_cryptographic_failures,
        check_sql_injection,
        check_xss,
        check_command_injection,
        check_insecure_design,
        check_security_misconfiguration,
        check_outdated_components,
        check_authentication_failures,
        check_data_integrity,
        check_logging,
        check_ssrf,
        check_http_headers,
        check_idor,
        check_file_inclusion,
        check_cors,
        check_csrf,
        check_security_txt,
        check_robots_txt,
        check_sensitive_data_exposure
    ]
    
    advanced_checks = [
        check_xml_external_entities,
        check_dom_based_xss,
        check_insecure_deserialization,
        check_server_side_request_forgery,
        check_api_security,
        check_rate_limiting,
        check_dns_security,
        check_email_security,
        check_clickjacking,
        check_host_header_injection,
        check_server_side_template_injection,
        check_http_request_smuggling,
        check_web_cache_deception,
        check_subdomain_takeover,
        check_open_redirect,
        check_domain_security,
        check_web_sockets,
        check_webdav,
        check_http_methods,
        check_port_scan,
        check_directory_traversal,
        check_http_parameter_pollution,
        check_web_fingerprinting,
        check_known_vulnerabilities
    ]
    
    # Select checks based on mode
    checks_to_run = basic_checks
    if advanced.get('advanced', False):
        checks_to_run += advanced_checks
    
    # Run checks with progress bar
    with tqdm(total=len(checks_to_run), desc=f"{Fore.BLUE}Scanning{Style.RESET_ALL}", unit="check") as pbar:
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_func, url, session): check_func for check_func in checks_to_run}
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        vulnerabilities.append(result)
                        
                        # Print result immediately
                        status_color = Fore.RED if result["result"] == "Vulnerable" else Fore.YELLOW if result["result"] == "Warning" else Fore.GREEN if result["result"] == "Safe" else Fore.BLUE
                        logger.info(f"\n{status_color}[{result['check_name']}] Result: {result['result']}{Style.RESET_ALL}")
                        logger.info(f"{result['details']}")
                except Exception as e:
                    logger.error(f"{Fore.RED}Error in vulnerability check: {e}{Style.RESET_ALL}")
                finally:
                    pbar.update(1)
    
    # Generate report if requested
    if advanced.get('report', False):
        report_format = advanced.get('format', 'pdf')
        report_path = generate_report(vulnerabilities, url, report_format)
        
        if report_path and advanced.get('open', False):
            try:
                webbrowser.open(report_path)
            except:
                logger.error(f"{Fore.RED}Could not automatically open report{Style.RESET_ALL}")
    
    return vulnerabilities

def display_results(vulnerabilities):
    if not vulnerabilities:
        logger.info(f"{Fore.GREEN}No vulnerabilities found!{Style.RESET_ALL}")
        return
    
    # Count vulnerabilities by severity
    vuln_count = len([v for v in vulnerabilities if v["result"] == "Vulnerable"])
    warning_count = len([v for v in vulnerabilities if v["result"] == "Warning"])
    safe_count = len([v for v in vulnerabilities if v["result"] == "Safe"])
    info_count = len([v for v in vulnerabilities if v["result"] not in ["Vulnerable", "Warning", "Safe"]])
    
    logger.info(f"\n{Fore.YELLOW}{'='*50}")
    logger.info(f"{Fore.YELLOW} Scan Summary ")
    logger.info(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
    logger.info(f"{Fore.RED}Critical Vulnerabilities: {vuln_count}{Style.RESET_ALL}")
    logger.info(f"{Fore.YELLOW}Warnings: {warning_count}{Style.RESET_ALL}")
    logger.info(f"{Fore.GREEN}Secure Findings: {safe_count}{Style.RESET_ALL}")
    logger.info(f"{Fore.BLUE}Informational: {info_count}{Style.RESET_ALL}")
    
    # Display vulnerabilities by severity
    if vuln_count > 0:
        logger.info(f"\n{Fore.RED}{'='*50}")
        logger.info(f"{Fore.RED} Critical Vulnerabilities ")
        logger.info(f"{Fore.RED}{'='*50}{Style.RESET_ALL}")
        for vuln in [v for v in vulnerabilities if v["result"] == "Vulnerable"]:
            logger.info(f"\n{Fore.RED}[!] {vuln['check_name']}{Style.RESET_ALL}")
            logger.info(f"{vuln['details']}")
    
    if warning_count > 0:
        logger.info(f"\n{Fore.YELLOW}{'='*50}")
        logger.info(f"{Fore.YELLOW} Warnings ")
        logger.info(f"{Fore.YELLOW}{'='*50}{Style.RESET_ALL}")
        for vuln in [v for v in vulnerabilities if v["result"] == "Warning"]:
            logger.info(f"\n{Fore.YELLOW}[*] {vuln['check_name']}{Style.RESET_ALL}")
            logger.info(f"{vuln['details']}")
    
    if info_count > 0:
        logger.info(f"\n{Fore.BLUE}{'='*50}")
        logger.info(f"{Fore.BLUE} Informational Findings ")
        logger.info(f"{Fore.BLUE}{'='*50}{Style.RESET_ALL}")
        for vuln in [v for v in vulnerabilities if v["result"] not in ["Vulnerable", "Warning", "Safe"]]:
            logger.info(f"\n{Fore.BLUE}[i] {vuln['check_name']}{Style.RESET_ALL}")
            logger.info(f"{vuln['details']}")
    
    if safe_count > 0:
        logger.info(f"\n{Fore.GREEN}{'='*50}")
        logger.info(f"{Fore.GREEN} Secure Findings ")
        logger.info(f"{Fore.GREEN}{'='*50}{Style.RESET_ALL}")
        for vuln in [v for v in vulnerabilities if v["result"] == "Safe"]:
            logger.info(f"\n{Fore.GREEN}[✓] {vuln['check_name']}{Style.RESET_ALL}")
            logger.info(f"{vuln['details']}")

def welcome_screen():
    print(f"{Fore.GREEN}{BANNER}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}{DESCRIPTION}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Usage: python ksetrajnam.py <url> [options]{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Example: python ksetrajnam.py https://example.com -v -r pdf -a{Style.RESET_ALL}")

# Main script entry point
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose mode for detailed logs")
    parser.add_argument("-r", "--report", action="store_true", help="Generate a vulnerability report")
    parser.add_argument("-f", "--format", choices=["pdf", "html", "json", "csv"], default="pdf", help="Report format (default: pdf)")
    parser.add_argument("-a", "--advanced", action="store_true", help="Enable advanced vulnerability checks")
    parser.add_argument("-o", "--open", action="store_true", help="Open the report automatically after generation")
    
    args = parser.parse_args()
    
    welcome_screen()
    
    advanced_options = {
        'report': args.report,
        'format': args.format,
        'advanced': args.advanced,
        'open': args.open
    }
    
    vulnerabilities = vulnerability_scan(args.url, args.verbose, advanced_options)
    display_results(vulnerabilities)