import socket
import requests
import json
from datetime import datetime

# Define target (You can change this to a local IP or a test website like 'scanme.nmap.org')
TARGET_HOST = "localhost" 
TARGET_URL = "http://localhost"  # Used for HTTP header checks if applicable

# 1. Port Scanner Function
def scan_ports(host, ports_to_scan):
    print(f"[*] Starting port scan on host: {host}")
    open_ports = []
    
    for port in ports_to_scan:
        # Create a socket object
        # AF_INET = IPv4, SOCK_STREAM = TCP
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0) # Stop waiting after 1 second
        
        # Try to connect to the port
        result = s.connect_ex((host, port))
        if result == 0:
            print(f"[+] Port {port} is OPEN")
            open_ports.append(port)
        s.close()
        
    return open_ports

# 2. Software Version / Weak Configuration Checker
def check_http_headers(url):
    print(f"\n[*] Checking HTTP headers for software versions on: {url}")
    vulnerabilities = []
    
    try:
        response = requests.get(url, timeout=3)
        headers = response.headers
        
        # Check if Server header leaks software version
        server = headers.get("Server")
        if server:
            print(f"[!] Server Header found: {server}")
            vulnerabilities.append(f"Information Disclosure: 'Server' header leaks software details ({server}).")
            
            # Simulated outdated check for the sake of the mini-project
            if "Apache/2.4.41" in server or "nginx/1.14.0" in server:
                vulnerabilities.append(f"Potentially Outdated Software: {server} might be an older release.")
        else:
            print("[+] Server header is hidden (Good Configuration).")
            
        # Check for missing security headers (Weak Configuration)
        if "X-Frame-Options" not in headers:
            vulnerabilities.append("Weak Configuration: Missing 'X-Frame-Options' header (Vulnerable to Clickjacking).")
            
        if "X-Content-Type-Options" not in headers:
            vulnerabilities.append("Weak Configuration: Missing 'X-Content-Type-Options' header.")

    except requests.exceptions.RequestException as e:
        print(f"[-] Could not connect to web URL: {e}")
        vulnerabilities.append(f"Web scan skipped: Could not connect to {url}")
        
    return vulnerabilities

# 3. Report Generator Function
def generate_report(host, open_ports, issues):
    report_filename = "vulnerability_report.txt"
    
    with open(report_filename, "w") as report:
        report.write("="*50 + "\n")
        report.write("          VULNERABILITY SCANNER REPORT          \n")
        report.write("="*50 + "\n")
        report.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        report.write(f"Target Host: {host}\n")
        report.write("-"*50 + "\n\n")
        
        # Ports section
        report.write("1. NETWORK PORT RESULTS:\n")
        if open_ports:
            report.write(f"   [!] Open Ports Detected: {', '.join(map(str, open_ports))}\n")
        else:
            report.write("   [+] No critical open ports detected in the scanned range.\n")
        report.write("\n")
        
        # Vulnerabilities section
        report.write("2. CONFIGURATION & SOFTWARE ISSUES:\n")
        if issues:
            for issue in issues:
                report.write(f"   - {issue}\n")
        else:
            report.write("   [+] No software configuration issues detected.\n")
            
        report.write("\n" + "="*50 + "\n")
        report.write("Scan Complete. Secure your systems!\n")
        
    print(f"\n[+] Simple vulnerability report successfully generated: '{report_filename}'")


# Main Execution Block
if __name__ == "__main__":
    # Standard ports to check: 21 (FTP), 22 (SSH), 80 (HTTP), 443 (HTTPS)
    ports_list = [21, 22, 80, 443]
    
    # Run Scans
    detected_ports = scan_ports(TARGET_HOST, ports_list)
    detected_issues = check_http_headers(TARGET_URL)
    
    # Build Report
    generate_report(TARGET_HOST, detected_ports, detected_issues)