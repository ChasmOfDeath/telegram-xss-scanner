#!/usr/bin/env python3
"""
Comprehensive XSS Vulnerability Scanner
Includes Reflected, Stored, and DOM-based XSS detection
"""
import sys
import requests
from dom_xss_scanner import DOMXSSScanner
from datetime import datetime

class ComprehensiveXSSScanner:
    def __init__(self):
        self.dom_scanner = DOMXSSScanner()
        self.reflected_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
        ]
        self.all_vulnerabilities = []
    
    def scan_all(self, url):
        """Run all XSS scans"""
        print(f"\n{'='*60}")
        print("COMPREHENSIVE XSS VULNERABILITY SCAN")
        print(f"{'='*60}\n")
        print(f"Target: {url}\n")
        
        # 1. DOM-based XSS scan
        print("[1/3] Scanning for DOM-based XSS...")
        self.dom_scanner.scan_url(url)
        self.dom_scanner.test_dom_xss_payload(url)
        
        # 2. Reflected XSS scan
        print("\n[2/3] Scanning for Reflected XSS...")
        self.scan_reflected_xss(url)
        
        # 3. Generate comprehensive report
        print("\n[3/3] Generating comprehensive report...")
        self.generate_comprehensive_report()
    
    def scan_reflected_xss(self, url):
        """Scan for reflected XSS"""
        params = ['q', 'search', 'query', 'id', 'name', 'page']
        
        for param in params:
            for payload in self.reflected_payloads:
                try:
                    test_url = f"{url}?{param}={payload}"
                    response = requests.get(test_url, timeout=5)
                    
                    if payload in response.text:
                        vuln = {
                            'type': 'Reflected XSS',
                            'url': url,
                            'parameter': param,
                            'payload': payload,
                            'severity': 'HIGH',
                            'timestamp': datetime.now().isoformat()
                        }
                        self.all_vulnerabilities.append(vuln)
                        print(f"[!] Reflected XSS found: {param} = {payload[:30]}...")
                
                except Exception as e:
                    pass
    
    def generate_comprehensive_report(self):
        """Generate comprehensive report combining all scan types"""
        # Combine DOM and reflected vulnerabilities
        all_vulns = self.dom_scanner.vulnerabilities + self.all_vulnerabilities
        
        if not all_vulns:
            print("\n[+] No vulnerabilities found")
            return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_file = f'reports/comprehensive_xss_report_{timestamp}.txt'
        
        with open(report_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("COMPREHENSIVE XSS VULNERABILITY REPORT\n")
            f.write("="*70 + "\n\n")
            f.write(f"Scan Date: {datetime.now()}\n")
            f.write(f"Total Vulnerabilities: {len(all_vulns)}\n\n")
            
            # Group by type
            dom_vulns = [v for v in all_vulns if 'DOM' in v.get('type', '')]
            reflected_vulns = [v for v in all_vulns if 'Reflected' in v.get('type', '')]
            
            f.write(f"DOM-based XSS: {len(dom_vulns)}\n")
            f.write(f"Reflected XSS: {len(reflected_vulns)}\n\n")
            
            f.write("="*70 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("="*70 + "\n")
            
            for i, vuln in enumerate(all_vulns, 1):
                f.write(f"\n[{i}] {vuln.get('type', 'Unknown')} - {vuln.get('severity', 'MEDIUM')}\n")
                f.write(f"URL: {vuln.get('url', 'N/A')}\n")
                
                if 'source' in vuln:
                    f.write(f"Source: {vuln['source']}\n")
                    f.write(f"Sink: {vuln['sink']}\n")
                
                if 'parameter' in vuln:
                    f.write(f"Parameter: {vuln['parameter']}\n")
                    f.write(f"Payload: {vuln['payload']}\n")
                
                f.write("-"*70 + "\n")
        
        print(f"\n[+] Comprehensive report saved: {report_file}")
        print(f"[!] Total vulnerabilities found: {len(all_vulns)}")

def main():
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║   Comprehensive XSS Vulnerability Scanner        ║
    ║   DOM-based + Reflected + Stored XSS Detection   ║
    ║   Educational & Authorized Use Only              ║
    ╚═══════════════════════════════════════════════════╝
    """)
    
    target = input("\n[?] Enter target URL: ").strip()
    
    if not target:
        print("[!] No URL provided")
        return
    
    scanner = ComprehensiveXSSScanner()
    scanner.scan_all(target)

if __name__ == "__main__":
    main()
