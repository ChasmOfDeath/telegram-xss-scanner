#!/usr/bin/env python3
"""
DOM-based XSS Vulnerability Scanner
Detects client-side XSS vulnerabilities in JavaScript code
"""
import re
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, parse_qs
import json
from datetime import datetime

class DOMXSSScanner:
    def __init__(self):
        self.sources = [
            'location.hash',
            'location.search',
            'location.href',
            'document.URL',
            'document.documentURI',
            'document.referrer',
            'window.name',
            'document.cookie',
            'localStorage',
            'sessionStorage',
        ]
        
        self.sinks = [
            'eval(',
            'setTimeout(',
            'setInterval(',
            'Function(',
            'innerHTML',
            'outerHTML',
            'document.write(',
            'document.writeln(',
            '.html(',
            'location.href',
            'location.assign(',
            'location.replace(',
            'script.src',
            'iframe.src',
        ]
        
        self.vulnerabilities = []
    
    def scan_url(self, url):
        """Scan a URL for DOM-based XSS"""
        print(f"\n[*] Scanning for DOM XSS: {url}")
        
        try:
            response = requests.get(url, timeout=10)
            html_content = response.text
            
            # Extract and analyze JavaScript
            js_code = self.extract_javascript(html_content)
            
            # Analyze inline scripts
            self.analyze_inline_scripts(html_content, url)
            
            # Analyze external scripts
            self.analyze_external_scripts(html_content, url)
            
            # Check for dangerous patterns
            self.check_dangerous_patterns(js_code, url)
            
        except Exception as e:
            print(f"[!] Error scanning {url}: {e}")
    
    def extract_javascript(self, html):
        """Extract JavaScript code from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script')
        
        js_code = []
        for script in scripts:
            if script.string:
                js_code.append(script.string)
        
        return '\n'.join(js_code)
    
    def analyze_inline_scripts(self, html, url):
        """Analyze inline JavaScript for DOM XSS"""
        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script')
        
        for idx, script in enumerate(scripts):
            if script.string:
                code = script.string
                
                # Check for source-to-sink flows
                for source in self.sources:
                    if source in code:
                        for sink in self.sinks:
                            if sink in code:
                                # Potential DOM XSS found
                                vuln = self.create_vulnerability(
                                    url=url,
                                    vuln_type='DOM XSS',
                                    source=source,
                                    sink=sink,
                                    code_snippet=code[:200],
                                    location=f'Inline script #{idx + 1}'
                                )
                                self.vulnerabilities.append(vuln)
                                print(f"[!] Potential DOM XSS: {source} → {sink}")
    
    def analyze_external_scripts(self, html, base_url):
        """Analyze external JavaScript files"""
        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script', src=True)
        
        for script in scripts:
            src = script.get('src')
            if src:
                # Handle relative URLs
                if not src.startswith('http'):
                    from urllib.parse import urljoin
                    src = urljoin(base_url, src)
                
                try:
                    print(f"[*] Analyzing external script: {src}")
                    response = requests.get(src, timeout=5)
                    js_code = response.text
                    
                    # Check for source-to-sink flows
                    for source in self.sources:
                        if source in js_code:
                            for sink in self.sinks:
                                if sink in js_code:
                                    vuln = self.create_vulnerability(
                                        url=base_url,
                                        vuln_type='DOM XSS (External)',
                                        source=source,
                                        sink=sink,
                                        code_snippet=self.extract_context(js_code, source, sink),
                                        location=src
                                    )
                                    self.vulnerabilities.append(vuln)
                                    print(f"[!] Potential DOM XSS in {src}: {source} → {sink}")
                
                except Exception as e:
                    print(f"[!] Error analyzing {src}: {e}")
    
    def check_dangerous_patterns(self, js_code, url):
        """Check for dangerous JavaScript patterns"""
        dangerous_patterns = [
            # Direct eval of user input
            (r'eval\s*\(\s*location\.', 'eval() with location object'),
            (r'eval\s*\(\s*document\.URL', 'eval() with document.URL'),
            
            # innerHTML with user input
            (r'innerHTML\s*=\s*location\.', 'innerHTML with location object'),
            (r'innerHTML\s*=\s*document\.URL', 'innerHTML with document.URL'),
            
            # document.write with user input
            (r'document\.write\s*\(\s*location\.', 'document.write() with location'),
            (r'document\.write\s*\(\s*window\.name', 'document.write() with window.name'),
            
            # setTimeout/setInterval with strings
            (r'setTimeout\s*\(\s*["\'].*location\.', 'setTimeout with location'),
            (r'setInterval\s*\(\s*["\'].*location\.', 'setInterval with location'),
            
            # jQuery HTML methods
            (r'\$\(.*\)\.html\s*\(\s*location\.', 'jQuery .html() with location'),
            (r'\$\(.*\)\.append\s*\(\s*location\.', 'jQuery .append() with location'),
        ]
        
        for pattern, description in dangerous_patterns:
            matches = re.finditer(pattern, js_code, re.IGNORECASE)
            for match in matches:
                vuln = self.create_vulnerability(
                    url=url,
                    vuln_type='Dangerous Pattern',
                    source='User Input',
                    sink=description,
                    code_snippet=match.group(0),
                    location='JavaScript code'
                )
                self.vulnerabilities.append(vuln)
                print(f"[!] Dangerous pattern found: {description}")
    
    def extract_context(self, code, source, sink, context_size=100):
        """Extract code context around source and sink"""
        source_pos = code.find(source)
        sink_pos = code.find(sink)
        
        if source_pos != -1 and sink_pos != -1:
            start = max(0, min(source_pos, sink_pos) - context_size)
            end = min(len(code), max(source_pos, sink_pos) + context_size)
            return code[start:end]
        
        return code[:200]
    
    def create_vulnerability(self, url, vuln_type, source, sink, code_snippet, location):
        """Create vulnerability record"""
        return {
            'url': url,
            'type': vuln_type,
            'source': source,
            'sink': sink,
            'code': code_snippet,
            'location': location,
            'severity': self.calculate_severity(sink),
            'timestamp': datetime.now().isoformat()
        }
    
    def calculate_severity(self, sink):
        """Calculate vulnerability severity"""
        high_risk_sinks = ['eval(', 'Function(', 'setTimeout(', 'setInterval(']
        medium_risk_sinks = ['innerHTML', 'outerHTML', 'document.write(']
        
        if any(s in sink for s in high_risk_sinks):
            return 'HIGH'
        elif any(s in sink for s in medium_risk_sinks):
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def test_dom_xss_payload(self, url):
        """Test URL with DOM XSS payloads"""
        payloads = [
            '#<img src=x onerror=alert(1)>',
            '#<script>alert(1)</script>',
            '?search=<img src=x onerror=alert(1)>',
            '#javascript:alert(1)',
        ]
        
        print(f"\n[*] Testing DOM XSS payloads on: {url}")
        
        for payload in payloads:
            test_url = url + payload
            print(f"[*] Testing: {test_url}")
            
            try:
                response = requests.get(test_url, timeout=5)
                
                # Check if payload is in JavaScript context
                if self.check_payload_execution(response.text, payload):
                    vuln = {
                        'url': url,
                        'type': 'Confirmed DOM XSS',
                        'payload': payload,
                        'test_url': test_url,
                        'severity': 'CRITICAL',
                        'timestamp': datetime.now().isoformat()
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"[!!!] CONFIRMED DOM XSS with payload: {payload}")
            
            except Exception as e:
                print(f"[!] Error testing payload: {e}")
    
    def check_payload_execution(self, html, payload):
        """Check if payload could execute in DOM"""
        # Look for payload in script context
        soup = BeautifulSoup(html, 'html.parser')
        scripts = soup.find_all('script')
        
        for script in scripts:
            if script.string and payload.strip('#?search=') in script.string:
                return True
        
        return False
    
    def generate_report(self, output_file='reports/dom_xss_report.json'):
        """Generate detailed DOM XSS report"""
        report = {
            'scan_date': datetime.now().isoformat(),
            'total_vulnerabilities': len(self.vulnerabilities),
            'severity_breakdown': self.get_severity_breakdown(),
            'vulnerabilities': self.vulnerabilities
        }
        
        # Save JSON report
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        # Generate text report
        text_file = output_file.replace('.json', '.txt')
        with open(text_file, 'w') as f:
            f.write("="*70 + "\n")
            f.write("DOM-BASED XSS VULNERABILITY SCAN REPORT\n")
            f.write("="*70 + "\n\n")
            f.write(f"Scan Date: {report['scan_date']}\n")
            f.write(f"Total Vulnerabilities: {report['total_vulnerabilities']}\n\n")
            
            f.write("Severity Breakdown:\n")
            for severity, count in report['severity_breakdown'].items():
                f.write(f"  {severity}: {count}\n")
            
            f.write("\n" + "="*70 + "\n")
            f.write("DETAILED FINDINGS\n")
            f.write("="*70 + "\n\n")
            
            for i, vuln in enumerate(self.vulnerabilities, 1):
                f.write(f"\n[{i}] {vuln['type']} - {vuln.get('severity', 'UNKNOWN')}\n")
                f.write(f"URL: {vuln['url']}\n")
                f.write(f"Source: {vuln.get('source', 'N/A')}\n")
                f.write(f"Sink: {vuln.get('sink', 'N/A')}\n")
                f.write(f"Location: {vuln.get('location', 'N/A')}\n")
                f.write(f"Code Snippet:\n{vuln.get('code', 'N/A')}\n")
                f.write("-"*70 + "\n")
        
        print(f"\n[+] Reports saved:")
        print(f"    JSON: {output_file}")
        print(f"    Text: {text_file}")
    
    def get_severity_breakdown(self):
        """Get count of vulnerabilities by severity"""
        breakdown = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for vuln in self.vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown

def main():
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║   DOM-based XSS Vulnerability Scanner            ║
    ║   Detects Client-Side XSS Vulnerabilities        ║
    ║   Educational & Authorized Use Only              ║
    ╚═══════════════════════════════════════════════════╝
    """)
    
    scanner = DOMXSSScanner()
    
    target = input("\n[?] Enter target URL: ").strip()
    
    if not target:
        print("[!] No URL provided")
        return
    
    # Scan for DOM XSS
    scanner.scan_url(target)
    
    # Test with payloads
    test_payloads = input("\n[?] Test with DOM XSS payloads? (y/n): ").strip().lower()
    if test_payloads == 'y':
        scanner.test_dom_xss_payload(target)
    
    # Generate report
    if scanner.vulnerabilities:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scanner.generate_report(f'reports/dom_xss_report_{timestamp}.json')
        print(f"\n[!] Found {len(scanner.vulnerabilities)} potential DOM XSS vulnerabilities")
    else:
        print("\n[+] No DOM XSS vulnerabilities detected")

if __name__ == "__main__":
    main()
