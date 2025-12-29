#!/usr/bin/env python3
"""
Bug Bounty Automation
Auto-submit vulnerabilities to HackerOne, Bugcrowd, and Intigriti
"""
import json
import requests
from datetime import datetime

class BugBountyAutomation:
    def __init__(self):
        self.platforms = {
            'hackerone': self.submit_to_hackerone,
            'bugcrowd': self.submit_to_bugcrowd,
            'intigriti': self.submit_to_intigriti,
        }
        self.severity_mapping = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
    
    def submit_to_hackerone(self, vuln, api_key):
        """Submit vulnerability to HackerOne"""
        print("\n[*] Submitting to HackerOne...")
        
        # HackerOne API endpoint
        url = "https://api.hackerone.com/v1/reports"
        
        # Format vulnerability report
        report = {
            "data": {
                "type": "report",
                "attributes": {
                    "title": f"{vuln.get('type')} in {vuln.get('url')}",
                    "vulnerability_information": self.format_vulnerability(vuln),
                    "severity_rating": self.severity_mapping.get(vuln.get('severity', 'MEDIUM')),
                    "impact": self.generate_impact(vuln)
                }
            }
        }
        
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {api_key}'
        }
        
        try:
            # Dry run - don't actually submit without confirmation
            print(f"[*] Would submit to HackerOne:")
            print(json.dumps(report, indent=2))
            
            # Uncomment to actually submit:
            # response = requests.post(url, json=report, headers=headers)
            # if response.status_code == 201:
            #     print("[+] Successfully submitted to HackerOne!")
            #     return response.json()
            
            return {"status": "dry_run", "platform": "hackerone"}
        
        except Exception as e:
            print(f"[!] Error submitting to HackerOne: {e}")
            return None
    
    def submit_to_bugcrowd(self, vuln, api_key):
        """Submit vulnerability to Bugcrowd"""
        print("\n[*] Submitting to Bugcrowd...")
        
        url = "https://api.bugcrowd.com/submissions"
        
        report = {
            "title": f"{vuln.get('type')} Vulnerability",
            "description": self.format_vulnerability(vuln),
            "severity": self.severity_mapping.get(vuln.get('severity', 'MEDIUM')),
            "vulnerability_type": self.map_vuln_type(vuln.get('type')),
            "proof_of_concept": self.generate_poc(vuln)
        }
        
        headers = {
            'Authorization': f'Token {api_key}',
            'Content-Type': 'application/json'
        }
        
        print(f"[*] Would submit to Bugcrowd:")
        print(json.dumps(report, indent=2))
        
        return {"status": "dry_run", "platform": "bugcrowd"}
    
    def submit_to_intigriti(self, vuln, api_key):
        """Submit vulnerability to Intigriti"""
        print("\n[*] Submitting to Intigriti...")
        
        report = {
            "title": f"{vuln.get('type')} - {vuln.get('url')}",
            "description": self.format_vulnerability(vuln),
            "severity": vuln.get('severity', 'MEDIUM'),
            "type": vuln.get('type'),
            "endpoint": vuln.get('url')
        }
        
        print(f"[*] Would submit to Intigriti:")
        print(json.dumps(report, indent=2))
        
        return {"status": "dry_run", "platform": "intigriti"}
    
    def format_vulnerability(self, vuln):
        """Format vulnerability for submission"""
        report = f"""
# {vuln.get('type')} Vulnerability Report

## Summary
A {vuln.get('type')} vulnerability was discovered during automated security testing.

## Vulnerability Details
- **Type**: {vuln.get('type')}
- **Severity**: {vuln.get('severity', 'MEDIUM')}
- **URL**: {vuln.get('url', 'N/A')}
- **Discovery Date**: {datetime.now().strftime('%Y-%m-%d')}

## Technical Details
"""
        
        if 'parameter' in vuln:
            report += f"\n- **Vulnerable Parameter**: `{vuln['parameter']}`"
        
        if 'payload' in vuln:
            report += f"\n- **Payload**: `{vuln['payload']}`"
        
        if 'source' in vuln:
            report += f"\n- **Source**: `{vuln['source']}`"
        
        if 'sink' in vuln:
            report += f"\n- **Sink**: `{vuln['sink']}`"
        
        report += "\n\n## Proof of Concept\n"
        report += self.generate_poc(vuln)
        
        report += "\n\n## Impact\n"
        report += self.generate_impact(vuln)
        
        report += "\n\n## Remediation\n"
        report += self.generate_remediation(vuln)
        
        return report
    
    def generate_poc(self, vuln):
        """Generate proof of concept"""
        vuln_type = vuln.get('type', '').lower()
        
        if 'xss' in vuln_type:
            return f"""
1. Navigate to: {vuln.get('url')}
2. Enter payload in parameter '{vuln.get('parameter', 'N/A')}': `{vuln.get('payload', 'N/A')}`
3. Observe that the payload is reflected without sanitization
4. The JavaScript executes in the browser context

**Test URL**: {vuln.get('url')}?{vuln.get('parameter', 'q')}={vuln.get('payload', '')}
"""
        
        elif 'sql' in vuln_type:
            return f"""
1. Navigate to: {vuln.get('url')}
2. Inject SQL payload in parameter '{vuln.get('parameter', 'id')}'
3. Observe SQL error messages or unexpected behavior
4. Payload: `{vuln.get('payload', "' OR '1'='1")}`
"""
        
        else:
            return f"Detailed PoC available in attached exploit files."
    
    def generate_impact(self, vuln):
        """Generate impact statement"""
        vuln_type = vuln.get('type', '').lower()
        
        impacts = {
            'xss': """
- Account takeover via session hijacking
- Credential theft through phishing
- Malware distribution
- Defacement of web pages
- Theft of sensitive user data
""",
            'sql': """
- Unauthorized database access
- Data exfiltration
- Data manipulation or deletion
- Authentication bypass
- Potential remote code execution
""",
            'csrf': """
- Unauthorized actions on behalf of users
- Account modification
- Privilege escalation
- Data manipulation
""",
            'ssrf': """
- Internal network scanning
- Access to cloud metadata
- Bypass of access controls
- Information disclosure
"""
        }
        
        for key, impact in impacts.items():
            if key in vuln_type:
                return impact
        
        return "Security impact depends on the specific vulnerability context."
    
    def generate_remediation(self, vuln):
        """Generate remediation advice"""
        vuln_type = vuln.get('type', '').lower()
        
        remediations = {
            'xss': """
- Implement proper input validation and output encoding
- Use Content Security Policy (CSP) headers
- Sanitize user input using libraries like DOMPurify
- Use framework-provided XSS protection (e.g., React's JSX)
- Implement HTTPOnly and Secure flags on cookies
""",
            'sql': """
- Use parameterized queries (prepared statements)
- Implement proper input validation
- Apply principle of least privilege for database accounts
- Use ORM frameworks with built-in protection
- Implement web application firewall (WAF)
""",
            'csrf': """
- Implement anti-CSRF tokens
- Use SameSite cookie attribute
- Verify Origin and Referer headers
- Require re-authentication for sensitive actions
""",
            'ssrf': """
- Implement whitelist of allowed URLs/IPs
- Disable unnecessary URL schemas
- Use network segmentation
- Validate and sanitize all user-supplied URLs
"""
        }
        
        for key, remediation in remediations.items():
            if key in vuln_type:
                return remediation
        
        return "Follow OWASP guidelines for secure coding practices."
    
    def map_vuln_type(self, vuln_type):
        """Map vulnerability type to platform categories"""
        mapping = {
            'XSS': 'cross_site_scripting',
            'SQL Injection': 'sql_injection',
            'CSRF': 'csrf',
            'SSRF': 'ssrf',
            'Command Injection': 'command_injection'
        }
        return mapping.get(vuln_type, 'other')
    
    def batch_submit(self, vulnerabilities, platform='hackerone', api_key=None):
        """Submit multiple vulnerabilities"""
        print(f"\n[*] Batch submitting {len(vulnerabilities)} vulnerabilities to {platform}")
        
        results = []
        for vuln in vulnerabilities:
            if platform in self.platforms:
                result = self.platforms[platform](vuln, api_key)
                results.append(result)
        
        return results
    
    def generate_submission_report(self, results, output_file='bug_bounty_submissions.json'):
        """Generate report of submissions"""
        report = {
            'submission_date': datetime.now().isoformat(),
            'total_submissions': len(results),
            'results': results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Submission report saved: {output_file}")

def main():
    print("""
    ╔═══════════════════════════════════════════════════╗
    ║   Bug Bounty Automation                          ║
    ║   Auto-submit to HackerOne, Bugcrowd, Intigriti ║
    ╚═══════════════════════════════════════════════════╝
    """)
    
    automation = BugBountyAutomation()
    
    # Example vulnerability
    vuln = {
        'type': 'XSS',
        'url': 'https://example.com/search',
        'parameter': 'q',
        'payload': '<script>alert(1)</script>',
        'severity': 'HIGH'
    }
    
    print("\n[*] Example Vulnerability Report:")
    print(automation.format_vulnerability(vuln))
    
    print("\n[!] Note: This is a DRY RUN. No actual submissions made.")
    print("[*] To enable real submissions, configure API keys and uncomment submission code.")

if __name__ == "__main__":
    main()
