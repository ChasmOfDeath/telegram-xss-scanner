#!/usr/bin/env python3
"""
Telegram Bot XSS Scanner
Scans Telegram bot responses for XSS vulnerabilities
"""
import requests
import json
from datetime import datetime

class TelegramBotScanner:
    def __init__(self, bot_token):
        self.bot_token = bot_token
        self.base_url = f"https://api.telegram.org/bot{bot_token}"
        self.payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg/onload=alert(1)>",
        ]
    
    def send_message(self, chat_id, text):
        """Send message to bot"""
        url = f"{self.base_url}/sendMessage"
        data = {
            'chat_id': chat_id,
            'text': text,
            'parse_mode': 'HTML'
        }
        
        try:
            response = requests.post(url, json=data)
            return response.json()
        except Exception as e:
            print(f"[!] Error: {e}")
            return None
    
    def scan_bot(self, chat_id):
        """Scan bot for XSS vulnerabilities"""
        print(f"\n[*] Scanning Telegram Bot...")
        vulnerabilities = []
        
        for payload in self.payloads:
            print(f"[*] Testing payload: {payload[:50]}")
            result = self.send_message(chat_id, payload)
            
            if result and result.get('ok'):
                # Check if bot echoes back the payload
                if 'result' in result:
                    response_text = result['result'].get('text', '')
                    if payload in response_text:
                        print(f"[!] VULNERABLE: Bot echoes XSS payload")
                        vulnerabilities.append({
                            'payload': payload,
                            'response': response_text,
                            'timestamp': datetime.now().isoformat()
                        })
        
        return vulnerabilities

def main():
    print("""
    ╔═══════════════════════════════════════════╗
    ║   Telegram Bot XSS Scanner               ║
    ║   Educational & Authorized Use Only      ║
    ╚═══════════════════════════════════════════╝
    """)
    
    bot_token = input("\n[?] Enter Bot Token: ").strip()
    chat_id = input("[?] Enter Chat ID: ").strip()
    
    if not bot_token or not chat_id:
        print("[!] Missing required information")
        return
    
    scanner = TelegramBotScanner(bot_token)
    vulns = scanner.scan_bot(chat_id)
    
    if vulns:
        print(f"\n[!] Found {len(vulns)} potential vulnerabilities")
    else:
        print("\n[+] No vulnerabilities detected")

if __name__ == "__main__":
    main()
