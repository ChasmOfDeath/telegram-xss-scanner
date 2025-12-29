#!/usr/bin/env python3
"""
Master Control Panel
Central hub for all security testing tools
"""
import os
import sys

class MasterControl:
    def __init__(self):
        self.tools = {
            '1': ('DOM XSS Scanner', 'python dom_xss_scanner.py'),
            '2': ('Comprehensive XSS Scanner', 'python scanner.py'),
            '3': ('Telegram Bot Scanner', 'python telegram_bot.py'),
            '4': ('Attack Tools Suite', 'python attack_tools.py'),
            '5': ('Exploit Generator', 'python exploit_generator.py'),
            '6': ('Integrated Framework (Full Scan + Exploits)', 'python integrated_exploit_framework.py'),
            '7': ('Payload Generator', 'python payloads/dom_xss_payloads.py'),
        }
    
    def display_banner(self):
        print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║        🔒 MASTER SECURITY TESTING CONTROL PANEL 🔒        ║
    ║                                                           ║
    ║   Comprehensive Vulnerability Assessment & Exploitation  ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
        """)
    
    def display_menu(self):
        print("\n" + "="*60)
        print("AVAILABLE TOOLS")
        print("="*60)
        
        for key, (name, _) in self.tools.items():
            print(f"{key}. {name}")
        
        print("0. Exit")
        print("="*60)
    
    def run(self):
        self.display_banner()
        
        while True:
            self.display_menu()
            choice = input("\n[?] Select tool (0-7): ").strip()
            
            if choice == '0':
                print("\n[+] Exiting Master Control Panel...")
                print("[!] Remember: Use these tools responsibly and legally!")
                break
            
            if choice not in self.tools:
                print("[!] Invalid choice")
                continue
            
            tool_name, command = self.tools[choice]
            
            print(f"\n[*] Launching: {tool_name}")
            print(f"[*] Command: {command}\n")
            
            os.system(command)
            
            input("\n[*] Press Enter to return to menu...")

if __name__ == "__main__":
    control = MasterControl()
    control.run()
