# Usage Guide - Telegram XSS Scanner

## Quick Start

```bash
# Run quick start script
./quick_start.sh

# Or manually launch master control
python master_control.py

Individual Tools

1. DOM XSS Scanner

Detects client-side XSS vulnerabilities in JavaScript code.

python dom_xss_scanner.py
Insert at cursor

Features:

Source-to-sink flow analysis
Dangerous pattern detection
Payload testing
Detailed JSON/text reports

2. Comprehensive XSS Scanner

Scans for all types of XSS (DOM, Reflected, Stored).

python scanner.py
Insert at cursor

3. Telegram Bot Scanner

Tests Telegram bots for XSS vulnerabilities.

python telegram_bot.py
Insert at cursor

Required:

Bot token
Chat ID

4. Attack Tools Suite

10 different security testing tools.

python attack_tools.py
Insert at cursor

Tools included:

SQL Injection Scanner
Command Injection Scanner
XXE Scanner
SSRF Scanner
Path Traversal Scanner
CORS Misconfiguration Checker
Security Headers Analyzer
SSL/TLS Analysis
Subdomain Enumeration
Port Scanner

5. Exploit Generator

Automatically generates working PoC exploits.

python exploit_generator.py
Insert at cursor

Generates:

Cookie stealers
Keyloggers
Session hijackers
Phishing pages
CSRF exploits

6. Integrated Framework

Full vulnerability scan + automatic exploit generation.

python integrated_exploit_framework.py
Insert at cursor

Process:

Comprehensive vulnerability scan (10 different tests)
Automatic exploit generation
HTML/JSON/Text report generation

7. Payload Generator

Context-aware XSS payload generator.

python payloads/dom_xss_payloads.py
Insert at cursor

Payload categories:

Hash-based
Search parameter
innerHTML
eval()
jQuery

Master Control Panel

Central hub for all tools.

python master_control.py
Insert at cursor

Menu:

DOM XSS Scanner
Comprehensive XSS Scanner
Telegram Bot Scanner
Attack Tools Suite
Exploit Generator
Integrated Framework
Payload Generator

Output Files

Reports Directory


reports/
├── dom_xss_report_TIMESTAMP.json
├── dom_xss_report_TIMESTAMP.txt
├── pentest_report_TIMESTAMP.json
├── pentest_report_TIMESTAMP.html
└── pentest_report_TIMESTAMP.txt
Insert at cursor

Exploits Directory


exploits/
├── dom_xss_1_1.html
├── reflected_xss_2_1.html
├── sql_injection_3_1.html
└── ...
Insert at cursor

Example Workflow

Basic Scan


# 1. Launch master control
python master_control.py

# 2. Select tool #6 (Integrated Framework)
# 3. Enter target URL
# 4. Wait for scan completion
# 5. Review reports in reports/ directory
Insert at cursor

Advanced Usage


# 1. Run DOM XSS scan
python dom_xss_scanner.py
# Enter: https://example.com

# 2. Generate exploits
python exploit_generator.py

# 3. Review exploits in exploits/ directory
Insert at cursor

Legal & Ethical Use

⚠️ CRITICAL REMINDERS:


Authorization Required

Always get written permission
Document your scope
Follow rules of engagement



Responsible Disclosure

Report vulnerabilities privately
Allow time for fixes
Don't publicly disclose until patched



Legal Compliance

Follow local laws (CFAA, GDPR, etc.)
Respect bug bounty program rules
Never test production systems without permission



Ethical Guidelines

Don't cause harm
Don't access/modify data without permission
Don't disrupt services
Maintain confidentiality



Troubleshooting

Common Issues

Import errors:

pip install -r requirements.txt
Insert at cursor

Permission denied:

chmod +x *.py *.sh
Insert at cursor

No vulnerabilities found:

Target may be secure
Try different payloads
Check network connectivity

Exploit generation fails:

Ensure exploits/ directory exists
Check vulnerability data format

Advanced Configuration

Custom Payloads

Edit payloads/dom_xss_payloads.py to add custom payloads.
Custom Exploit Templates

Edit exploit_generator.py to add new exploit types.
Scan Timeout

Modify timeout values in scanner files (default: 5 seconds).
Support

For issues or questions:

GitHub Issues: https://github.com/ChasmOfDeath/telegram-xss-scanner/issues

Documentation: README.md

Updates

Check for updates:

git pull origin master
pip install -r requirements.txt --upgrade
Insert at cursor

