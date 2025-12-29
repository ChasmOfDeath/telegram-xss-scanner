# 🔍 Telegram XSS Vulnerability Scanner

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-linux%20%7C%20termux-lightgrey)

Professional XSS vulnerability scanner for Telegram bots and web applications.

## ⚠️ LEGAL DISCLAIMER

**FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY**

This tool is designed for:
- ✅ Security researchers with proper authorization
- ✅ Bug bounty programs
- ✅ Penetration testing with written permission
- ✅ Educational purposes in controlled environments

**ILLEGAL USES:**
- ❌ Unauthorized testing of systems you don't own
- ❌ Malicious exploitation
- ❌ Violating computer fraud laws (CFAA, etc.)

**You are responsible for obtaining proper authorization before scanning any system.**

---

## 🚀 Features

- 🤖 **Telegram Bot Scanner** - Test bots for XSS vulnerabilities
- 🌐 **Web Application Scanner** - Scan web apps linked from Telegram
- 💉 **Multiple Payload Types** - Comprehensive XSS payload database
- 📊 **Detailed Reports** - Generate professional vulnerability reports
- 🎯 **Parameter Detection** - Automatic parameter discovery
- 🔄 **Reflected XSS Detection** - Identify reflected XSS vulnerabilities

---

## 📋 Requirements

- Python 3.8+
- Internet connection
- Valid Telegram Bot Token (for bot scanning)

---

## 🔧 Installation

```bash
# Clone repository
git clone https://github.com/ChasmOfDeath/telegram-xss-scanner.git
cd telegram-xss-scanner

# Install dependencies
pip install -r requirements.txt

💻 Usage

Scan Web Application


python scanner.py
# Enter target URL when prompted
Insert at cursor

Scan Telegram Bot


python telegram_bot.py
# Enter bot token and chat ID
Insert at cursor



📁 Project Structure


telegram-xss-scanner/
├── scanner.py              # Main web scanner
├── telegram_bot.py         # Telegram bot scanner
├── web_scanner.py          # Advanced web scanning
├── payloads/               # XSS payload database
├── reports/                # Scan reports
├── config/                 # Configuration files
├── requirements.txt
├── README.md
└── LICENSE
Insert at cursor



🛡️ XSS Payload Examples

The scanner tests various XSS vectors:

<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
javascript:alert('XSS')
<iframe src=javascript:alert('XSS')>
Insert at cursor



📊 Sample Report


==================================================
XSS VULNERABILITY SCAN REPORT
==================================================

Scan Date: 2024-12-29 00:00:00
Total Vulnerabilities Found: 3

[1] Vulnerability Details:
URL: https://example.com/search
Parameter: q
Payload: <script>alert('XSS')</script>
Timestamp: 2024-12-29T00:00:00
Insert at cursor



🤝 Contributing

Contributions welcome! Please:

Fork the repository
Create feature branch
Add tests for new payloads
Submit pull request



📝 License

MIT License - See LICENSE file
Educational use only. Use responsibly and ethically.


🙏 Acknowledgments


OWASP XSS Prevention Cheat Sheet
PortSwigger Web Security Academy
Bug bounty community



📧 Contact



GitHub: [@ChasmOfDeath](https://github.com/ChasmOfDeath)


Issues: [Report bugs](https://github.com/ChasmOfDeath/telegram-xss-scanner/issues)




⚖️ Responsible Disclosure

If you find vulnerabilities using this tool:

Report to the affected party immediately
Allow reasonable time for fixes
Don't publicly disclose until patched
Follow responsible disclosure guidelines

Happy (legal) hunting! 🔍
