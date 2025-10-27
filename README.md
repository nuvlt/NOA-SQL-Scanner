# NOA SQL Scanner

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Version](https://img.shields.io/badge/version-1.9.0.3-orange)
![Status](https://img.shields.io/badge/status-beta-yellow)

**Automated SQL Injection Vulnerability Scanner for Web Applications**

NOA SQL Scanner is a powerful, easy-to-use tool designed to automatically detect SQL injection vulnerabilities in web applications. It performs comprehensive testing including subdomain discovery, URL crawling, and multiple SQL injection techniques targeting MySQL and PostgreSQL databases.

## ⚠️ Legal Disclaimer

**WARNING**: This tool is designed for authorized security testing only. 

- ✅ Use only on systems you own or have explicit permission to test
- ❌ Unauthorized testing is illegal and unethical
- 🔒 Users are responsible for compliance with local laws
- 📋 Always obtain written permission before testing

## ✨ Features

### Core Capabilities
- 🌐 **Subdomain Discovery**
  - DNS brute-force enumeration
  - Certificate Transparency log analysis (crt.sh)
  
- 🕷️ **Smart Web Crawling**
  - Automatic link extraction
  - Parameter identification
  - Configurable depth and URL limits (max 500 URLs)
  - Rate limiting (0.5s delay between requests)

- 💉 **SQL Injection Testing**
  - **Error-Based Detection** (MySQL & PostgreSQL)
  - **Boolean-Based Blind SQL Injection**
  - **Time-Based Blind SQL Injection**
  - **UNION-Based Injection**

- 🛡️ **WAF Bypass Techniques**
  - User-Agent rotation
  - Header randomization
  - IP spoofing headers (X-Forwarded-For)
  - Rate limiting

- 📊 **Comprehensive Reporting**
  - Real-time vulnerability alerts
  - Detailed TXT reports
  - Attack categorization
  - Remediation recommendations

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/NOA-SQL-Scanner.git
cd NOA-SQL-Scanner

# Install dependencies
pip install -r requirements.txt

# Or install as a package
pip install -e .
```

## 📖 Usage

### Basic Scan

```bash
python cli.py -u https://example.com
```

### Advanced Options

```bash
# Full scan with subdomain discovery
python cli.py -u https://example.com --subdomains --deep

# Custom output file
python cli.py -u https://example.com -o my_report.txt

# Deep crawling without subdomain discovery
python cli.py -u https://example.com --deep

# Disable banner
python cli.py -u https://example.com --no-banner
```

### Command Line Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `-u, --url` | Target URL to scan | ✅ Yes |
| `--subdomains` | Enable subdomain discovery | ❌ No |
| `--deep` | Enable deep craw
