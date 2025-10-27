# NOA-SQL-Scanner

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Status](https://img.shields.io/badge/status-beta-yellow)

**Automated SQL Injection Vulnerability Scanner for Web Applications**

SQL Scanner is a powerful, easy-to-use tool designed to automatically detect SQL injection vulnerabilities in web applications. It performs comprehensive testing including subdomain discovery, URL crawling, and multiple SQL injection techniques.

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
  - Certificate Transparency log analysis
  
- 🕷️ **Smart Web Crawling**
  - Automatic link extraction
  - Parameter identification
  - Configurable depth and URL limits

- 💉 **SQL Injection Testing**
  - **Error-Based Detection** (MySQL & PostgreSQL)
  - **Boolean-Based Blind SQL Injection**
  - **Time-Based Blind SQL Injection**
  - **UNION-Based Injection**

- 🛡️ **WAF Bypass Techniques**
  - User-Agent rotation
  - Header randomization
  - IP spoofing headers
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
git clone https://github.com/yourusername/sql-scanner.git
cd sql-scanner

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
| `--deep` | Enable deep crawling (max 500 URLs) | ❌ No |
| `-o, --output` | Output report file (default: sqli_report.txt) | ❌ No |
| `--threads` | Number of threads (reserved for future use) | ❌ No |
| `--no-banner` | Disable banner display | ❌ No |

## 🎯 How It Works

### Phase 1: Discovery
1. **Subdomain Enumeration** (if enabled)
   - DNS brute-force with common subdomain wordlist
   - Certificate Transparency logs via crt.sh
   
2. **URL Crawling**
   - Extracts all links from HTML pages
   - Identifies URLs with GET parameters
   - Respects max URL limit (500 default)
   - Implements rate limiting (0.5s delay)

### Phase 2: SQL Injection Testing

For each URL parameter, the scanner tests:

#### 1. Error-Based Injection
Tests payloads that trigger database errors:
```sql
' OR '1'='1
" OR "1"="1
' UNION SELECT NULL--
```

#### 2. Boolean-Based Blind Injection
Compares responses to TRUE and FALSE conditions:
```sql
' AND '1'='1  (TRUE)
' AND '1'='2  (FALSE)
```

#### 3. Time-Based Blind Injection
Tests for response delays:
```sql
' AND SLEEP(5)--         (MySQL)
' AND pg_sleep(5)--      (PostgreSQL)
```

#### 4. UNION-Based Injection
Tests for data exfiltration:
```sql
' UNION SELECT NULL,NULL--
' ORDER BY 1--
```

### Phase 3: Reporting
- Real-time vulnerability alerts during scan
- Comprehensive TXT report generation
- Vulnerability categorization and statistics

## 📊 Sample Output

### Console Output
```
╔═══════════════════════════════════════════════════════╗
║   ███████╗ ██████╗ ██╗         ███████╗ ██████╗     ║
║   SQL Injection Scanner v1.0                          ║
╚═══════════════════════════════════════════════════════╝

[*] Target: https://example.com
[*] Starting scan...

[+] Found subdomain: api.example.com
[+] Found URL with params: https://example.com/product?id=1

================================================================================
🚨 SQL INJECTION VULNERABILITY DETECTED! 🚨
================================================================================
[+] URL: https://example.com/product?id=1
[+] Parameter: id
[+] Payload: ' OR '1'='1
[+] Database: MySQL
[+] Attack Type: Error-Based
[+] Evidence: SQL syntax error near '1'='1'...
================================================================================
```

### Report File (sqli_report.txt)
```
================================================================================
SQL INJECTION VULNERABILITY SCAN REPORT
================================================================================

Target URL: https://example.com
Scan Date: 2025-01-15 14:30:00
Total Vulnerabilities Found: 3

================================================================================
VULNERABILITY #1
================================================================================

[!] Severity: HIGH
[!] Type: SQL Injection - Error-Based

URL: https://example.com/product?id=1
Parameter: id
Database Type: MySQL
Attack Type: Error-Based

Payload Used:
' OR '1'='1

Evidence:
SQL syntax error near '1'='1'...

Recommendation:
- Use parameterized queries (prepared statements)
- Implement input validation and sanitization
- Apply principle of least privilege for database accounts
```

## 🏗️ Project Structure

```
sql-scanner/
├── cli.py              # Main CLI interface
├── config.py           # Configuration & constants
├── crawler.py          # URL & subdomain discovery
├── scanner.py          # SQL injection testing engine
├── payloads.py         # SQL injection payloads
├── detector.py         # Vulnerability detection logic
├── reporter.py         # Report generation
├── requirements.txt    # Python dependencies
├── setup.py           # Installation script
├── .gitignore         # Git ignore rules
├── README.md          # This file
└── LICENSE            # MIT License

```

## 🔧 Configuration

Edit `config.py` to customize:

```python
# Scanning limits
MAX_URLS = 500                # Maximum URLs to crawl
MAX_CRAWL_DEPTH = 3          # Maximum crawling depth
RATE_LIMIT_DELAY = 0.5       # Seconds between requests

# Timeouts
REQUEST_TIMEOUT = 10         # HTTP request timeout
TIME_BASED_THRESHOLD = 5     # Time-based detection threshold

# Subdomain wordlist
SUBDOMAIN_WORDLIST = [
    'www', 'api', 'admin', 'test', 'dev', ...
]
```

## 🛠️ Development

### Running Tests

```bash
# Install dev dependencies
pip install pytest pytest-cov

# Run tests
pytest tests/

# Run with coverage
pytest --cov=. tests/
```

### Adding Custom Payloads

Edit `payloads.py`:

```python
ERROR_BASED_PAYLOADS = {
    'mysql': [
        "'",
        "' OR '1'='1",
        # Add your custom payload here
        "' OR 1=1--",
    ],
}
```

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Contribution Guidelines
- Follow PEP 8 style guide
- Add tests for new features
- Update documentation
- Keep commits atomic and descriptive

## 📝 Roadmap

- [ ] Multi-threading support
- [ ] JSON/HTML report formats
- [ ] POST parameter testing
- [ ] Cookie and header injection
- [ ] Advanced WAF bypass techniques
- [ ] Blind SQL injection data extraction
- [ ] MongoDB and NoSQL injection support
- [ ] Custom wordlist support
- [ ] Proxy support (HTTP/SOCKS)
- [ ] Authentication support (Basic, OAuth)

## 🐛 Known Issues

- Certificate Transparency API may rate limit on high volume
- Some WAFs may still block requests despite bypass attempts
- Time-based detection may have false positives on slow networks

## 📚 Resources

### SQL Injection Learning
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [SQL Injection Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)

### Related Tools
- [SQLMap](https://github.com/sqlmapproject/sqlmap)
- [NoSQLMap](https://github.com/codingo/NoSQLMap)
- [jSQL Injection](https://github.com/ron190/jsql-injection)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Your Name**
- GitHub: [@yourusername](https://github.com/yourusername)
- Email: your.email@example.com

## 🙏 Acknowledgments

- OWASP for SQL injection documentation
- SQLMap project for inspiration
- The security community for continuous research

## ⭐ Support

If you find this tool useful, please consider:
- ⭐ Starring the repository
- 🐛 Reporting bugs and issues
- 💡 Suggesting new features
- 🤝 Contributing code

---

**Remember**: Always obtain proper authorization before testing any system. Happy (ethical) hacking! 🔒
