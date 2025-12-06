<!-- PROJECT SHIELDS -->
<div align="center">

[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]

</div>

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/log0207/lynx">
    <img src="lynx logo.png" alt="Logo" width="120" height="120">
  </a>

  <h1 align="center">Lynx VAPT Automation Tool</h1>

  <p align="center">
    An advanced, AI-powered Vulnerability Assessment and Penetration Testing toolkit for modern web applications
    <br />
    <a href="https://github.com/log0207/lynx/issues">Report Bug</a>
    ·
    <a href="https://github.com/log0207/lynx/issues">Request Feature</a>
  </p>
</div>

---

## 🦁 About The Project

**Lynx v1.0 [BETA]** is a cutting-edge VAPT (Vulnerability Assessment and Penetration Testing) automation tool designed to identify security vulnerabilities in web applications with precision and speed. Built with Python's asynchronous capabilities and powered by optional AI analysis, Lynx offers enterprise-grade security testing in an accessible package.

### ✨ Key Highlights

* **🤖 Intelligent Automation**
  - Asynchronous architecture using `asyncio` and `aiohttp` for high-performance scanning
  - Event-driven design with real-time progress tracking
  - Smart crawling with Katana integration for comprehensive URL discovery
  - Selenium-based dynamic analysis for JavaScript-heavy applications

* **🔍 Comprehensive Vulnerability Detection**
  - **Zone A (Input/Output Validation)**: SQL Injection, XSS, Command Injection, XXE, HTML Injection, LFI
  - **Zone E (Server Configuration)**: Security Headers, CORS, CMS Detection, TLS/SSL
  - Severity-based classification (P1-P4) aligned with industry standards
  - Advanced payload libraries with WAF bypass techniques

* **🧠 AI-Powered Analysis** *(Optional)*
  - Google Gemini integration for intelligent vulnerability assessment
  - Automated executive summary generation
  - Business impact analysis and remediation prioritization

* **📊 Professional Reporting**
  - Beautiful HTML reports with modern, responsive UI
  - Detailed vulnerability breakdowns with CVSS scores
  - Remediation guidance and validation steps
  - JSON export for integration with CI/CD pipelines

* **🖥️ Real-Time Dashboard**
  - Live vulnerability findings visualization
  - Network activity monitoring with request/error tracking
  - Phase-based progress tracking (Pre-Engagement → Reporting)
  - Animated, color-coded severity indicators

---

## 🏗️ Architecture Overview

### Core Components

```
lynx/
├── lynx.py              # Main entry point & CLI interface
├── core.py              # ScanEngine & ScanContext orchestration
├── ui.py                # Real-time dashboard with Rich library
├── reporter.py          # HTML/JSON report generation
├── katana_crawler.py    # External Katana crawler integration
├── ai_engine.py         # Google Gemini AI integration
├── common.py            # Event system, utilities, constants
├── updater.py           # Auto-update functionality
├── scanners/            # Modular scanner architecture
│   ├── __init__.py      # Scanner registry
│   ├── base.py          # BaseScanner abstract class
│   ├── sqli.py          # SQL Injection scanner (GET/POST/Time-based)
│   ├── xss.py           # Selenium-based XSS scanner
│   ├── injection.py     # HTML, Command, XXE, LFI scanners
│   └── misconfig.py     # Security Headers, CORS, CMS scanners
├── payloads/            # Extensive payload libraries
│   ├── sqli.txt         # SQL injection payloads
│   ├── xss.txt          # XSS payloads
│   ├── lfi.txt          # LFI payloads
│   └── ...
└── templates/
    └── report_template.html  # Jinja2 report template
```

### Event-Driven Architecture

Lynx uses a custom `EventManager` for decoupled communication:

```python
# Event Types:
- "log"                  # Execution logs
- "vulnerability"        # Vulnerability findings
- "scanner_status"       # Scanner state updates
- "net_request_start"    # Network request initiated
- "net_request_end"      # Network request completed
- "net_request_error"    # Network request failed
```

### Scanner Lifecycle

1. **Initialization**: Scanners inherit from `BaseScanner` and register with `ScanEngine`
2. **Execution**: Asynchronous `run()` method with semaphore-controlled concurrency
3. **Reporting**: Vulnerabilities emitted via `emit_vulnerability()` with deduplication
4. **Cleanup**: Optional `cleanup()` for resource management (e.g., Selenium drivers)

---

## 🚀 Getting Started

### Prerequisites

* **Python 3.8+** (tested on Python 3.13)
* **Google Chrome** (for Selenium-based XSS scanner)
* **Katana** (optional, for advanced crawling): [Install Katana](https://github.com/projectdiscovery/katana)
* **Operating System**: Windows, macOS, or Linux

### Installation

#### Automated Installation (Recommended)

1. **Clone the repository**
   ```bash
   git clone https://github.com/log0207/lynx.git
   cd lynx
   ```

2. **Run the automated installer**
   ```bash
   python installer.py
   ```

   The installer will:
   - ✅ Check Python version (3.8+ required)
   - ✅ Verify pip installation
   - ✅ Install all Python dependencies (handles externally managed environments)
   - ✅ Verify package installation
   - ✅ Check for Google Chrome (required for XSS scanner)
   - ✅ Check for Katana crawler (optional but recommended)
   - ✅ Run verification tests

3. **Start using Lynx**
   ```bash
   python lynx.py --help
   ```

#### Manual Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/log0207/lynx.git
   cd lynx
   ```

2. **Install Python dependencies**
   ```bash
   # Standard installation
   pip install -r requirements.txt
   
   # If you encounter "externally managed" error (Linux):
   pip install -r requirements.txt --break-system-packages
   
   # Or use a virtual environment (recommended):
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. **Install Katana** (Optional but recommended)
   ```bash
   go install github.com/projectdiscovery/katana/cmd/katana@latest
   ```

4. **Verify installation**
   ```bash
   python lynx.py --help
   ```

---

## 💡 Usage

### Interactive Mode (Recommended)

Launch Lynx in interactive mode for a guided experience:

```bash
python lynx.py
```

**Interactive Menu Options:**
1. **Comprehensive VAPT Scan** - Full crawling + all vulnerability scanners
2. **Quick Scan** - Fast scanning without crawling (single URL)
3. **Custom Scans** - Select specific scanners (SQLi, XSS, etc.)
4. **AI Analysis** - Enable AI-powered executive summary

### Command Line Interface

For automation and scripting:

```bash
# Basic scan (no crawling)
python lynx.py -u https://example.com

# Full scan with crawling
python lynx.py -u https://example.com --crawl

# Quick scan (alias for no crawling)
python lynx.py -u https://example.com --quick

# Scan with specific scanners
python lynx.py -u https://example.com --scanners sqli,xss

# Enable AI analysis (requires GEMINI_API_KEY environment variable)
python lynx.py -u https://example.com --ai
```

### Testing with Demo Sites

For educational purposes, test Lynx on intentionally vulnerable sites:

```bash
# DVWA (Damn Vulnerable Web Application)
python lynx.py -u http://testphp.vulnweb.com --quick

# OWASP Juice Shop (if running locally)
python lynx.py -u http://localhost:3000 --crawl
```

**⚠️ Legal Notice**: Only test on applications you own or have explicit permission to test. Unauthorized security testing is illegal.

---

## ⚙️ Configuration

### Environment Variables

```bash
# Enable/disable debug logging (default: true)
export LYNX_DEBUG=true

# Google Gemini API key for AI analysis
export GEMINI_API_KEY=your_api_key_here
```

### Scanning Options

* **Concurrency**: Automatically adjusted (default semaphore: 15 concurrent scanners)
* **Crawling Depth**: Katana depth 3 with JavaScript crawling enabled
* **Timeout**: 60s total, 15s connect, 30s read
* **Payload Customization**: Edit files in `payloads/` directory

### AI Integration

To enable AI-powered vulnerability analysis:

1. Obtain a Google Gemini API key from [Google AI Studio](https://ai.google.dev/)
2. Set the environment variable:
   ```bash
   export GEMINI_API_KEY=your_api_key_here
   ```
3. Run with `--ai` flag or select AI analysis in interactive mode

---

## 🔍 Scanner Modules

### Zone A: Input/Output Validation

| Scanner | Vulnerability Type | Severity | Techniques |
|---------|-------------------|----------|------------|
| **SQLiScanner** | SQL Injection | P1 | Error-based, Time-based, Boolean-based, POST/GET |
| **SeleniumXSSScanner** | Reflected XSS | P2 | DOM-based detection, JavaScript execution |
| **HTMLInjectionScanner** | HTML Injection | P3 | Reflection-based detection |
| **CommandInjectionScanner** | OS Command Injection | P1 | Unix/Windows command signatures |
| **XXEScanner** | XML External Entity | P1 | File disclosure via XML parsing |
| **LFIScanner** | Local File Inclusion | P2 | Path traversal, file disclosure |

### Zone E: Server Configuration

| Scanner | Vulnerability Type | Severity | Checks |
|---------|-------------------|----------|--------|
| **SecurityHeadersCheck** | Missing Security Headers | P3 | HSTS, CSP, X-Frame-Options, etc. |
| **CORSCheck** | CORS Misconfiguration | P3 | Wildcard origins, credential leakage |
| **CMSScanner** | CMS Detection & Exposure | P3-P4 | WordPress, Joomla, Drupal, Shopify |

### Payload Libraries

- **SQL Injection**: 30+ payloads (error-based, union-based, time-based)
- **XSS**: 100+ payloads including WAF bypass techniques
- **LFI**: 5MB+ payload file with extensive path traversal variants
- **Command Injection**: Unix/Windows command execution signatures

---

## 📊 Reporting

### HTML Reports

Generated reports include:

* **Executive Summary** (with AI analysis if enabled)
* **Vulnerability Statistics Dashboard**
  - Severity breakdown (P1/P2/P3/P4)
  - Zone-based categorization
  - Scanner-specific findings
* **Detailed Findings**
  - CVSS scores and impact categories
  - Proof-of-Concept (PoC) URLs and payloads
  - Remediation guidance
  - Validation steps
* **Technical References**
  - OWASP Top 10 mappings
  - CWE identifiers

**Report Location**: `lynx_report_YYYYMMDD_HHMMSS.html`

### JSON Export

Structured vulnerability data for automation:

```json
{
  "type": "SQL Injection",
  "url": "https://example.com/page?id=1'",
  "payload": "1' OR '1'='1",
  "severity": "P1",
  "scanner": "SQLiScanner",
  "zone": "Zone A: Input/Output Validation",
  "remediation": "Use parameterized queries.",
  "details": "SQL syntax error detected..."
}
```

**Export Location**: `findings_YYYYMMDD_HHMMSS.json`

---

## 🛠️ Advanced Features

### Custom Scanner Development

Create custom scanners by extending `BaseScanner`:

```python
from scanners.base import BaseScanner
from common import TestingZone, event_manager

class MyCustomScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
    
    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting scan...")
        
        # Your scanning logic here
        for url in self.context.crawled_urls:
            # Test for vulnerabilities
            await self.emit_vulnerability(
                "Custom Vulnerability",
                "Detailed description",
                severity="P2",
                remediation="Fix recommendation",
                url=url
            )
```

Register in `scanners/__init__.py`:

```python
from .my_custom_scanner import MyCustomScanner

def get_all_scanners():
    return [
        # ... existing scanners
        MyCustomScanner
    ]
```

### Debugging

Enable detailed logging:

```bash
export LYNX_DEBUG=true
python lynx.py -u https://example.com
```

View logs in `debug.log`:

```
[12.34] [LOG] [Phase] Pre-Engagement: Initializing...
[15.67] [VULN] SQL Injection - https://example.com/page?id=1'
[18.90] [NET_ERR] {'url': 'https://example.com/404', 'error': '404'}
```

---

## 🗺️ Roadmap

- [x] Core VAPT scanning engine
- [x] SQL Injection detection (GET/POST/Time-based)
- [x] XSS detection with Selenium
- [x] AI-powered analysis with Google Gemini
- [x] Real-time dashboard with Rich library
- [x] HTML/JSON reporting
- [ ] **Enhanced API Security Testing**
  - GraphQL introspection
  - REST API fuzzing
  - JWT token analysis
- [ ] **Mobile Application Testing**
  - Android APK analysis
  - iOS IPA analysis
- [ ] **CI/CD Integration**
  - GitHub Actions workflow
  - GitLab CI template
  - Jenkins plugin
- [ ] **Additional Scanners**
  - SSRF detection
  - IDOR testing
  - Authentication bypass
  - Rate limiting checks
- [ ] **Multi-Language Support**
  - Internationalization (i18n)
  - Report translations
- [ ] **Cloud Platform Integrations**
  - AWS S3 bucket scanning
  - Azure Blob storage
  - GCP Cloud Storage

See the [open issues](https://github.com/log0207/lynx/issues) for a full list of proposed features and known issues.

---

## 🤝 Contributing

Contributions are what make the open-source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

### How to Contribute

1. **Fork the Project**
2. **Create your Feature Branch**
   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. **Commit your Changes**
   ```bash
   git commit -m 'Add some AmazingFeature'
   ```
4. **Push to the Branch**
   ```bash
   git push origin feature/AmazingFeature
   ```
5. **Open a Pull Request**

### Contribution Guidelines

- Follow PEP 8 style guide for Python code
- Add docstrings to all functions and classes
- Include unit tests for new features
- Update documentation (README, inline comments)
- Ensure all tests pass before submitting PR

---

## 📄 License

Distributed under the **MIT License**. See `LICENSE` file for more information.

---

## 📧 Contact

**Project Maintainer**: Logesh

**Project Link**: [https://github.com/log0207/lynx](https://github.com/log0207/lynx)

**Report Issues**: [https://github.com/log0207/lynx/issues](https://github.com/log0207/lynx/issues)

---

## 🙏 Acknowledgments

### Technologies & Libraries

* [Python AsyncIO](https://docs.python.org/3/library/asyncio.html) - Asynchronous programming framework
* [aiohttp](https://docs.aiohttp.org/) - Async HTTP client/server
* [Selenium](https://www.selenium.dev/) - Browser automation for dynamic analysis
* [Rich](https://github.com/Textualize/rich) - Beautiful terminal interfaces
* [Jinja2](https://palletsprojects.com/p/jinja/) - Template engine for reports
* [BeautifulSoup4](https://www.crummy.com/software/BeautifulSoup/) - HTML parsing
* [Google Generative AI](https://ai.google.dev/) - AI-powered analysis
* [Katana](https://github.com/projectdiscovery/katana) - Next-generation crawling framework

### Testing Resources

* [testphp.vulnweb.com](http://testphp.vulnweb.com) - Acunetix's intentionally vulnerable test site
* [OWASP WebGoat](https://owasp.org/www-project-webgoat/) - Educational vulnerable application
* [DVWA](https://github.com/digininja/DVWA) - Damn Vulnerable Web Application
* [OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) - Modern vulnerable web application

### Security Standards

* [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Web application security risks
* [CWE](https://cwe.mitre.org/) - Common Weakness Enumeration
* [CVSS](https://www.first.org/cvss/) - Common Vulnerability Scoring System

---

## 📚 Additional Resources

### Documentation

- [Installation Guide](docs/installation.md) *(Coming Soon)*
- [Scanner Development Guide](docs/scanner-development.md) *(Coming Soon)*
- [API Reference](docs/api-reference.md) *(Coming Soon)*

### Tutorials

- [Getting Started with Lynx](docs/tutorials/getting-started.md) *(Coming Soon)*
- [Advanced Configuration](docs/tutorials/advanced-config.md) *(Coming Soon)*
- [CI/CD Integration](docs/tutorials/cicd-integration.md) *(Coming Soon)*

---

## ⚠️ Disclaimer

**Lynx is designed for authorized security testing only.** Unauthorized access to computer systems is illegal. Users are responsible for ensuring they have proper authorization before testing any systems. The developers assume no liability for misuse or damage caused by this tool.

**Use responsibly. Test ethically. Secure the web.**

---

<!-- MARKDOWN LINKS & IMAGES -->
[contributors-shield]: https://img.shields.io/github/contributors/log0207/lynx.svg?style=for-the-badge
[contributors-url]: https://github.com/log0207/lynx/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/log0207/lynx.svg?style=for-the-badge
[forks-url]: https://github.com/log0207/lynx/network/members
[stars-shield]: https://img.shields.io/github/stars/log0207/lynx.svg?style=for-the-badge
[stars-url]: https://github.com/log0207/lynx/stargazers
[issues-shield]: https://img.shields.io/github/issues/log0207/lynx.svg?style=for-the-badge
[issues-url]: https://github.com/log0207/lynx/issues
[license-shield]: https://img.shields.io/github/license/log0207/lynx.svg?style=for-the-badge
[license-url]: https://github.com/log0207/lynx/blob/master/LICENSE.txt