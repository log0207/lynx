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
    An advanced, automated Vulnerability Assessment and Penetration Testing toolkit for modern web applications
    <br />
    <a href="https://github.com/log0207/lynx/issues">Report Bug</a>
    ·
    <a href="https://github.com/log0207/lynx/issues">Request Feature</a>
  </p>
</div>

<!-- ABOUT THE PROJECT -->
## 🦁 About The Project

Lynx is a cutting-edge VAPT (Vulnerability Assessment and Penetration Testing) automation tool designed to identify security vulnerabilities in web applications. Built with Python's asynchronous capabilities, Lynx offers high-performance scanning while maintaining accuracy in vulnerability detection.

### Key Features

* **🤖 Automated Scanning Pipeline**
  - Intelligent crawling and mapping of web applications
  - Automated vulnerability detection across multiple attack vectors
  - Dynamic analysis using headless browsers

* **🔍 Comprehensive Security Testing**
  - Injection flaws (SQLi, Command Injection, XXE, HTML Injection)
  - Client-side vulnerabilities (XSS, Open Redirects)
  - Server-side issues (LFI, SSRF, Misconfigurations)
  - Authentication and authorization weaknesses

* **⚡ High Performance Engine**
  - Asynchronous architecture using `asyncio` and `aiohttp`
  - Concurrent request handling for rapid scanning
  - Optimized resource utilization

* **🖥️ Interactive Dashboard**
  - Real-time progress tracking with rich CLI interface
  - Live vulnerability findings visualization
  - Network activity monitoring

* **🧠 AI-Powered Analysis** *(Optional)*
  - Integration with Google Gemini for intelligent vulnerability assessment
  - Automated executive summary generation
  - Enhanced vulnerability classification

* **📊 Professional Reporting**
  - Beautiful HTML reports with modern UI
  - Detailed vulnerability breakdowns
  - Remediation guidance

<!-- GETTING STARTED -->
## 🚀 Getting Started

To get a local copy up and running, follow these simple steps.

### Prerequisites

* Python 3.8 or higher
* Google Chrome browser (for Selenium-based scans)
* Windows, macOS, or Linux operating system

### Installation

1. Clone the repository
   ```bash
   git clone https://github.com/log0207/lynx.git
   cd lynx
   ```

2. Install required dependencies
   ```bash
   pip install -r requirements.txt
   ```

3. Verify installation
   ```bash
   python lynx.py --help
   ```

<!-- USAGE EXAMPLES -->
## 💡 Usage

### Interactive Mode

Launch Lynx in interactive mode for guided scanning:

```bash
python lynx.py
```

In interactive mode, you can choose from:
1. **Comprehensive VAPT Scan** - Full crawling and vulnerability assessment
2. **Quick Scan** - Fast scanning without crawling
3. **Custom Scans** - Targeted modules (SQLi, XSS, etc.)
4. **AI Analysis** - Enhanced scanning with AI-powered insights

### Command Line Interface

For automated or scripted usage:

```bash
# Basic scan
python lynx.py -u https://example.com

# Quick scan (no crawling)
python lynx.py -u https://example.com --quick

# Enable AI analysis (requires API key)
python lynx.py -u https://example.com --quick
```

### Testing with Demo Sites

For testing purposes, you can use the publicly available demo site:

```bash
# Test with the vulnerable test site
python lynx.py -u http://testphp.vulnweb.com --quick
```

**Note**: [testphp.vulnweb.com](http://testphp.vulnweb.com) is a legitimate demo site specifically designed for security testing and education. It contains intentional vulnerabilities for practicing penetration testing techniques.

<!-- CONFIGURATION -->
## ⚙️ Configuration

### Scanning Options

* **Concurrency Control**: Automatically adjusted for optimal performance (default semaphore: 25)
* **Crawling Depth**: Configurable depth for web application mapping
* **Payload Customization**: Modify payloads in the `payloads/` directory

### AI Integration

To enable AI-powered vulnerability analysis:
1. Obtain a Google Gemini API key
2. Set the `GEMINI_API_KEY` environment variable
3. Select AI analysis option in interactive mode

### Debugging

Control debug output with the `LYNX_DEBUG` environment variable:
* `LYNX_DEBUG=true` - Enable detailed logging to `debug.log`
* `LYNX_DEBUG=false` - Disable logging (default)

<!-- SCANNER MODULES -->
## 🔍 Scanner Modules

Lynx implements a modular scanning architecture organized by security testing zones:

### Zone A: Input/Output Validation
* SQL Injection Scanner
* Cross-Site Scripting (XSS) Scanner
* Command Injection Detector
* XML External Entity (XXE) Scanner
* HTML Injection Checker
* Local File Inclusion (LFI) Detector

### Zone B: Authentication & Authorization
* Authentication Mechanism Testing
* Session Management Analysis
* Access Control Verification
* CSRF Protection Evaluation

### Zone C: Business Logic
* Workflow Validation
* Transaction Integrity Checks
* Parameter Manipulation Tests

### Zone D: API Security
* REST API Endpoint Analysis
* GraphQL Security Testing
* Rate Limiting Evaluation

### Zone E: Server Configuration
* Security Header Assessment
* CORS Misconfiguration Detection
* Content Management System Identification
* TLS/SSL Configuration Review

<!-- REPORTING -->
## 📊 Reporting

Lynx generates two types of reports:

### HTML Reports
Modern, interactive reports featuring:
* Vulnerability statistics dashboard
* Grouped findings by severity
* Detailed vulnerability descriptions
* Remediation recommendations
* Technical references

### JSON Findings
Structured vulnerability data for:
* Integration with other tools
* Automated processing workflows
* Custom reporting solutions

Reports are automatically saved in the working directory with timestamps.

<!-- ROADMAP -->
## 🗺️ Roadmap

- [ ] Enhanced API security testing capabilities
- [ ] Mobile application testing support
- [ ] CI/CD pipeline integration
- [ ] Additional vulnerability scanners
- [ ] Multi-language support
- [ ] Cloud platform integrations

See the [open issues](https://github.com/log0207/lynx/issues) for a full list of proposed features.

<!-- CONTRIBUTING -->
## 🤝 Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->
## 📄 License

Distributed under the MIT License. See `LICENSE` file for more information.

<!-- CONTACT -->
## 📧 Contact

Project Link: [https://github.com/log0207/lynx](https://github.com/log0207/lynx)

<!-- ACKNOWLEDGMENTS -->
## 🙏 Acknowledgments

* [Python AsyncIO](https://docs.python.org/3/library/asyncio.html) for asynchronous programming
* [Selenium](https://www.selenium.dev/) for browser automation
* [Rich](https://github.com/Textualize/rich) for beautiful terminal interfaces
* [Jinja2](https://palletsprojects.com/p/jinja/) for templating
* [Google Generative AI](https://ai.google.dev/) for AI capabilities
* [testphp.vulnweb.com](http://testphp.vulnweb.com) for providing a safe testing environment

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