import os
import datetime
import html
import urllib.parse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from common import console, VERSION

VULN_DB = {
    "SQL Injection": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical)",
        "impact_cat": "Data Integrity & Confidentiality",
        "summary": "The application allows untrusted user input to interfere with database queries. This was found in a URL parameter or form field. It is dangerous because it allows attackers to view, modify, or delete database data.",
        "technical": "The application constructs SQL queries by concatenating user input directly into the query string without validation or parameterization. This allows an attacker to inject malicious SQL tokens to alter the query logic.",
        "impact_analysis": "Technical: Full database compromise, data exfiltration, authentication bypass.\nBusiness: Severe data breach, regulatory fines (GDPR/CCPA), loss of customer trust.",
        "risk_justification": "Rated P1 (Critical) due to high impact (data loss) and high exploitability (often automated).",
        "remediation": "Use parameterized queries (Prepared Statements) for all database access. Validate and sanitize all user inputs.",
        "validation": "Retest with the same payload. Ensure the application returns a standard error or handles the input safely without executing the SQL.",
        "references": "OWASP Top 10: A03:2021-Injection, CWE-89"
    },
    "Reflected XSS": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N (6.1 Medium)",
        "impact_cat": "Client-Side Injection",
        "summary": "The application reflects user input in the HTTP response without proper escaping. Found in a URL parameter. Dangerous as it allows execution of malicious scripts in the victim's browser.",
        "technical": "The application takes data from the request (e.g., query parameter) and outputs it to the DOM or HTML body without HTML entity encoding. This allows <script> tags or event handlers to execute.",
        "impact_analysis": "Technical: Session hijacking, cookie theft, redirection to phishing sites.\nBusiness: Account takeover of users, reputation damage.",
        "risk_justification": "Rated P2 (High) as it requires user interaction (phishing) but can lead to full account compromise.",
        "remediation": "Sanitize all user inputs and use proper HTML entity encoding when rendering user data. Implement a strong Content Security Policy (CSP).",
        "validation": "Retest with the same payload. Ensure the application HTML-encodes the output or blocks the request.",
        "references": "OWASP Top 10: A03:2021-Injection, CWE-79"
    },
    "CMS Vulnerability": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L (5.3 Medium)",
        "impact_cat": "Security Misconfiguration",
        "summary": "A vulnerability or misconfiguration was detected in the Content Management System (CMS).",
        "technical": "The scanner identified a CMS (e.g., WordPress, Shopify) and found exposed version info, login pages, or known paths.",
        "impact_analysis": "Technical: Information disclosure, potential for known exploits.\nBusiness: Increased attack surface.",
        "risk_justification": "Rated P3/P4 depending on the finding.",
        "remediation": "Update CMS to latest version, hide version headers, and restrict access to admin panels.",
        "validation": "Verify the finding manually.",
        "references": "OWASP Top 10: A06:2021-Vulnerable and Outdated Components"
    },
    "403 Bypass": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N (5.3 Medium)",
        "impact_cat": "Security Misconfiguration",
        "summary": "Access control bypass detected on a restricted endpoint (403/401).",
        "technical": "The scanner successfully accessed a restricted page by manipulating HTTP headers (e.g., X-Forwarded-For) or the URL structure.",
        "impact_analysis": "Technical: Unauthorized access to admin panels or internal APIs.\nBusiness: Data breach, unauthorized actions.",
        "risk_justification": "Rated P1 (Critical) if sensitive data is exposed.",
        "remediation": "Configure the web server to ignore unauthorized proxy headers and enforce strict URL matching.",
        "validation": "Reproduce with the specific header or URL modification.",
        "references": "OWASP Top 10: A01:2021-Broken Access Control"
    },
    "Secret Leaked": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (7.5 High)",
        "impact_cat": "Information Disclosure",
        "summary": "A sensitive secret (API Key, Access Token, Private Key) was found hardcoded in the response. Found in the HTML source or JS file. Dangerous as it allows unauthorized access to third-party services or internal systems.",
        "technical": "Developers have accidentally committed secrets to the codebase or included them in client-side assets. The scanner identified a pattern matching a known secret format.",
        "impact_analysis": "Technical: Unauthorized API access, potential data leakage, billing abuse.\nBusiness: Financial loss, data breach, unauthorized access to cloud resources.",
        "risk_justification": "Rated P1 (Critical) if the key is active and high-privilege. P2/P3 if low privilege.",
        "remediation": "Revoke the exposed key immediately. Remove the key from the code and use environment variables or a secrets manager. Rotate all related secrets.",
        "validation": "Verify the key is no longer in the source code. Attempt to use the revoked key to ensure it is invalid.",
        "references": "OWASP Top 10: A05:2021-Security Misconfiguration, CWE-798"
    },
    "DEFAULT": {
        "cvss": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L (5.0 Medium)",
        "impact_cat": "Security Misconfiguration",
        "summary": "A security issue was identified in the application configuration or logic.",
        "technical": "The application fails to implement standard security controls or validation.",
        "impact_analysis": "Technical: Varies based on vulnerability.\nBusiness: Increased attack surface.",
        "risk_justification": "Rated based on standard severity mapping.",
        "remediation": "Apply security best practices relevant to the specific issue.",
        "validation": "Retest to confirm the issue is resolved.",
        "references": "OWASP Top 10"
    }
}

class Reporter:
    def __init__(self, context):
        self.context = context
        self.template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
        self.env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(['html', 'xml'])
        )

    def generate_report(self) -> str:
        try:
            template = self.env.get_template("report_template.html")
            
            vulns = self.context.findings
            target = self.context.target
            ai_summary = self.context.ai_summary
            
            stats = {
                "P1": sum(1 for v in vulns if v['severity'] == 'P1'),
                "P2": sum(1 for v in vulns if v['severity'] == 'P2'),
                "P3": sum(1 for v in vulns if v['severity'] == 'P3'),
                "P4": sum(1 for v in vulns if v['severity'] == 'P4'),
                "Total": len(vulns)
            }

            grouped = {}
            for v in vulns:
                v_type = v['type']
                if v_type not in grouped:
                    grouped[v_type] = []
                grouped[v_type].append(v)

            severity_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
            sorted_groups = dict(sorted(grouped.items(), key=lambda x: severity_order.get(x[1][0]['severity'], 99)))

            html_content = template.render(
                target=target,
                date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                version=VERSION,
                stats=stats,
                grouped_findings=sorted_groups,
                vuln_db=VULN_DB,
                ai_summary=ai_summary
            )

            filename = f"report_{urllib.parse.urlparse(target).netloc}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            with open(filename, "w", encoding="utf-8") as f:
                f.write(html_content)
            
            return filename
            
        except Exception as e:
            console.print(f"[bold red]Error generating report:[/bold red] {e}")
            import traceback
            traceback.print_exc()
            return None