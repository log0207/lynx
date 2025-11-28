import asyncio
import aiohttp
import os
import re
import urllib.parse
import socket
import json
import shutil
import hashlib
import time
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, UnexpectedAlertPresentException
from common import event_manager, TestingZone

SEVERITY_MAP = {
    "SQL Injection": "P1",
    "SQL Injection (POST)": "P1",
    "Reflected XSS": "P2",
    "Local File Inclusion": "P2",
    "CSRF Missing": "P2",
    "Open Redirect": "P3",
    "Sensitive File Found": "P3",
    "Weak Security Headers": "P3",
    "Cookie Security": "P3",
    "CORS Misconfiguration": "P3",
    "Information Disclosure": "P4",
    "TLS/SSL Issue": "P3",
    "API Endpoint Found": "P4",
    "Potential SSRF": "P2",
    "Secret Leaked": "P1",
    "Auth Issue": "P2",
    "HTML Injection": "P3",
    "Command Injection": "P1",
    "XXE Injection": "P1",
    "Form Security": "P4",
    "Open Port": "P4",
    "CMS Vulnerability": "P3"
}

class BaseScanner:
    def __init__(self, context):
        self.context = context
        self.name = self.__class__.__name__
        self.zone = TestingZone.ZONE_E

    async def emit_vulnerability(self, vuln_type, details, severity=None, remediation=None, url=None, payload=None):
        if severity is None:
            severity = SEVERITY_MAP.get(vuln_type, "P4")
        target_url = url if url else self.context.target
        unique_key = f"{vuln_type}|{target_url}|{details[:50]}"
        vuln_hash = hashlib.md5(unique_key.encode()).hexdigest()
        if vuln_hash in self.context.seen_vulns:
            return
        self.context.seen_vulns.add(vuln_hash)
        data = {
            "type": vuln_type,
            "url": target_url,
            "payload": payload,
            "details": details,
            "severity": severity,
            "scanner": self.name,
            "zone": self.zone.value,
            "remediation": remediation or "Apply standard security best practices."
        }
        try:
            await event_manager.emit("vulnerability", data)
            await event_manager.emit("log", f"[red][{severity}] {vuln_type} found in {self.zone.name}![/red]")
        except Exception as e:
            await event_manager.emit("log", f"[red][Error] Failed to emit vulnerability: {e}[/red]")

    def generate_injection_points(self, url, payload):
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        if params:
            for param in params:
                new_params = params.copy()
                new_params[param] = [payload]
                new_query = urllib.parse.urlencode(new_params, doseq=True)
                new_url = urllib.parse.urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment
                ))
                yield new_url
        if not params:
            if url.endswith('/'):
                yield f"{url}{payload}"
            else:
                yield f"{url}/{payload}"
            yield f"{url}?q={payload}"
            yield f"{url}?id={payload}"
            yield f"{url}?search={payload}"

    def cleanup(self):
        pass

class SQLiScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.scanned_forms = set()

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting advanced scan on {len(self.context.crawled_urls)} URLs...")
        payloads_file = os.path.join(self.context.payloads_dir, "sqli", "sqli.txt")
        if not os.path.exists(payloads_file):
            error_payloads = ["'", "\"", "1' OR '1'='1"]
        else:
            with open(payloads_file, "r", encoding="utf-8", errors="ignore") as f:
                error_payloads = [line.strip() for line in f if line.strip()]
        if len(error_payloads) > 30:
            error_payloads = error_payloads[:30]
        time_payloads = ["1' WAITFOR DELAY '0:0:5'--+", "1' AND SLEEP(5)--+", "1 AND SLEEP(5)"]
        tasks = []
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        for url in urls_to_scan:
            if "?" not in url:
                limited = error_payloads[:5]
                for payload in limited:
                    for target_url in self.generate_injection_points(url, payload):
                        tasks.append(self.check_error_based(payload, target_url))
                continue
            parsed = urllib.parse.urlparse(url)
            current_payloads = error_payloads

            for payload in current_payloads:
                for target_url in self.generate_injection_points(url, payload):
                    tasks.append(self.check_error_based(payload, target_url))
            for payload in time_payloads:
                for target_url in self.generate_injection_points(url, payload):
                    tasks.append(self.check_time_based(payload, target_url))
            tasks.append(self.scan_forms(url, error_payloads, [], time_payloads))
        chunk_size = 15
        for i in range(0, len(tasks), chunk_size):
            await asyncio.gather(*tasks[i:i+chunk_size])

    async def scan_forms(self, url, error_payloads, boolean_payloads, time_payloads):
        try:
            async with self.context.session.get(url) as response:
                html = await response.text()
                soup = BeautifulSoup(html, 'html.parser')
                forms = soup.find_all('form')
                for form in forms:
                    action = form.get('action')
                    method = form.get('method', 'get').lower()
                    inputs = form.find_all(['input', 'textarea'])
                    action_url = urllib.parse.urljoin(url, action) if action else url
                    input_names = sorted([i.get('name', '') for i in inputs])
                    form_sig = f"{action_url}|{method}|{','.join(input_names)}"
                    form_hash = hashlib.md5(form_sig.encode()).hexdigest()
                    if form_hash in self.scanned_forms:
                        continue
                    self.scanned_forms.add(form_hash)
                    for payload in error_payloads[:10]:
                        await self._inject_form(action_url, method, inputs, payload, "error")
                    for payload in time_payloads:
                        await self._inject_form(action_url, method, inputs, payload, "time")
        except Exception:
            pass

    async def _inject_form(self, url, method, inputs, payload, check_type):
        for input_tag in inputs:
            name = input_tag.get('name')
            if not name:
                continue
            data = {i.get('name'): 'test' for i in inputs if i.get('name')}
            data[name] = payload
            if method == 'post':
                if check_type == "error":
                    await self.check_post_error_based(url, data, payload)
                elif check_type == "time":
                    await self.check_post_time_based(url, data, payload)
            else:
                query = urllib.parse.urlencode(data)
                full_url = f"{url}?{query}"
                if check_type == "error":
                    await self.check_error_based(payload, full_url)
                elif check_type == "time":
                    await self.check_time_based(payload, full_url)

    async def check_post_error_based(self, url, data, payload):
        try:
            async with self.context.session.post(url, data=data) as response:
                text = await response.text()
                if self.is_vulnerable(text):
                    await self.emit_vulnerability("SQL Injection (POST)", f"Payload: {payload}\nData: {data}", "P1", "Use parameterized queries.")
        except Exception:
            pass

    async def check_post_time_based(self, url, data, payload):
        try:
            start = asyncio.get_event_loop().time()
            async with self.context.session.post(url, data=data) as response:
                await response.text()
            end = asyncio.get_event_loop().time()
            if (end - start) > 4:
                await self.emit_vulnerability("Time-Based SQLi (POST)", f"Payload: {payload}\nDelay: {end-start:.2f}s", "P1", "Use parameterized queries.")
        except Exception:
            pass

    async def check_error_based(self, payload, url=None):
        if not url:
            return
        try:
            async with self.context.session.get(url) as response:
                text = await response.text()
                if self.is_vulnerable(text):
                    await self.emit_vulnerability("SQL Injection", f"URL: {url}\nPayload: {payload}", "P1", "Use parameterized queries.")
        except Exception:
            pass

    async def check_time_based(self, payload, url):
        try:
            start = asyncio.get_event_loop().time()
            async with self.context.session.get(url) as response:
                await response.text()
            end = asyncio.get_event_loop().time()
            if (end - start) > 4:
                await self.emit_vulnerability("Time-Based SQLi", f"URL: {url}\nDelay: {end-start:.2f}s", "P1", "Use parameterized queries.")
        except Exception:
            pass

    def is_vulnerable(self, text):
        errors = ["SQL syntax", "mysql_fetch", "syntax error", "ORA-", "PostgreSQL", "SQLite/JDBCDriver"]
        return any(err in text for err in errors)

class HTMLInjectionScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting scan...")
        payloads = ["<h1>Lynx</h1>", "<iframe>", "<b>Bold</b>"]
        tasks = []
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        for url in urls_to_scan:
            for payload in payloads:
                tasks.append(self.check_payload(payload, url))
        await asyncio.gather(*tasks)

    async def check_payload(self, payload, url):
        target_url = f"{url}?q={payload}" if "?" in url else f"{url}/{payload}"
        try:
            async with self.context.session.get(target_url) as response:
                text = await response.text()
                if payload in text:
                    await self.emit_vulnerability("HTML Injection", "Payload reflected in response.", "P3", "Sanitize user input to prevent HTML injection.", url=target_url, payload=payload)
        except Exception:
            pass

class CommandInjectionScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting scan...")
        payloads = ["; cat /etc/passwd", "| cat /etc/passwd", "; type C:\\Windows\\win.ini", "| type C:\\Windows\\win.ini", "& whoami", "| whoami"]
        tasks = []
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        for url in urls_to_scan:
            for payload in payloads:
                tasks.append(self.check_payload(payload, url))
        await asyncio.gather(*tasks)

    async def check_payload(self, payload, url):
        target_url = f"{url}?cmd={payload}" if "?" in url else f"{url}?cmd={payload}"
        try:
            async with self.context.session.get(target_url) as response:
                text = await response.text()
                sigs = ["root:x:0:0", "[extensions]", "boot loader", "Microsoft Windows"]
                if any(sig in text for sig in sigs):
                    await self.emit_vulnerability("Command Injection", f"PoC URL: {target_url}\nPayload: {payload}", "P1", "Sanitize user input and use safe APIs.", url=target_url, payload=payload)
        except Exception:
            pass

class XXEScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting scan...")
        payloads = [
            """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file:///etc/passwd" >]><foo>&xxe;</foo>""",
            """<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE foo [<!ELEMENT foo ANY ><!ENTITY xxe SYSTEM "file://c:/windows/win.ini" >]><foo>&xxe;</foo>"""
        ]
        tasks = []
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        for url in urls_to_scan:
            for payload in payloads:
                tasks.append(self.check_payload(payload, url))
        await asyncio.gather(*tasks)

    async def check_payload(self, payload, url):
        headers = {"Content-Type": "application/xml"}
        try:
            async with self.context.session.post(url, data=payload, headers=headers) as response:
                text = await response.text()
                if "root:x:0:0" in text or "[extensions]" in text:
                    await self.emit_vulnerability("XXE Injection", f"PoC URL: {url}\nPayload: {payload[:50]}...", "P1", "Disable external entity processing.", url=url, payload=payload)
        except Exception:
            pass

class LFIScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting scan...")
        payloads = [
            "../../../../../../../../etc/passwd", 
            "../../../../../../../../windows/win.ini",
            "/etc/passwd", 
            "c:\\windows\\win.ini"
        ]
        tasks = []
        urls_to_scan = self.context.crawled_urls if self.context.crawled_urls else {self.context.target}
        for url in urls_to_scan:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            if params:
                for param in params:
                    for payload in payloads:
                        new_params = params.copy()
                        new_params[param] = [payload]
                        new_query = urllib.parse.urlencode(new_params, doseq=True)
                        new_url = urllib.parse.urlunparse((
                            parsed.scheme, parsed.netloc, parsed.path,
                            parsed.params, new_query, parsed.fragment
                        ))
                        tasks.append(self.check_payload(payload, new_url))
        await asyncio.gather(*tasks)

    async def check_payload(self, payload, url):
        try:
            async with self.context.session.get(url) as response:
                text = await response.text()
                if any(sig in text for sig in ["root:x:0:0", "[extensions]"]):
                    await self.emit_vulnerability("Local File Inclusion", f"PoC URL: {url}\nPayload: {payload}", "P2", "Validate user input against a whitelist of allowed files.", url=url, payload=payload)
        except Exception:
            pass

class RedirectScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
    async def run(self):
        pass

class AuthScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_B
    async def run(self):
        pass

class CSRFCheck(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_B
    async def run(self):
        pass

class FormSecurityCheck(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
    async def run(self):
        pass

class APIScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_D
    async def run(self):
        pass

class SecurityHeadersCheck(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_E

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting scan...")
        try:
            async with self.context.session.get(self.context.target) as response:
                headers = response.headers
                missing_headers = []
                
                if "strict-transport-security" not in headers:
                    missing_headers.append("Strict-Transport-Security")
                if "content-security-policy" not in headers:
                    missing_headers.append("Content-Security-Policy")
                if "x-frame-options" not in headers:
                    missing_headers.append("X-Frame-Options")
                if "x-content-type-options" not in headers:
                    missing_headers.append("X-Content-Type-Options")
                if "referrer-policy" not in headers:
                    missing_headers.append("Referrer-Policy")
                
                if missing_headers:
                    await self.emit_vulnerability(
                        "Weak Security Headers", 
                        f"Missing security headers: {', '.join(missing_headers)}", 
                        "P3", 
                        "Add missing security headers to HTTP responses.",
                        url=self.context.target
                    )
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Error: {e}")

class CORSCheck(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_E

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting scan...")
        try:
            headers = {"Origin": "http://evil.com"}
            async with self.context.session.get(self.context.target, headers=headers) as response:
                resp_headers = response.headers
                acao = resp_headers.get("access-control-allow-origin", "")
                acac = resp_headers.get("access-control-allow-credentials", "")
                
                if "*" in acao and "true" in acac.lower():
                    await self.emit_vulnerability(
                        "CORS Misconfiguration", 
                        "Wildcard origin with credentials allowed", 
                        "P3", 
                        "Restrict origins to trusted domains only.",
                        url=self.context.target
                    )
        except Exception as e:
            await event_manager.emit("log", f"[{self.name}] Error: {e}")

class CMSScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_E

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting scan...")
        try:
            async with self.context.session.get(self.context.target) as response:
                html_content = await response.text()
                soup = BeautifulSoup(html_content, 'html.parser')
                
                meta_gen = soup.find("meta", attrs={"name": "generator"})
                if meta_gen:
                    content = meta_gen.get("content", "")
                    if "WordPress" in content:
                        await self.emit_vulnerability("CMS Vulnerability", f"WordPress detected via meta tag: {content}", "P4", "Hide WordPress version to prevent targeted exploits.")
                    elif "Shopify" in content:
                        await self.emit_vulnerability("CMS Vulnerability", f"Shopify detected via meta tag: {content}", "P4", "Standard Shopify detection.")
                    elif "Joomla" in content:
                        await self.emit_vulnerability("CMS Vulnerability", f"Joomla detected via meta tag: {content}", "P4", "Hide Joomla version.")
                    elif "Drupal" in content:
                        await self.emit_vulnerability("CMS Vulnerability", f"Drupal detected via meta tag: {content}", "P4", "Hide Drupal version.")
                if "/wp-content/" in html_content or "/wp-includes/" in html_content:
                    await self.emit_vulnerability("CMS Vulnerability", "WordPress detected via asset paths (/wp-content/)", "P4", "Standard WordPress structure.")
                    await self.check_wp_login()
                if "cdn.shopify.com" in html_content:
                    await self.emit_vulnerability("CMS Vulnerability", "Shopify detected via CDN links", "P4", "Standard Shopify structure.")
        except Exception:
            pass

    async def check_wp_login(self):
        login_url = urllib.parse.urljoin(self.context.target, "wp-login.php")
        try:
            async with self.context.session.get(login_url) as response:
                if response.status == 200 and "user_login" in await response.text():
                    await self.emit_vulnerability("CMS Vulnerability", f"WordPress Login Page Exposed: {login_url}", "P3", "Restrict access to wp-login.php (e.g., IP whitelist, 2FA).")
        except Exception:
            pass
        api_url = urllib.parse.urljoin(self.context.target, "wp-json/wp/v2/users")
        try:
            async with self.context.session.get(api_url) as response:
                if response.status == 200:
                    content = await response.text()
                    if "id" in content and "slug" in content:
                        await self.emit_vulnerability("CMS Vulnerability", f"WordPress User Enumeration via API: {api_url}", "P3", "Disable REST API user endpoints or use a security plugin.")
        except Exception:
            pass

class SeleniumXSSScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.driver = None

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting dynamic XSS scan...")
        
        await event_manager.emit("log", f"[{self.name}] Optimizing {len(self.context.crawled_urls)} crawled URLs...")
        unique_paths = set()
        optimized_endpoints = []
        for url in self.context.crawled_urls:
            parsed = urllib.parse.urlparse(url)
            path = parsed.path
            if path not in unique_paths:
                unique_paths.add(path)
                optimized_endpoints.append(url)
            if len(optimized_endpoints) >= 10:
                break

        await event_manager.emit("log", f"[{self.name}] Optimized scan: Testing {len(optimized_endpoints)} unique endpoints.")
        await event_manager.emit("log", f"[Status] Launching Browser (may take 5-10s)...")

        canary = "LynxXSS"
        payloads = [
            f"<script>alert('{canary}')</script>",
            f"\"><script>alert('{canary}')</script>"
        ]

        test_urls = []
        for endpoint in optimized_endpoints:
            for payload in payloads:
                for injected_url in self.generate_injection_points(endpoint, payload):
                    test_urls.append((injected_url, payload))
        
        if not test_urls:
             await event_manager.emit("log", f"[{self.name}] No parameters found. Attempting query injection on endpoints.")
             for endpoint in optimized_endpoints:
                 for payload in payloads:
                     if "?" in endpoint:
                         test_urls.append((f"{endpoint}&q={urllib.parse.quote(payload)}", payload))
                     else:
                         test_urls.append((f"{endpoint}?q={urllib.parse.quote(payload)}", payload))

        if not test_urls:
             await event_manager.emit("log", f"[{self.name}] No test cases generated.")
             return

        await event_manager.emit("log", f"[{self.name}] Generated {len(test_urls)} test cases.")

        loop = asyncio.get_running_loop()
        try:
            results = await loop.run_in_executor(None, self._selenium_work, test_urls, loop)
        except Exception as e:
            await event_manager.emit("log", f"[red][{self.name}] Error running Selenium work: {e}[/red]")
            return

        for result in results:
            if "error" in result:
                 await event_manager.emit("log", f"[red][{self.name}] Error: {result['error']}[/red]")
            else:
                try:
                    await event_manager.emit("log", f"[{self.name}] Attempting to emit vulnerability: {result}")
                    await self.emit_vulnerability(
                        vuln_type=result["vuln_type"],
                        details=result["details"],
                        severity=result["severity"],
                        remediation=result["remediation"],
                        url=result["url"],
                        payload=result["payload"]
                    )
                except Exception as e:
                    await event_manager.emit("log", f"[red][{self.name}] Error emitting vulnerability: {e}[/red]")

    def _selenium_work(self, test_cases, loop):
        results = []
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-plugins")
        chrome_options.add_argument("--disable-images")
        chrome_options.add_argument("--disable-javascript")
        chrome_options.page_load_strategy = 'eager'
        chrome_options.add_argument("--blink-settings=imagesEnabled=false")

        self.driver = None

        def log_sync(msg):
            event_manager.emit_sync("log", msg)

        def init_driver():
            log_sync(f"[Selenium] Initializing Chrome Driver...")
            try:
                service = Service(ChromeDriverManager().install())
                driver = webdriver.Chrome(service=service, options=chrome_options)
                driver.set_page_load_timeout(10)
                driver.implicitly_wait(2)
                return driver
            except Exception as e:
                log_sync(f"[Selenium] Failed to initialize driver: {e}")
                return None

        self.driver = init_driver()
        if not self.driver:
            return [{"error": "Failed to start Selenium driver"}]

        log_sync(f"[Selenium] Driver Ready. Executing {len(test_cases)} tests...")

        for i, (target_url, payload) in enumerate(test_cases):
            if i % 3 == 0 or i == len(test_cases) - 1:
                log_sync(f"[Selenium] Progress: {i}/{len(test_cases)}")
            
            if self.driver is None:
                self.driver = init_driver()
                if not self.driver:
                    results.append({"error": "Driver failed to reinitialize"})
                    continue
            
            try:
                self.driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                    'source': 'Object.defineProperty(navigator, "webdriver", {get: () => undefined})'
                })
                
                self.driver.get(target_url)
                
                try:
                    WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                    alert = self.driver.switch_to.alert
                    alert_text = alert.text
                    if "LynxXSS" in alert_text or "XSS" in alert_text:
                        alert.accept()
                        results.append({
                            "vuln_type": "DOM/Reflected XSS (Selenium Verified)",
                            "details": f"Payload executed successfully in browser.\nAlert Text: {alert_text}",
                            "severity": "P1",
                            "remediation": "Sanitize input and use CSP.",
                            "url": target_url,
                            "payload": payload
                        })
                        log_sync(f"[bold green][Selenium] VULNERABILITY FOUND: {target_url}[/bold green]")
                    else:
                        alert.accept()
                except TimeoutException:
                    pass
                except NoAlertPresentException:
                    pass
                except UnexpectedAlertPresentException:
                    try:
                        alert = self.driver.switch_to.alert
                        alert.accept()
                    except:
                        pass
                
            except Exception as e:
                log_sync(f"[Debug] Selenium Error on {target_url}: {str(e)}")
                try:
                    self.driver.quit()
                except:
                    pass
                self.driver = None

        self.cleanup()
        return results

    def cleanup(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None

def get_all_scanners():
    return [
        SQLiScanner,
        SeleniumXSSScanner,
        HTMLInjectionScanner,
        CommandInjectionScanner,
        XXEScanner,
        LFIScanner,
        RedirectScanner,
        AuthScanner,
        CSRFCheck,
        FormSecurityCheck,
        APIScanner,
        SecurityHeadersCheck,
        CORSCheck,
        CMSScanner
    ]