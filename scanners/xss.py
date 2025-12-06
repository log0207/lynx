import asyncio
import urllib.parse
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, NoAlertPresentException, UnexpectedAlertPresentException

from .base import BaseScanner
from common import event_manager, TestingZone

class SeleniumXSSScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.driver = None

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting dynamic XSS scan...")
        await event_manager.emit("log", f"[{self.name}] Optimizing {len(self.context.crawled_urls)} crawled URLs...")
        
        optimized_endpoints = self._optimize_endpoints()
        
        await event_manager.emit("log", f"[{self.name}] Optimized scan: Testing {len(optimized_endpoints)} endpoints.")
        await event_manager.emit("log", f"[Status] Launching Browser (may take 5-10s)...")

        canary = "LynxXSS"
        payloads = [
            f"<script>alert('{canary}')</script>",
            f"\"><script>alert('{canary}')</script>"
        ]

        test_urls = await self._generate_test_cases(optimized_endpoints, payloads)

        if not test_urls:
             await event_manager.emit("log", f"[{self.name}] No test cases generated.")
             return

        await event_manager.emit("log", f"[{self.name}] Generated {len(test_urls)} test cases.")

        loop = asyncio.get_running_loop()
        try:
            results = await loop.run_in_executor(None, self._selenium_work, test_urls)
        except Exception as e:
            await event_manager.emit("log", f"[red][{self.name}] Error running Selenium work: {e}[/red]")
            return

        for result in results:
            if "error" in result:
                 await event_manager.emit("log", f"[red][{self.name}] Error: {result['error']}[/red]")
            else:
                await self.emit_vulnerability(
                    vuln_type=result["vuln_type"],
                    details=result["details"],
                    severity=result["severity"],
                    remediation=result["remediation"],
                    url=result["url"],
                    payload=result["payload"]
                )

    def _optimize_endpoints(self):
        unique_paths = set()
        optimized_endpoints = []

        # Prioritize URLs with parameters
        param_urls = [u for u in self.context.crawled_urls if "?" in u]
        other_urls = [u for u in self.context.crawled_urls if "?" not in u]

        # Add up to 20 param URLs
        for url in param_urls:
            if len(optimized_endpoints) >= 20: break
            optimized_endpoints.append(url)

        # Fill rest with unique paths
        for url in other_urls:
            if len(optimized_endpoints) >= 30: break
            parsed = urllib.parse.urlparse(url)
            if parsed.path not in unique_paths:
                unique_paths.add(parsed.path)
                optimized_endpoints.append(url)
        
        return optimized_endpoints

    async def _generate_test_cases(self, endpoints, payloads):
        test_urls = []
        for endpoint in endpoints:
            # Generate URL-based injections
            for payload in payloads:
                for injected_url in self.generate_injection_points(endpoint, payload):
                    test_urls.append((injected_url, payload))
        return test_urls

    def _init_driver(self):
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        chrome_options.add_argument("--no-sandbox")
        chrome_options.add_argument("--disable-dev-shm-usage")
        chrome_options.add_argument("--disable-gpu")
        chrome_options.add_argument("--log-level=3")
        chrome_options.add_argument("--disable-extensions")
        chrome_options.add_argument("--disable-plugins")
        chrome_options.add_argument("--disable-images")
        # chrome_options.add_argument("--disable-javascript") # Removed as XSS requires JS

        chrome_options.add_argument("--disk-cache-size=0")
        chrome_options.page_load_strategy = 'eager'
        chrome_options.add_argument("--blink-settings=imagesEnabled=false")

        try:
            service = Service(ChromeDriverManager().install())
            driver = webdriver.Chrome(service=service, options=chrome_options)
            driver.set_page_load_timeout(10)
            driver.implicitly_wait(2)
            return driver
        except Exception as e:
            return None

    def _selenium_work(self, test_cases):
        results = []
        
        def log_sync(msg):
            event_manager.emit_sync("log", msg)

        log_sync(f"[Selenium] Initializing Chrome Driver...")
        self.driver = self._init_driver()
        
        if not self.driver:
            return [{"error": "Failed to start Selenium driver"}]

        log_sync(f"[Selenium] Driver Ready. Executing {len(test_cases)} tests...")

        try:
            for i, (target_url, payload) in enumerate(test_cases):
                display_payload = payload if len(payload) < 20 else payload[:17] + "..."
                log_sync(f"[Status] Selenium: {target_url} | Payload: {display_payload}")

                if self.driver is None:
                    self.driver = self._init_driver()
                    if not self.driver:
                        results.append({"error": "Driver failed to reinitialize"})
                        continue

                try:
                    # Disable webdriver detection
                    self.driver.execute_cdp_cmd('Page.addScriptToEvaluateOnNewDocument', {
                        'source': 'Object.defineProperty(navigator, "webdriver", {get: () => undefined})'
                    })

                    # 1. Load the page
                    try:
                        self.driver.get(target_url)
                    except TimeoutException:
                        log_sync(f"[Debug] Timeout loading {target_url}")
                        continue
                    except Exception as e:
                        log_sync(f"[Debug] Error loading {target_url}: {e}")
                        continue

                    # 2. Check for Alert (Reflected in URL)
                    try:
                        WebDriverWait(self.driver, 3).until(EC.alert_is_present())
                        alert = self.driver.switch_to.alert
                        alert_text = alert.text
                        if "LynxXSS" in alert_text:
                            alert.accept()
                            # Avoid duplicates
                            if not any(r['url'] == target_url and r['payload'] == payload for r in results):
                                results.append({
                                    "vuln_type": "DOM/Reflected XSS (Selenium Verified)",
                                    "details": f"Payload executed successfully in browser.\nAlert Text: {alert_text}",
                                    "severity": "P1",
                                    "remediation": "Sanitize input and use CSP.",
                                    "url": target_url,
                                    "payload": payload
                                })
                                log_sync(f"[bold green][Selenium] VULNERABILITY FOUND (URL): {target_url}[/bold green]")
                        else:
                            alert.accept()
                    except (TimeoutException, NoAlertPresentException):
                        pass
                    except UnexpectedAlertPresentException:
                        try:
                            self.driver.switch_to.alert.accept()
                        except:
                            pass

                except Exception as e:
                    log_sync(f"[Debug] Selenium Error on {target_url}: {str(e)}")
                    try:
                        self.driver.quit()
                    except:
                        pass
                    self.driver = None

        finally:
            self.cleanup()
        return results

    def cleanup(self):
        if self.driver:
            try:
                self.driver.quit()
            except Exception:
                pass
            self.driver = None
