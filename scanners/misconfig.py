import asyncio
import urllib.parse
from bs4 import BeautifulSoup
from .base import BaseScanner
from common import TestingZone, event_manager

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
