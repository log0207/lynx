import asyncio
import aiohttp
import urllib.parse
import hashlib
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
        # Use payload for better deduplication, fallback to details if no payload
        unique_component = payload if payload else details
        unique_key = f"{vuln_type}|{target_url}|{unique_component}"
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
        """
        Generates various injection points for a given URL and payload.
        1. Injects into existing query parameters.
        2. Appends to path.
        3. Appends common parameters (q, id, search).
        """
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)
        
        # 1. Inject into existing parameters
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
        
        # 2. Append to path and common params (if no params or just to be thorough)
        # Note: Original code only did this if not params, but we might want to be thorough.
        # Keeping original logic for now to avoid explosion of requests, but slightly modified.
        if not params:
            if url.endswith('/'):
                yield f"{url}{payload}"
            else:
                yield f"{url}/{payload}"
            
            # Common params
            yield f"{url}?q={payload}"
            yield f"{url}?id={payload}"
            yield f"{url}?search={payload}"

    async def check_generic_payload(self, payload, url, signatures, vuln_type, severity, remediation):
        """
        Generic check: GET request to URL, check response text for signatures.
        """
        try:
            async with self.context.session.get(url) as response:
                text = await response.text()
                if any(sig in text for sig in signatures):
                    await self.emit_vulnerability(
                        vuln_type, 
                        f"PoC URL: {url}\nPayload: {payload}", 
                        severity, 
                        remediation, 
                        url=url, 
                        payload=payload
                    )
        except Exception:
            pass

    def cleanup(self):
        pass
