import asyncio
import os
import urllib.parse
import hashlib
from bs4 import BeautifulSoup
from .base import BaseScanner
from common import TestingZone

class SQLiScanner(BaseScanner):
    def __init__(self, context):
        super().__init__(context)
        self.zone = TestingZone.ZONE_A
        self.scanned_forms = set()
        self.sql_errors = ["SQL syntax", "mysql_fetch", "syntax error", "ORA-", "PostgreSQL", "SQLite/JDBCDriver"]

    async def run(self):
        await event_manager.emit("log", f"[{self.name}] Starting advanced scan on {len(self.context.crawled_urls)} URLs...")
        
        # Load payloads
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
            # GET Injection
            for payload in error_payloads:
                for target_url in self.generate_injection_points(url, payload):
                    tasks.append(self.check_error_based(payload, target_url))
            
            for payload in time_payloads:
                for target_url in self.generate_injection_points(url, payload):
                    tasks.append(self.check_time_based(payload, target_url))
            
            # Form Injection
            tasks.append(self.scan_forms(url, error_payloads, [], time_payloads))

        # Run in chunks to avoid overwhelming
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
        if not url: return
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
        return any(err in text for err in self.sql_errors)
