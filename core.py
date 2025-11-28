import asyncio
import aiohttp
import re
import urllib.parse
import socket
import json
import shutil
import hashlib
import os
import html
import time
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Callable, Optional
from dataclasses import dataclass, field
from bs4 import BeautifulSoup

from common import ScanPhase, TestingZone, event_manager, console

@dataclass
class ScanContext:
    target: str
    session: aiohttp.ClientSession
    payloads_dir: str
    crawled_urls: set = field(default_factory=set)
    config: Dict[str, Any] = field(default_factory=dict)
    current_phase: ScanPhase = ScanPhase.PRE_ENGAGEMENT
    findings: List[Dict] = field(default_factory=list)
    seen_vulns: set = field(default_factory=set)
    ai_api_key: Optional[str] = None
    ai_summary: Optional[str] = None
    loop: asyncio.AbstractEventLoop = field(default_factory=asyncio.get_event_loop)

class SitemapParser:
    def __init__(self, context: ScanContext):
        self.context = context

    async def parse(self):
        parsed = urllib.parse.urlparse(self.context.target)
        sitemap_url = f"{parsed.scheme}://{parsed.netloc}/sitemap.xml"
        try:
            async with self.context.session.get(sitemap_url) as response:
                if response.status == 200:
                    xml_content = await response.text()
                    root = ET.fromstring(xml_content)
                    ns = {'ns': 'http://www.sitemaps.org/schemas/sitemap/0.9'}
                    urls = root.findall('.//ns:loc', ns)
                    for url_elem in urls:
                        url = url_elem.text
                        if url:
                            self.context.crawled_urls.add(url)
                            await event_manager.emit("log", f"[Sitemap] Found: {url}")
        except Exception:
            pass

class JSAnalyzer:
    def __init__(self, context: ScanContext):
        self.context = context

    async def analyze(self, js_url: str):
        try:
            async with self.context.session.get(js_url) as response:
                if response.status == 200:
                    js_content = await response.text()
                    api_patterns = [
                        r'["\'](/api/[^"\'\'\s]+)["\']',
                        r'["\'](/v\d+/[^"\'\'\s]+)["\']',
                        r'["\']([^"\'\'\s]*\.json)["\']',
                    ]
                    for pattern in api_patterns:
                        matches = re.findall(pattern, js_content)
                        for match in matches:
                            full_url = urllib.parse.urljoin(self.context.target, match)
                            if full_url not in self.context.crawled_urls:
                                self.context.crawled_urls.add(full_url)
                                await event_manager.emit("log", f"[JSAnalyzer] Found endpoint: {full_url}")

                    sinks = {
                        "eval(": "Usage of eval() is dangerous and can lead to XSS/RCE.",
                        "innerHTML": "Unsafe assignment to innerHTML can lead to DOM XSS.",
                        "document.write(": "document.write() with user input is a sink for DOM XSS.",
                        "localStorage": "Sensitive data in localStorage can be stolen via XSS.",
                        "sessionStorage": "Sensitive data in sessionStorage can be stolen via XSS."
                    }
                    for sink, desc in sinks.items():
                        if sink in js_content:
                            await self._emit_js_vuln("Potential DOM XSS / Insecure JS", f"Found '{sink}' in {js_url}", desc)
        except Exception:
            pass

    async def _emit_js_vuln(self, type, details, remediation):
        data = {
            "type": type,
            "url": self.context.target, 
            "details": details,
            "severity": "P3",
            "scanner": "JSAnalyzer",
            "zone": TestingZone.ZONE_B.value,
            "remediation": remediation
        }
        unique_key = f"{type}|{self.context.target}|{details[:50]}"
        vuln_hash = hashlib.md5(unique_key.encode()).hexdigest()
        if vuln_hash not in self.context.seen_vulns:
            self.context.seen_vulns.add(vuln_hash)
            await event_manager.emit("vulnerability", data)
            await event_manager.emit("log", f"[yellow][P3] {type} found in JS![/yellow]")

class Crawler:
    def __init__(self, context: ScanContext, concurrency: int = 25):
        self.context = context
        self.visited = set()
        self.max_depth = 3
        self.concurrency = concurrency
        self.js_analyzer = JSAnalyzer(context)

    async def crawl(self, start_url: str):
        queue = asyncio.Queue()
        queue.put_nowait((start_url, 0))
        
        workers = [asyncio.create_task(self.worker(queue)) for _ in range(self.concurrency)]
        
        await queue.join()
        
        for w in workers:
            w.cancel()

    async def worker(self, queue):
        target_netloc = urllib.parse.urlparse(self.context.target).netloc.replace("www.", "")
        while True:
            try:
                url, depth = await queue.get()
                
                if depth > self.max_depth or url in self.visited:
                    queue.task_done()
                    continue
                
                parsed = urllib.parse.urlparse(url)
                ext = os.path.splitext(parsed.path)[1].lower()
                if ext in ['.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.pdf', '.zip']:
                    queue.task_done()
                    continue

                self.visited.add(url)
                self.context.crawled_urls.add(url)
                await event_manager.emit("log", f"[Crawler] Visiting: {url}")

                try:
                    crawler_timeout = aiohttp.ClientTimeout(total=10)
                    async with self.context.session.get(url, allow_redirects=True, timeout=crawler_timeout) as response:
                        if response.status != 200:
                            await event_manager.emit("log", f"[Debug] Crawler: {url} returned {response.status}")
                            queue.task_done()
                            continue
                        
                        ctype = response.headers.get("Content-Type", "").lower()
                        if "image" in ctype or "video" in ctype or "application/zip" in ctype:
                             queue.task_done()
                             continue
                        
                        if "javascript" in ctype or url.endswith(".js"):
                            await self.js_analyzer.analyze(url)

                        html_content = await response.text()
                        soup = BeautifulSoup(html_content, 'html.parser')
                        
                        tags = {'a': 'href', 'link': 'href', 'script': 'src', 'img': 'src', 'iframe': 'src', 'form': 'action'}
                        found_links = set()
                        
                        for tag, attr in tags.items():
                            for element in soup.find_all(tag):
                                link = element.get(attr)
                                if link:
                                    found_links.add(link)

                        for link in found_links:
                            full_url = urllib.parse.urljoin(url, link)
                            parsed_full = urllib.parse.urlparse(full_url)
                            link_netloc = parsed_full.netloc.replace("www.", "")
                            
                            if link_netloc == target_netloc:
                                if full_url not in self.visited:
                                    queue.put_nowait((full_url, depth + 1))

                except Exception as e:
                    await event_manager.emit("log", f"[Crawler] Error crawling {url}: {e}")
                
                queue.task_done()
            except asyncio.CancelledError:
                return
            except Exception:
                queue.task_done()

async def on_request_start(session, trace_config_ctx, params):
    await event_manager.emit("net_request_start", params.url)

async def on_request_end(session, trace_config_ctx, params):
    await event_manager.emit("net_request_end", {"url": params.url, "status": params.response.status})

async def on_request_exception(session, trace_config_ctx, params):
    await event_manager.emit("net_request_error", {"url": params.url, "error": str(params.exception)})

class ScanEngine:
    def __init__(self, target: str, scanners: List, payloads_dir: str, crawl: bool = False, ai_api_key: str = None):
        self.target = target
        self.scanners = scanners
        self.payloads_dir = payloads_dir
        self.crawl_enabled = crawl
        self.ai_api_key = ai_api_key
        self.semaphore = asyncio.Semaphore(15)
        self.initialized_scanners = []

    async def run(self):
        trace_config = aiohttp.TraceConfig()
        trace_config.on_request_start.append(on_request_start)
        trace_config.on_request_end.append(on_request_end)
        trace_config.on_request_exception.append(on_request_exception)

        timeout = aiohttp.ClientTimeout(total=20)
        async with aiohttp.ClientSession(timeout=timeout, trace_configs=[trace_config]) as session:
            try:
                context = ScanContext(self.target, session, self.payloads_dir, ai_api_key=self.ai_api_key)

                context.current_phase = ScanPhase.PRE_ENGAGEMENT
                await event_manager.emit("log", "[Phase] Pre-Engagement: Initializing...")

                sitemap_parser = SitemapParser(context)
                await sitemap_parser.parse()

                if self.crawl_enabled:
                    context.current_phase = ScanPhase.ACTIVE_MAPPING
                    await event_manager.emit("log", "[Phase] Active Mapping: Crawling target...")
                    crawler = Crawler(context, concurrency=15)
                    await crawler.crawl(self.target)
                else:
                    context.crawled_urls.add(self.target)

                await event_manager.emit("log", "[Phase] Analysis: Identifying injection points...")

                candidates = []
                if context.crawled_urls:
                    for url in context.crawled_urls:
                        if "?" in url:
                            candidates.append(url)

                if not candidates and "?" in context.target:
                    candidates.append(context.target)

                if candidates:
                    await event_manager.emit("log", f"[Analysis] Found {len(candidates)} URLs with parameters for injection.")
                else:
                    await event_manager.emit("log", "[Analysis] No parameters found in crawled URLs. Scanners will attempt to inject into paths/headers.")

                await event_manager.emit("log", f"[Phase] Vulnerability Scanning: Launching {len(self.scanners)} Modules...")

                tasks = []
                for scanner_cls in self.scanners:
                    scanner = scanner_cls(context)
                    self.initialized_scanners.append(scanner)
                    tasks.append(self.run_scanner_wrapper(scanner))

                if not tasks:
                    await event_manager.emit("log", "No scanners registered.")
                    return

                await asyncio.gather(*tasks)

                context.current_phase = ScanPhase.REPORTING

                if self.ai_api_key and context.findings:
                    try:
                        from ai_engine import AIEngine
                        ai_engine = AIEngine(self.ai_api_key)
                        await event_manager.emit("log", "[AI] Generating Executive Summary...")
                        context.ai_summary = await ai_engine.generate_executive_summary(context.findings)
                    except Exception as e:
                        await event_manager.emit("log", f"[AI] Failed to generate summary: {e}")

                await event_manager.emit("log", "All scans completed.")
            finally:
                self.cleanup_scanners()

    async def run_scanner_wrapper(self, scanner):
        try:
            await event_manager.emit("log", f"[Debug] Starting scanner: {scanner.name}")
            async with self.semaphore:
                await scanner.run()
        except Exception as e:
            await event_manager.emit("log", f"[red][Error] Scanner {scanner.name} failed: {e}[/red]")
        finally:
            await event_manager.emit("log", f"[{scanner.name}] Scan complete.")

    def cleanup_scanners(self):
        for scanner in self.initialized_scanners:
            if hasattr(scanner, 'cleanup'):
                try:
                    scanner.cleanup()
                except Exception:
                    pass