import asyncio
import aiohttp
import urllib.parse
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field

from common import ScanPhase, event_manager, console
from katana_crawler import KatanaCrawler

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
        self.scanner_status = {}

    async def run(self):
        trace_config = aiohttp.TraceConfig()
        trace_config.on_request_start.append(on_request_start)
        trace_config.on_request_end.append(on_request_end)
        trace_config.on_request_exception.append(on_request_exception)

        # Optimization: Connection pooling and better timeouts to reduce failed requests
        connector = aiohttp.TCPConnector(limit=100, limit_per_host=10, ttl_dns_cache=300)
        timeout = aiohttp.ClientTimeout(total=60, connect=15, sock_read=30)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout, trace_configs=[trace_config]) as session:
            try:
                context = ScanContext(self.target, session, self.payloads_dir, ai_api_key=self.ai_api_key)

                context.current_phase = ScanPhase.PRE_ENGAGEMENT
                await event_manager.emit("log", "[Phase] Pre-Engagement: Initializing...")

                if self.crawl_enabled:
                    context.current_phase = ScanPhase.ACTIVE_MAPPING
                    await event_manager.emit("log", "[Phase] Active Mapping: Crawling target with Katana...")
                    crawler = KatanaCrawler(context)
                    await crawler.crawl(self.target)

                # Ensure target is always in crawled_urls if nothing else found
                if not context.crawled_urls:
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
                    self.scanner_status[scanner.name] = "Pending"
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
        self.scanner_status[scanner.name] = "Running"
        try:
            await event_manager.emit("log", f"[Debug] Starting scanner: {scanner.name}")
            async with self.semaphore:
                await scanner.run()
            self.scanner_status[scanner.name] = "Completed"
        except Exception as e:
            self.scanner_status[scanner.name] = "Failed"
            await event_manager.emit("log", f"[red][Error] Scanner {scanner.name} failed: {e}[/red]")
        finally:
            await event_manager.emit("log", f"[{scanner.name}] Scan complete.")
            # Emit status update event for dashboard
            await event_manager.emit("scanner_status", self.scanner_status)

    def cleanup_scanners(self):
        for scanner in self.initialized_scanners:
            if hasattr(scanner, 'cleanup'):
                try:
                    scanner.cleanup()
                except Exception:
                    pass
