import os
import asyncio
from enum import Enum
from typing import Dict, List, Callable, Any
from rich.console import Console

VERSION = "1.0 [BETA]"
AUTHORS = ["Logesh"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
]

console = Console()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_banner():
    clear_screen()
    console.print(r"""
+======================+
| _  __   ___   ___  __|
|| | \ \ / / \ | \ \/ /|
|| |  \ V /|  \| |\  / |
|| |___| | | |\  |/  \ |
||_____|_| |_| \_/_/\_\|
+======================+
""")
    console.print(f"[bold cyan]Lynx v{VERSION} - Advanced VAPT Automation Tool[/bold cyan]")
    console.print(f"[bold cyan]Authors: {', '.join(AUTHORS)}[/bold cyan]\n")

DEBUG_ENABLED = os.getenv("LYNX_DEBUG", "true").lower() == "true"
DEBUG_LOG_FILE = "debug.log"

def debug_log(message):
    if not DEBUG_ENABLED:
        return
    try:
        with open(DEBUG_LOG_FILE, "a", encoding="utf-8") as f:
            timestamp = asyncio.get_event_loop().time() if asyncio.get_event_loop().is_running() else 0
            f.write(f"[{timestamp:.2f}] {message}\n")
    except Exception:
        pass

class ScanPhase(Enum):
    PRE_ENGAGEMENT = "Pre-Engagement"
    RECONNAISSANCE = "Reconnaissance"
    ACTIVE_MAPPING = "Active Mapping"
    VULNERABILITY_SCANNING = "Vulnerability Scanning"
    EXPLOITATION = "Exploitation"
    REPORTING = "Reporting"

class TestingZone(Enum):
    ZONE_A = "Zone A: Input/Output Validation"
    ZONE_B = "Zone B: Authentication & Authorization"
    ZONE_C = "Zone C: Business Logic"
    ZONE_D = "Zone D: API Security"
    ZONE_E = "Zone E: Server Configuration"
    ZONE_F = "Zone F: Network/Infrastructure"
    ZONE_G = "Zone G: Data Protection"

class EventManager:
    def __init__(self):
        self.listeners: Dict[str, List[Callable]] = {}
        self.main_loop = None

    def set_loop(self, loop):
        self.main_loop = loop

    def subscribe(self, event_type: str, callback: Callable):
        if event_type not in self.listeners:
            self.listeners[event_type] = []
        self.listeners[event_type].append(callback)

    async def emit(self, event_type: str, data: Any):
        if DEBUG_ENABLED:
            if event_type == "log":
                debug_log(f"[LOG] {data}")
            elif event_type == "vulnerability":
                debug_log(f"[VULN] {data.get('type')} - {data.get('url')}")
            elif event_type == "net_request_error":
                debug_log(f"[NET_ERR] {data}")

        if event_type in self.listeners:
            for callback in self.listeners[event_type]:
                if asyncio.iscoroutinefunction(callback):
                    await callback(data)
                else:
                    callback(data)

    def emit_sync(self, event_type: str, data: Any):
        if DEBUG_ENABLED:
            if event_type == "log":
                debug_log(f"[LOG] {data}")
            elif event_type == "vulnerability":
                debug_log(f"[VULN] {data.get('type')} - {data.get('url')}")
            elif event_type == "net_request_error":
                debug_log(f"[NET_ERR] {data}")

        if event_type in self.listeners:
            for callback in self.listeners[event_type]:
                if asyncio.iscoroutinefunction(callback):
                    try:
                        loop = self.main_loop
                        if not loop:
                            # Fallback logic
                            try:
                                loop = asyncio.get_running_loop()
                            except RuntimeError:
                                loop = asyncio.get_event_loop()

                        if loop and loop.is_running():
                            asyncio.run_coroutine_threadsafe(callback(data), loop)
                        else:
                            # If no loop is running, we can't await a coroutine from sync context easily
                            # unless we run it in a new loop, but that's risky.
                            pass
                    except Exception as e:
                         pass
                else:
                    callback(data)

event_manager = EventManager()