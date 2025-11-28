import asyncio
import argparse
import os
import json
import datetime
import time
from dataclasses import dataclass
from rich.live import Live
from rich.panel import Panel
from rich.prompt import Prompt
from rich.layout import Layout
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

from common import event_manager, print_banner, console
from core import ScanEngine
from reporter import Reporter
from scanners import get_all_scanners, SQLiScanner, SeleniumXSSScanner

class Dashboard:
    def __init__(self):
        self.logs = []
        self.vulns = []
        self.max_logs = 50
        self.current_phase = "Initializing"
        self.status_message = ""
        self.start_time = None
        self.total_scanners = 0
        self.completed_scanners = 0
        self.animation_frame = 0

        self.active_requests = 0
        self.total_requests = 0
        self.failed_requests = 0
        self.total_latency = 0
        self.request_times = []

        self.layout = Layout()
        self.layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body", ratio=1),
            Layout(name="network", size=3),
            Layout(name="footer", size=3)
        )
        self.layout["body"].split_row(
            Layout(name="logs", ratio=1),
            Layout(name="findings", ratio=1)
        )

    def set_scanner_count(self, count):
        self.total_scanners = count
        
    def start_timer(self):
        self.start_time = time.time()
        
    def get_elapsed_time(self):
        if not self.start_time:
            return 0
        return time.time() - self.start_time
        
    def net_request_start(self, url):
        self.active_requests += 1
        self.total_requests += 1

    def net_request_end(self, data):
        self.active_requests = max(0, self.active_requests - 1)

    def net_request_error(self, data):
        self.active_requests = max(0, self.active_requests - 1)
        self.failed_requests += 1

    def add_log(self, message):
        if "[Phase]" in message:
            self.current_phase = message.split("]")[1].strip()
        elif "[Status]" in message:
            pass
        
        if "] Scan complete" in message:
            self.completed_scanners += 1
        
        self.logs.append(message)
        if len(self.logs) > self.max_logs:
            self.logs.pop(0)

    def add_vuln(self, data):
        try:
            self.add_log(f"[Debug] Adding vulnerability to dashboard: {data.get('type')} - {data.get('url')}")
            self.vulns.append(data)
        except Exception as e:
            self.add_log(f"[red][Error] Failed to add vulnerability: {e}[/red]")

    def generate_layout(self):
        self.animation_frame = (self.animation_frame + 1) % 4
        spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        spinner = spinner_chars[self.animation_frame % len(spinner_chars)]
        
        status_color = "cyan"
        if "Vulnerability Scanning" in self.current_phase:
            status_color = "red"
        elif "Reporting" in self.current_phase:
            status_color = "green"
            
        header_content = f"[bold {status_color}]{spinner} {self.current_phase}[/bold {status_color}]"
        self.layout["header"].update(Panel(header_content, title="[bold white]Lynx v1.0 [BETA] - Active Scan[/bold white]", border_style=status_color))
        
        log_text = ""
        visible_logs = self.logs[-15:]
        for log in visible_logs:
            if "[Phase]" in log:
                log_text += f"[bold cyan]{log}[/bold cyan]\n"
            elif "[Error]" in log:
                log_text += f"[bold red]{log}[/bold red]\n"
            elif "[AI]" in log:
                log_text += f"[bold green]{log}[/bold green]\n"
            elif "[Selenium]" in log:
                 log_text += f"[bold magenta]{log}[/bold magenta]\n"
            else:
                log_text += f"{log}\n"
        
        self.layout["logs"].update(Panel(log_text, title="📜 Execution Logs (Last 15)", border_style="blue"))
        
        vuln_lines = []
        for v in self.vulns[-10:]: 
            color = "white"
            icon = "🔹"
            if v['severity'] == "P1": 
                color = "red"
                icon = "💥"
            elif v['severity'] == "P2": 
                color = "orange1"
                icon = "🔥"
            elif v['severity'] == "P3": 
                color = "yellow"
                icon = "⚠️"
            elif v['severity'] == "P4": 
                color = "cyan"
                icon = "ℹ️"
            
            vuln_str = f"[{color}]{icon} {v['type']}[/{color}]"
            if v.get('url'):
                url = v['url']
                if len(url) > 40: url = url[:37] + "..."
                vuln_str += f"\n  [dim]{url}[/dim]"
            vuln_lines.append(vuln_str)
            
        vuln_text = "\n\n".join(vuln_lines) if vuln_lines else "[dim]No vulnerabilities detected yet...[/dim]"
        self.layout["findings"].update(Panel(vuln_text, title="🔥 Detected Vulnerabilities", border_style="red"))

        net_text = f"Active Requests: [bold cyan]{self.active_requests}[/bold cyan] | Total Requests: [bold white]{self.total_requests}[/bold white] | Failed: [bold red]{self.failed_requests}[/bold red]"
        self.layout["network"].update(Panel(net_text, title="📡 Network Monitor", border_style="magenta"))
        
        p1 = sum(1 for v in self.vulns if v['severity'] == 'P1')
        p2 = sum(1 for v in self.vulns if v['severity'] == 'P2')
        p3 = sum(1 for v in self.vulns if v['severity'] == 'P3')
        p4 = sum(1 for v in self.vulns if v['severity'] == 'P4')
        
        stats = f"[bold red]P1: {p1}[/bold red] | [bold orange1]P2: {p2}[/bold orange1] | [bold yellow]P3: {p3}[/bold yellow] | [bold cyan]P4: {p4}[/bold cyan] | [bold white]Total: {len(self.vulns)}[/bold white]"
        self.layout["footer"].update(Panel(stats, title="Live Statistics"))
        
        return self.layout


dashboard = Dashboard()

async def log_handler(message):
    dashboard.add_log(message)

async def vuln_handler(data):
    dashboard.add_log(f"[Debug] Received vulnerability event: {data.get('type')} - {data.get('url')}")
    dashboard.add_vuln(data)

async def net_start_handler(url):
    dashboard.net_request_start(url)

async def net_end_handler(data):
    dashboard.net_request_end(data)

async def net_error_handler(data):
    dashboard.net_request_error(data)

@dataclass
class MockContext:
    target: str
    findings: list
    ai_summary: str = None

async def main_async():
    parser = argparse.ArgumentParser(description="Lynx v1.0 - VAPT Tool")
    parser.add_argument("-u", "--url", help="Target URL")
    parser.add_argument("--quick", action="store_true", help="Run a quick scan (no crawl)")
    args = parser.parse_args()

    target = args.url
    selected_scanners = get_all_scanners()
    crawl_enabled = True

    print_banner()

    if not target:
        console.print(Panel.fit("[bold cyan]Interactive Mode[/bold cyan]"))
        console.print("1. Comprehensive VAPT Scan (All Zones + Crawl)")
        console.print("2. Quick Scan (No Crawl, Fast Checks)")
        console.print("3. Custom: SQL Injection Only")
        console.print("4. Selenium XSS Scan (Dynamic)")
        console.print("5. Full Scan with AI Analysis")
        
        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5"], default="1")
        
        if choice == "1":
            selected_scanners = get_all_scanners()
            crawl_enabled = True
        elif choice == "2":
            selected_scanners = get_all_scanners()
            crawl_enabled = False
        elif choice == "3":
            selected_scanners = [SQLiScanner]
            crawl_enabled = False
        elif choice == "4":
            selected_scanners = [SeleniumXSSScanner]
            crawl_enabled = True
        elif choice == "5":
            selected_scanners = get_all_scanners()
            crawl_enabled = True
            os.environ["GEMINI_API_KEY"] = "AIzaSyAbrr1qN2qlSOGgBcYTdj-UwNZuzlAUpmI"
            
        target = Prompt.ask("[cyan]Enter target URL[/cyan]")

    if args.quick:
        crawl_enabled = False

    event_manager.subscribe("log", log_handler)
    event_manager.subscribe("vulnerability", vuln_handler)
    event_manager.subscribe("net_request_start", net_start_handler)
    event_manager.subscribe("net_request_end", net_end_handler)
    event_manager.subscribe("net_request_error", net_error_handler)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    payloads_dir = os.path.join(base_dir, "payloads") 
    
    engine = ScanEngine(target, selected_scanners, payloads_dir, crawl=crawl_enabled, ai_api_key=os.getenv("GEMINI_API_KEY"))
    
    dashboard.set_scanner_count(len(selected_scanners))
    dashboard.start_timer()

    with Live(dashboard.generate_layout(), refresh_per_second=4, screen=True) as live:
        task = asyncio.create_task(engine.run())
        
        try:
            while not task.done():
                live.update(dashboard.generate_layout())
                await asyncio.sleep(0.25)
            await task
        except asyncio.CancelledError:
            pass
        except Exception as e:
            console.print(f"[bold red]Fatal Error during scan:[/bold red] {e}")
            import traceback
            traceback.print_exc()
        finally:
            live.update(dashboard.generate_layout())
        
    console.print("\n[bold]Scan Summary:[/bold]")
    if dashboard.vulns:
        p1 = sum(1 for v in dashboard.vulns if v['severity'] == 'P1')
        p2 = sum(1 for v in dashboard.vulns if v['severity'] == 'P2')
        p3 = sum(1 for v in dashboard.vulns if v['severity'] == 'P3')
        p4 = sum(1 for v in dashboard.vulns if v['severity'] == 'P4')
        
        console.print(f"[bold red]Found {len(dashboard.vulns)} vulnerabilities![/bold red]")
        console.print(f"  [red]P1 (Critical): {p1}[/red]")
        console.print(f"  [orange1]P2 (High): {p2}[/orange1]")
        console.print(f"  [yellow]P3 (Medium): {p3}[/yellow]")
        console.print(f"  [cyan]P4 (Low): {p4}[/cyan]")
        
        console.print("\n[bold]Findings:[/bold]")
        for v in dashboard.vulns:
            console.print(f"- [{v['severity']}] {v['type']} ({v.get('zone', 'Unknown')}): {v['url']}")
            
        findings_data = {
            "scan_id": f"LYNX-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "target": target,
            "mode": "active",
            "timestamp": datetime.datetime.now().isoformat(),
            "summary": {
                "total": len(dashboard.vulns),
                "P1": p1,
                "P2": p2,
                "P3": p3,
                "P4": p4
            },
            "findings": dashboard.vulns
        }
        
        with open("findings.json", "w", encoding="utf-8") as f:
            json.dump(findings_data, f, indent=2)
        console.print(f"\n[bold cyan]Findings saved to: {os.path.abspath('findings.json')}[/bold cyan]")
            
        mock_context = MockContext(target, dashboard.vulns, ai_summary=None)
        reporter = Reporter(mock_context)
        report_file = reporter.generate_report()
        
        if report_file:
            console.print(f"[bold green]Report saved to: {os.path.abspath(report_file)}[/bold green]")
            try:
                if os.path.exists("findings.json"):
                    os.remove("findings.json")
                    console.print("[dim]findings.json removed successfully.[/dim]")
            except Exception as e:
                console.print(f"[dim]Could not remove findings.json: {e}[/dim]")
    else:
        console.print("[bold green]No vulnerabilities found.[/bold green]")

    if not task.cancelled():
        console.print("\n[dim]Press Enter to exit...[/dim]")
        try:
            await asyncio.get_event_loop().run_in_executor(None, input)
        except:
            pass

def main():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        task = loop.create_task(main_async())
        loop.run_until_complete(task)
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan aborted by user. Cleaning up...[/bold red]")
        for t in asyncio.all_tasks(loop):
            t.cancel()
        loop.run_until_complete(asyncio.gather(*asyncio.all_tasks(loop), return_exceptions=True))
        loop.close()
        console.print("[bold green]Cleanup completed. Exiting...[/bold green]")
        os._exit(0)
    except Exception as e:
        console.print(f"\n[bold red]Fatal Error: {e}[/bold red]")
        os._exit(1)

if __name__ == "__main__":
    main()