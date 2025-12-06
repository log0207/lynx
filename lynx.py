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
from updater import check_for_updates
from ui import dashboard

async def log_handler(message):
    dashboard.add_log(message)

async def status_handler(data):
    # Data is a dict of scanner_name: status
    pass # Dashboard doesn't natively render this dict yet, we can add it to logs or specialized view if needed.

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
    parser.add_argument("--update", action="store_true", help="Check for updates")
    parser.add_argument("-s", "--scanner", help="Specific scanner to run (xss, sqli, full)", default="full")
    args = parser.parse_args()

    if args.update:
        check_for_updates(force=True)
        return

    target = args.url
    
    # Select scanners based on argument
    if args.scanner.lower() == "xss":
        selected_scanners = [SeleniumXSSScanner]
    elif args.scanner.lower() == "sqli":
        selected_scanners = [SQLiScanner]
    else:
        selected_scanners = get_all_scanners()
    
    crawl_enabled = True
    crawl_enabled = True

    print_banner()

    if not target:
        console.print(Panel.fit("[bold cyan]Interactive Mode[/bold cyan]"))
        console.print("1. Comprehensive VAPT Scan (All Zones + Crawl)")
        console.print("2. Quick Scan (No Crawl, Fast Checks)")
        console.print("3. Custom: SQL Injection Only")
        console.print("4. Selenium XSS Scan (Dynamic)")
        console.print("5. Full Scan with AI Analysis")
        console.print("6. Update Tool")

        choice = Prompt.ask("Select an option", choices=["1", "2", "3", "4", "5", "6"], default="1")

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
        elif choice == "6":
            check_for_updates(force=True)
            os._exit(0)

        target = Prompt.ask("[cyan]Enter target URL[/cyan]")

    if args.quick:
        crawl_enabled = False

    event_manager.subscribe("log", log_handler)
    event_manager.subscribe("vulnerability", vuln_handler)
    event_manager.subscribe("net_request_start", net_start_handler)
    event_manager.subscribe("net_request_end", net_end_handler)
    event_manager.subscribe("net_request_error", net_error_handler)
    event_manager.subscribe("scanner_status", status_handler)

    base_dir = os.path.dirname(os.path.abspath(__file__))
    payloads_dir = os.path.join(base_dir, "payloads")

    engine = ScanEngine(target, selected_scanners, payloads_dir, crawl=crawl_enabled, ai_api_key=os.getenv("GEMINI_API_KEY"))

    dashboard.set_scanner_count(len(selected_scanners))
    dashboard.start_timer()

    with Live(dashboard.generate_layout(), refresh_per_second=10, screen=True) as live:
        task = asyncio.create_task(engine.run())

        try:
            while not task.done():
                live.update(dashboard.generate_layout())
                await asyncio.sleep(0.1)
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

    if engine.scanner_status:
        console.print("\n[bold cyan]Module Execution Status:[/bold cyan]")
        for name, status in engine.scanner_status.items():
            color = "green" if status == "Completed" else "red" if status == "Failed" else "yellow"
            console.print(f"- {name}: [{color}]{status}[/{color}]")

    if dashboard.vulns:
        p1 = sum(1 for v in dashboard.vulns if v['severity'] == 'P1')
        p2 = sum(1 for v in dashboard.vulns if v['severity'] == 'P2')
        p3 = sum(1 for v in dashboard.vulns if v['severity'] == 'P3')
        p4 = sum(1 for v in dashboard.vulns if v['severity'] == 'P4')

        console.print(f"\n[bold red]Found {len(dashboard.vulns)} vulnerabilities![/bold red]")
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
        if any(s == "Failed" for s in engine.scanner_status.values()):
             console.print("[bold red]Scan completed with errors. No vulnerabilities found in successful modules.[/bold red]")
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
        import sys
        if "--update" not in sys.argv:
             check_for_updates()

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        event_manager.set_loop(loop)

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