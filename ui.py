import time
from rich.layout import Layout
from rich.panel import Panel
from rich.console import Console

console = Console()

class Dashboard:
    def __init__(self):
        self.logs = []
        self.vulns = []
        self.max_logs = 50
        self.current_phase = "Initializing"
        self.current_action = "Ready"
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
        if len(message) > 200:
            message = message[:197] + "..."
        if "[Phase]" in message:
            self.current_phase = message.split("]")[1].strip()
        elif "[Status]" in message:
            self.current_action = message.split("]")[1].strip()

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
        content = f"{stats}\n[dim]{self.current_action}[/dim]"
        self.layout["footer"].update(Panel(content, title="Live Statistics"))

        return self.layout

dashboard = Dashboard()
