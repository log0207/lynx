import os
import subprocess
from rich.prompt import Confirm
from common import console

def check_for_updates(repo_url="https://github.com/log0207/lynx", branch="main", force=False):
    """
    Checks for updates from the remote git repository.
    """
    console.print("[bold cyan]Checking for updates...[/bold cyan]")

    try:
        # Check if git is installed
        if subprocess.call(["git", "--version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
            console.print("[yellow]Git is not installed. Skipping update check.[/yellow]")
            return

        # Check if inside a git repo
        if subprocess.call(["git", "rev-parse", "--is-inside-work-tree"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
             console.print("[yellow]Auto-update unavailable: Not a git repository.[/yellow]")
             console.print("[dim]Please clone the repository using git to enable updates:\n  git clone https://github.com/riyapriya456/lynx-log[/dim]")
             return

        # Fetch latest changes
        console.print(f"[dim]Fetching updates from {branch}...[/dim]")
        subprocess.run(["git", "fetch", "origin", branch], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        # Get local and remote HEAD hashes
        local_hash = subprocess.check_output(["git", "rev-parse", "HEAD"]).decode().strip()
        remote_hash = subprocess.check_output(["git", "rev-parse", f"origin/{branch}"]).decode().strip()

        if local_hash != remote_hash:
            console.print(f"[bold green]Update available![/bold green] (Local: {local_hash[:7]} -> Remote: {remote_hash[:7]})")
            if force or Confirm.ask("Do you want to update now?"):
                console.print("[bold cyan]Updating...[/bold cyan]")
                try:
                    subprocess.run(["git", "pull", "origin", branch, "--rebase"], check=True)
                except subprocess.CalledProcessError:
                    console.print("[yellow]Rebase failed, trying normal pull...[/yellow]")
                    subprocess.run(["git", "pull", "origin", branch], check=True)

                console.print("[bold green]Update successful! Please restart the tool.[/bold green]")
                os._exit(0)
        else:
            console.print("[bold green]Lynx is up to date.[/bold green]\n")
            if force:
                 console.print("[dim]Forcing re-install/check could be implemented here if needed, but git says up to date.[/dim]")

    except subprocess.CalledProcessError as e:
        console.print(f"[red]Failed to check for updates: {e}[/red]")
    except Exception as e:
        console.print(f"[red]An error occurred during update check: {e}[/red]")
