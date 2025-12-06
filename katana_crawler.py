import asyncio
import os
import json
import shutil
import urllib.parse
from typing import Set
from common import event_manager, console

class KatanaCrawler:
    def __init__(self, context):
        self.context = context
        self.katana_path = shutil.which("katana")
        if not self.katana_path:
             # Try common go bin paths
             possible_paths = [
                 os.path.expanduser("~/go/bin/katana"),
                 "/usr/local/go/bin/katana",
                 "/go/bin/katana",
                 "katana"
             ]
             for path in possible_paths:
                 if os.path.exists(path):
                     self.katana_path = path
                     break
             if not self.katana_path:
                 self.katana_path = "katana" # Last resort, expect in PATH

    async def crawl(self, target: str):
        # Double check if binary is executable or exists if it's an absolute path
        if os.path.isabs(self.katana_path) and not os.path.exists(self.katana_path):
             await event_manager.emit("log", f"[red][Katana] Error: Binary not found at {self.katana_path}[/red]")
             return
        elif not shutil.which(self.katana_path):
             # If it's just "katana" and not in PATH
             if not os.path.isabs(self.katana_path):
                  await event_manager.emit("log", "[red][Katana] Error: katana binary not found in PATH. Please install projectdiscovery/katana.[/red]")
                  return

        await event_manager.emit("log", f"[Katana] Starting crawl for: {target}")

        # Prepare arguments
        args = [
            self.katana_path,
            "-u", target,
            "-jsonl",           # Output as JSONL
            "-silent",          # Only output findings
            "-d", "3",          # Depth 3
            "-jc",              # JS crawl
            "-kf", "all",       # Known files (robots, sitemap)
            "-c", "10",         # Concurrency
            "-timeout", "10",
            "-retry", "1",
            "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" # Static User-Agent for WAFs
        ]

        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )

            start_time = asyncio.get_event_loop().time()
            timeout_seconds = 300 # Increased timeout to 5 minutes

            buffer = b""
            chunk_size = 4096

            while True:
                if asyncio.get_event_loop().time() - start_time > timeout_seconds:
                    if process.returncode is None:
                        process.kill()
                        await event_manager.emit("log", "[red][Katana] Crawl timed out! Killing process.[/red]")
                    break

                try:
                    # Read chunk asynchronously with a small timeout to allow checking global timeout
                    try:
                        chunk = await asyncio.wait_for(process.stdout.read(chunk_size), timeout=1.0)
                    except asyncio.TimeoutError:
                        if process.returncode is not None:
                            # Process finished, read remaining
                            chunk = await process.stdout.read()
                            if not chunk:
                                break
                        else:
                            continue

                    if not chunk:
                        break

                    buffer += chunk

                    while b'\n' in buffer:
                        line_bytes, buffer = buffer.split(b'\n', 1)
                        line_text = line_bytes.decode(errors='ignore').strip()

                        if not line_text:
                            continue

                        try:
                            data = json.loads(line_text)
                            url = data.get("request", {}).get("endpoint")

                            if url:
                                # Debug: Log raw URL if needed
                                # await event_manager.emit("log", f"[Debug] Katana Raw: {url}")

                                # Clean up URL
                                parsed = urllib.parse.urlparse(url)
                                if parsed.scheme and parsed.netloc:
                                    # Filter out non-http(s)
                                    if parsed.scheme not in ["http", "https"]:
                                        continue

                                    # Filter out static assets
                                    ext = os.path.splitext(parsed.path)[1].lower()
                                    if ext in ['.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.pdf', '.zip', '.woff', '.woff2', '.ttf']:
                                        continue

                                    if url not in self.context.crawled_urls:
                                        self.context.crawled_urls.add(url)
                                        await event_manager.emit("log", f"[Katana] Found: {url}")
                        except json.JSONDecodeError:
                            pass
                        except Exception as e:
                            await event_manager.emit("log", f"[Debug] Katana parse error: {e}")

                except Exception as e:
                    await event_manager.emit("log", f"[red][Katana] Read error: {e}[/red]")
                    break

            await process.wait()

            stderr = await process.stderr.read()
            if stderr:
                 err_text = stderr.decode(errors='ignore')
                 # Filter out benign Katana info logs if needed, or check for specific errors
                 if "panic" in err_text or "fatal" in err_text.lower():
                      await event_manager.emit("log", f"[red][Katana] Critical Error: {err_text[:200]}[/red]")

            found_count = len(self.context.crawled_urls)
            await event_manager.emit("log", f"[Katana] Crawl finished. Found {found_count} URLs.")

            if found_count == 0:
                await event_manager.emit("log", "[yellow][Warning] Crawler found 0 URLs. WAF might be blocking requests or target is unreachable.[/yellow]")

        except Exception as e:
            await event_manager.emit("log", f"[red][Katana] Failed to execute: {e}[/red]")
        finally:
            if process and process.returncode is None:
                try:
                    process.kill()
                except:
                    pass
