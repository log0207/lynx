#!/usr/bin/env python3
"""
Lynx VAPT Tool - Automated Installer
=====================================
This installer handles all dependencies, checks for required tools,
and manages system package conflicts automatically.

Author: Logesh
Version: 1.0
"""

import os
import sys
import subprocess
import platform
import shutil
from pathlib import Path

# ANSI color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_banner():
    """Print the Lynx installer banner"""
    banner = f"""
{Colors.OKCYAN}+==============================================+
| _     __   __ _   _  __  __                |
|| |    \\ \\ / /| \\ | | \\ \\/ /                |
|| |     \\ V / |  \\| |  \\  /                 |
|| |___   | |  | |\\  |  /  \\                 |
||_____|  |_|  |_| \\_| /_/\\_\\                |
|                                            |
|        VAPT Tool - Installer v1.0         |
+==============================================+{Colors.ENDC}
"""
    print(banner)

def print_step(step_num, total_steps, message):
    """Print a formatted step message"""
    print(f"\n{Colors.BOLD}[{step_num}/{total_steps}]{Colors.ENDC} {Colors.OKBLUE}{message}{Colors.ENDC}")

def print_success(message):
    """Print a success message"""
    print(f"{Colors.OKGREEN}✓ {message}{Colors.ENDC}")

def print_warning(message):
    """Print a warning message"""
    print(f"{Colors.WARNING}⚠ {message}{Colors.ENDC}")

def print_error(message):
    """Print an error message"""
    print(f"{Colors.FAIL}✗ {message}{Colors.ENDC}")

def print_info(message):
    """Print an info message"""
    print(f"{Colors.OKCYAN}ℹ {message}{Colors.ENDC}")

def check_python_version():
    """Check if Python version is 3.8 or higher"""
    print_step(1, 7, "Checking Python version...")
    
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        print_error(f"Python 3.8+ required. Current version: {version.major}.{version.minor}.{version.micro}")
        return False
    
    print_success(f"Python {version.major}.{version.minor}.{version.micro} detected")
    return True

def check_pip():
    """Check if pip is installed and working"""
    print_step(2, 7, "Checking pip installation...")
    
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "--version"], 
                              capture_output=True, text=True, check=True)
        print_success(f"pip is installed: {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError:
        print_error("pip is not installed or not working")
        print_info("Installing pip...")
        try:
            subprocess.run([sys.executable, "-m", "ensurepip", "--default-pip"], check=True)
            print_success("pip installed successfully")
            return True
        except Exception as e:
            print_error(f"Failed to install pip: {e}")
            return False

def is_externally_managed():
    """Check if Python environment is externally managed (PEP 668)"""
    # Check for EXTERNALLY-MANAGED file
    stdlib_path = Path(sys.prefix) / "lib" / f"python{sys.version_info.major}.{sys.version_info.minor}"
    externally_managed = stdlib_path / "EXTERNALLY-MANAGED"
    
    return externally_managed.exists()

def install_dependencies():
    """Install Python dependencies from requirements.txt"""
    print_step(3, 7, "Installing Python dependencies...")
    
    requirements_file = Path(__file__).parent / "requirements.txt"
    
    if not requirements_file.exists():
        print_error("requirements.txt not found!")
        return False
    
    # Detect OS and externally managed environment
    os_type = platform.system()
    externally_managed = is_externally_managed()
    
    if externally_managed and os_type == "Linux":
        print_warning("Detected externally managed Python environment (PEP 668)")
        print_info("Using --break-system-packages flag to install dependencies")
        pip_args = [sys.executable, "-m", "pip", "install", "-r", str(requirements_file), "--break-system-packages"]
    else:
        pip_args = [sys.executable, "-m", "pip", "install", "-r", str(requirements_file)]
    
    try:
        print_info(f"Running: {' '.join(pip_args)}")
        result = subprocess.run(pip_args, check=True, capture_output=True, text=True)
        print_success("All Python dependencies installed successfully")
        
        # Show installed packages
        print_info("Installed packages:")
        for line in result.stdout.split('\n'):
            if 'Successfully installed' in line:
                print(f"  {line}")
        
        return True
    except subprocess.CalledProcessError as e:
        print_error("Failed to install dependencies")
        print_error(f"Error: {e.stderr}")
        
        # Suggest alternative installation methods
        print_warning("\nAlternative installation methods:")
        print_info("1. Create a virtual environment:")
        print(f"   python3 -m venv venv")
        print(f"   source venv/bin/activate  # On Windows: venv\\Scripts\\activate")
        print(f"   pip install -r requirements.txt")
        print_info("2. Use --user flag:")
        print(f"   pip install -r requirements.txt --user")
        print_info("3. Use --break-system-packages (Linux only):")
        print(f"   pip install -r requirements.txt --break-system-packages")
        
        return False

def verify_python_packages():
    """Verify that all required Python packages are installed"""
    print_step(4, 7, "Verifying Python packages...")
    
    required_packages = {
        'aiohttp': 'aiohttp',
        'selenium': 'selenium',
        'beautifulsoup4': 'bs4',
        'rich': 'rich',
        'google-generativeai': 'google.generativeai',
        'jinja2': 'jinja2',
        'webdriver-manager': 'webdriver_manager'
    }
    
    all_installed = True
    
    for package_name, import_name in required_packages.items():
        try:
            __import__(import_name)
            print_success(f"{package_name} is installed")
        except ImportError:
            print_error(f"{package_name} is NOT installed")
            all_installed = False
    
    return all_installed

def check_chrome():
    """Check if Google Chrome is installed"""
    print_step(5, 7, "Checking Google Chrome installation...")
    
    os_type = platform.system()
    chrome_paths = []
    
    if os_type == "Windows":
        chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe")
        ]
    elif os_type == "Darwin":  # macOS
        chrome_paths = [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
        ]
    else:  # Linux
        chrome_paths = [
            "/usr/bin/google-chrome",
            "/usr/bin/google-chrome-stable",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser"
        ]
    
    for path in chrome_paths:
        if os.path.exists(path):
            print_success(f"Google Chrome found at: {path}")
            return True
    
    # Try using 'which' command on Unix-like systems
    if os_type != "Windows":
        try:
            result = subprocess.run(["which", "google-chrome"], capture_output=True, text=True)
            if result.returncode == 0:
                print_success(f"Google Chrome found at: {result.stdout.strip()}")
                return True
        except:
            pass
    
    print_warning("Google Chrome not found")
    print_info("Chrome is required for XSS scanner (Selenium)")
    print_info("Download from: https://www.google.com/chrome/")
    print_info("Note: Lynx will still work, but XSS scanner will be disabled")
    
    return False

def check_katana():
    """Check if Katana crawler is installed"""
    print_step(6, 7, "Checking Katana crawler installation...")
    
    katana_path = shutil.which("katana")
    
    if katana_path:
        print_success(f"Katana found at: {katana_path}")
        
        # Check version
        try:
            result = subprocess.run(["katana", "-version"], capture_output=True, text=True)
            version_info = result.stdout.strip() or result.stderr.strip()
            print_info(f"Version: {version_info}")
        except:
            pass
        
        return True
    
    # Check common Go bin paths
    go_paths = [
        os.path.expanduser("~/go/bin/katana"),
        "/usr/local/go/bin/katana",
        "/go/bin/katana"
    ]
    
    for path in go_paths:
        if os.path.exists(path):
            print_success(f"Katana found at: {path}")
            return True
    
    print_warning("Katana not found")
    print_info("Katana is optional but recommended for advanced crawling")
    print_info("Install with: go install github.com/projectdiscovery/katana/cmd/katana@latest")
    print_info("Or download from: https://github.com/projectdiscovery/katana")
    print_info("Note: Lynx will still work without Katana (limited crawling)")
    
    return False

def run_verification_test():
    """Run a quick verification test to ensure Lynx can start"""
    print_step(7, 7, "Running verification test...")
    
    try:
        # Try importing main modules
        print_info("Testing core imports...")
        
        sys.path.insert(0, str(Path(__file__).parent))
        
        import common
        print_success("common.py imported successfully")
        
        import core
        print_success("core.py imported successfully")
        
        import ui
        print_success("ui.py imported successfully")
        
        import reporter
        print_success("reporter.py imported successfully")
        
        # Test scanner imports
        from scanners import get_all_scanners
        scanners = get_all_scanners()
        print_success(f"Loaded {len(scanners)} scanner modules")
        
        print_success("All core modules loaded successfully!")
        return True
        
    except Exception as e:
        print_error(f"Verification test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def print_summary(results):
    """Print installation summary"""
    print(f"\n{Colors.BOLD}{Colors.HEADER}{'='*50}{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}Installation Summary{Colors.ENDC}")
    print(f"{Colors.BOLD}{Colors.HEADER}{'='*50}{Colors.ENDC}\n")
    
    for step, status in results.items():
        icon = "✓" if status else "✗"
        color = Colors.OKGREEN if status else Colors.FAIL
        print(f"{color}{icon} {step}{Colors.ENDC}")
    
    all_passed = all(results.values())
    
    print(f"\n{Colors.BOLD}{'='*50}{Colors.ENDC}")
    
    if all_passed:
        print(f"\n{Colors.OKGREEN}{Colors.BOLD}🎉 Installation completed successfully!{Colors.ENDC}\n")
        print(f"{Colors.OKCYAN}You can now run Lynx with:{Colors.ENDC}")
        print(f"{Colors.BOLD}  python lynx.py{Colors.ENDC}")
        print(f"\n{Colors.OKCYAN}For help, run:{Colors.ENDC}")
        print(f"{Colors.BOLD}  python lynx.py --help{Colors.ENDC}\n")
    else:
        print(f"\n{Colors.WARNING}{Colors.BOLD}⚠ Installation completed with warnings{Colors.ENDC}\n")
        print(f"{Colors.OKCYAN}Lynx may still work with limited functionality.{Colors.ENDC}")
        print(f"{Colors.OKCYAN}Please review the warnings above and install missing components.{Colors.ENDC}\n")

def main():
    """Main installer function"""
    print_banner()
    
    print(f"{Colors.OKCYAN}This installer will set up Lynx VAPT Tool on your system.{Colors.ENDC}")
    print(f"{Colors.OKCYAN}It will install all required dependencies and verify the installation.{Colors.ENDC}\n")
    
    # Run installation steps
    results = {}
    
    # Step 1: Check Python version
    results["Python 3.8+"] = check_python_version()
    if not results["Python 3.8+"]:
        print_error("Cannot proceed without Python 3.8+")
        sys.exit(1)
    
    # Step 2: Check pip
    results["pip"] = check_pip()
    if not results["pip"]:
        print_error("Cannot proceed without pip")
        sys.exit(1)
    
    # Step 3: Install dependencies
    results["Python Dependencies"] = install_dependencies()
    
    # Step 4: Verify packages
    results["Package Verification"] = verify_python_packages()
    
    # Step 5: Check Chrome
    results["Google Chrome"] = check_chrome()
    
    # Step 6: Check Katana
    results["Katana Crawler"] = check_katana()
    
    # Step 7: Run verification test
    results["Verification Test"] = run_verification_test()
    
    # Print summary
    print_summary(results)
    
    # Exit code
    if results["Python Dependencies"] and results["Package Verification"] and results["Verification Test"]:
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Colors.WARNING}Installation cancelled by user{Colors.ENDC}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.FAIL}Unexpected error: {e}{Colors.ENDC}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
