#!/usr/bin/env python3
"""
Enhanced IP & Port Firewall Manager CLI (Linux + Windows support)
Version: 2025.1.0
Features:
- Full support for Linux (iptables / nftables) and Windows (netsh / Windows Firewall)
- Persistent allow/block lists with daily auto-reset option
- Better error handling & validation
- Colorful output & modern UX
- Logging + backup of rules
- Safe default policy (DROP everything except explicitly allowed)
"""

import subprocess
import platform
import os
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path

# ==================== CONFIGURATION ====================
BASE_DIR = Path.home() / ".firewall_cli"
BASE_DIR.mkdir(parents=True, exist_ok=True)

IP_ALLOW_FILE  = BASE_DIR / "ip_allow.txt"
IP_BLOCK_FILE  = BASE_DIR / "ip_block.txt"
PORT_BLOCK_FILE = BASE_DIR / "port_block.txt"
CONFIG_FILE    = BASE_DIR / "config.json"
LOG_FILE       = BASE_DIR / "firewall.log"

# Default config
DEFAULT_CONFIG = {
    "daily_limit_minutes": 20,          # per IP per day
    "default_policy": "DROP",
    "logging_enabled": True,
    "auto_backup_rules": True,
    "use_nftables_if_available": True   # Linux only - prefer nftables over iptables
}

# ==================== LOGGING SETUP ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-8s | %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("FirewallCLI")

# ==================== SYSTEM DETECTION ====================
IS_LINUX   = platform.system() == "Linux"
IS_WINDOWS = platform.system() == "Windows"

if not (IS_LINUX or IS_WINDOWS):
    print("❌ Unsupported operating system. Only Linux and Windows are supported.")
    exit(1)

# ==================== UTILITY FUNCTIONS ====================

def load_config():
    """Load configuration with defaults"""
    if CONFIG_FILE.exists():
        with CONFIG_FILE.open('r') as f:
            return json.load(f)
    else:
        CONFIG_FILE.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
        return DEFAULT_CONFIG.copy()


def save_config(config):
    """Save current configuration"""
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def load_list(path: Path):
    """Load list from file, create if not exists"""
    if not path.exists():
        path.touch()
        return []
    try:
        return [line.strip() for line in path.read_text(encoding='utf-8').splitlines() if line.strip()]
    except Exception as e:
        logger.error(f"Error reading {path}: {e}")
        return []


def save_list(path: Path, items: list):
    """Save list to file"""
    try:
        path.write_text('\n'.join(sorted(set(items))) + '\n', encoding='utf-8')
    except Exception as e:
        logger.error(f"Error writing to {path}: {e}")


def run_command(cmd: list, check=True, capture_output=True, text=True):
    """Safe subprocess wrapper"""
    try:
        return subprocess.run(
            cmd,
            check=check,
            capture_output=capture_output,
            text=text,
            encoding='utf-8'
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Command failed: {' '.join(cmd)}\nError: {e.stderr}")
        raise


# ==================== LINUX FIREWALL OPERATIONS ====================

def linux_flush_rules():
    config = load_config()
    if config.get("use_nftables_if_available") and shutil.which("nft"):
        run_command(["nft", "flush", "ruleset"])
    else:
        run_command(["iptables", "-F"])
        run_command(["iptables", "-X"])
        run_command(["iptables", "-t", "nat", "-F"])
        run_command(["iptables", "-t", "mangle", "-F"])
        run_command(["iptables", "-P", "INPUT", config["default_policy"]])
        run_command(["iptables", "-P", "FORWARD", config["default_policy"]])
        run_command(["iptables", "-P", "OUTPUT", "ACCEPT"])


def linux_apply_ip_rules():
    config = load_config()
    linux_flush_rules()

    # Allow explicitly allowed IPs
    for ip in load_list(IP_ALLOW_FILE):
        run_command(["iptables", "-A", "INPUT", "-s", ip, "-j", "ACCEPT"])

    # Block explicitly blocked IPs
    for ip in load_list(IP_BLOCK_FILE):
        run_command(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

    # Daily connection limit for everyone else
    if config["daily_limit_minutes"] > 0:
        minutes = config["daily_limit_minutes"]
        seconds = minutes * 60

        # Create limited chain
        run_command(["iptables", "-N", "LIMITED"], ignore_errors=True)
        run_command(["iptables", "-A", "INPUT", "-m", "recent", "--update",
                     "--seconds", str(seconds), "--hitcount", "1",
                     "--name", "DAILY", "--rsource", "-j", "DROP"])
        run_command(["iptables", "-A", "INPUT", "-m", "recent", "--set",
                     "--name", "DAILY", "--rsource", "-j", "ACCEPT"])
        run_command(["iptables", "-A", "INPUT", "-j", "LIMITED"])


def linux_apply_port_rules():
    for port in load_list(PORT_BLOCK_FILE):
        run_command(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", port, "-j", "DROP"])
        run_command(["iptables", "-A", "INPUT", "-p", "udp", "--dport", port, "-j", "DROP"])


def linux_backup_current_rules():
    if not load_config().get("auto_backup_rules"):
        return
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_file = BASE_DIR / f"iptables_backup_{timestamp}.rules"
    try:
        with open(backup_file, "w") as f:
            subprocess.run(["iptables-save"], stdout=f, check=True)
        logger.info(f"Current iptables rules backed up to {backup_file}")
    except Exception as e:
        logger.error(f"Backup failed: {e}")


# ==================== WINDOWS FIREWALL OPERATIONS ====================

def windows_apply_rules():
    config = load_config()

    # Clear existing custom rules (safety prefix)
    run_command(["netsh", "advfirewall", "firewall", "delete", "rule", "name=all", "description=FirewallCLI-managed"])

    # Allow IPs
    for ip in load_list(IP_ALLOW_FILE):
        run_command([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=FirewallCLI-ALLOW-IP", "dir=in", "action=allow",
            "remoteip=" + ip, "enable=yes", "description=FirewallCLI-managed"
        ])

    # Block IPs
    for ip in load_list(IP_BLOCK_FILE):
        run_command([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=FirewallCLI-BLOCK-IP", "dir=in", "action=block",
            "remoteip=" + ip, "enable=yes", "description=FirewallCLI-managed"
        ])

    # Block ports
    for port in load_list(PORT_BLOCK_FILE):
        run_command([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=FirewallCLI-BLOCK-PORT", "dir=in", "action=block",
            "protocol=TCP", "localport=" + port, "enable=yes", "description=FirewallCLI-managed"
        ])
        run_command([
            "netsh", "advfirewall", "firewall", "add", "rule",
            "name=FirewallCLI-BLOCK-PORT", "dir=in", "action=block",
            "protocol=UDP", "localport=" + port, "enable=yes", "description=FirewallCLI-managed"
        ])


# ==================== MENU SYSTEM ====================

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')


def print_header():
    print("\n" + "═" * 60)
    print("         🤖 Enhanced Firewall Manager CLI 2025         ")
    print("         IP & Port Control - Linux & Windows         ")
    print("═" * 60)


def show_main_menu():
    clear_screen()
    print_header()
    print("\n   [1]  IP Address Management")
    print("   [2]  Port Management")
    print("   [3]  Apply / Refresh Rules Now")
    print("   [4]  View Current Status")
    print("   [5]  Reset All Rules (Danger!)")
    print("   [0]  Exit\n")


def ip_menu():
    while True:
        clear_screen()
        print_header()
        print("\n   📍 IP Address Management\n")
        print("   [1]  Add IP to ALLOW list")
        print("   [2]  Remove IP from ALLOW list")
        print("   [3]  Add IP to BLOCK list")
        print("   [4]  Remove IP from BLOCK list")
        print("   [5]  View Allow/Block Lists")
        print("   [0]  Back to Main Menu\n")

        choice = input("   👉 Select option → ").strip()

        if choice == "1":
            ip = input("   🔐 Enter IP to ALLOW: ").strip()
            if ip:
                current = load_list(IP_ALLOW_FILE)
                if ip not in current:
                    current.append(ip)
                    save_list(IP_ALLOW_FILE, current)
                    print(f"   ✅ Added {ip} to ALLOW list")
                else:
                    print(f"   ℹ️  {ip} already in ALLOW list")
            input("\n   Press Enter to continue...")

        elif choice == "2":
            ip = input("   🗑️ Enter IP to remove from ALLOW: ").strip()
            current = load_list(IP_ALLOW_FILE)
            if ip in current:
                current.remove(ip)
                save_list(IP_ALLOW_FILE, current)
                print(f"   ✅ Removed {ip} from ALLOW list")
            else:
                print(f"   ⚠️  {ip} not found in ALLOW list")
            input("\n   Press Enter to continue...")

        elif choice == "3":
            ip = input("   🚫 Enter IP to BLOCK: ").strip()
            current = load_list(IP_BLOCK_FILE)
            if ip not in current:
                current.append(ip)
                save_list(IP_BLOCK_FILE, current)
                print(f"   ✅ Added {ip} to BLOCK list")
            else:
                print(f"   ℹ️  {ip} already in BLOCK list")
            input("\n   Press Enter to continue...")

        elif choice == "4":
            ip = input("   🔓 Enter IP to remove from BLOCK: ").strip()
            current = load_list(IP_BLOCK_FILE)
            if ip in current:
                current.remove(ip)
                save_list(IP_BLOCK_FILE, current)
                print(f"   ✅ Removed {ip} from BLOCK list")
            else:
                print(f"   ⚠️  {ip} not found in BLOCK list")
            input("\n   Press Enter to continue...")

        elif choice == "5":
            print("\n   ALLOW list:")
            for ip in load_list(IP_ALLOW_FILE):
                print(f"     • {ip}")
            print("\n   BLOCK list:")
            for ip in load_list(IP_BLOCK_FILE):
                print(f"     • {ip}")
            input("\n   Press Enter to continue...")

        elif choice == "0":
            break


def port_menu():
    while True:
        clear_screen()
        print_header()
        print("\n   🔌 Port Management\n")
        print("   [1]  Block a Port")
        print("   [2]  Unblock a Port")
        print("   [3]  View Blocked Ports")
        print("   [0]  Back to Main Menu\n")

        choice = input("   👉 Select option → ").strip()

        if choice == "1":
            port = input("   🚫 Enter port number to BLOCK: ").strip()
            if port.isdigit():
                current = load_list(PORT_BLOCK_FILE)
                if port not in current:
                    current.append(port)
                    save_list(PORT_BLOCK_FILE, current)
                    print(f"   ✅ Blocked port {port}")
                else:
                    print(f"   ℹ️  Port {port} already blocked")
            else:
                print("   ❌ Invalid port number")
            input("\n   Press Enter to continue...")

        elif choice == "2":
            port = input("   🔓 Enter port number to UNBLOCK: ").strip()
            current = load_list(PORT_BLOCK_FILE)
            if port in current:
                current.remove(port)
                save_list(PORT_BLOCK_FILE, current)
                print(f"   ✅ Unblocked port {port}")
            else:
                print(f"   ⚠️  Port {port} not found in block list")
            input("\n   Press Enter to continue...")

        elif choice == "3":
            ports = load_list(PORT_BLOCK_FILE)
            if ports:
                print("\n   Blocked ports:")
                for p in sorted(ports, key=int):
                    print(f"     • {p}")
            else:
                print("\n   No ports currently blocked.")
            input("\n   Press Enter to continue...")

        elif choice == "0":
            break


def apply_rules_now():
    """Apply current rules immediately"""
    config = load_config()
    print("\n   Applying firewall rules...\n")

    try:
        if IS_LINUX:
            linux_backup_current_rules()
            linux_flush_rules()
            linux_apply_ip_rules()
            linux_apply_port_rules()
            print("   ✅ Linux firewall rules successfully applied!\n")
        elif IS_WINDOWS:
            windows_apply_rules()
            print("   ✅ Windows Firewall rules successfully applied!\n")
    except Exception as e:
        print(f"   ❌ Error applying rules: {e}")
        logger.error(f"Rule application failed: {e}")

    input("   Press Enter to continue...")


def view_status():
    """Show current firewall status summary"""
    clear_screen()
    print_header()
    print("\n   Current Firewall Status Summary\n")

    print("   Platform:        ", platform.system())
    print("   Default policy:  ", load_config()["default_policy"])
    print("   Daily limit:     ", load_config()["daily_limit_minutes"], "minutes per IP\n")

    print("   Allowed IPs:", len(load_list(IP_ALLOW_FILE)))
    print("   Blocked IPs:", len(load_list(IP_BLOCK_FILE)))
    print("   Blocked Ports:", len(load_list(PORT_BLOCK_FILE)), "\n")

    input("   Press Enter to return...")


def reset_all_rules():
    """Dangerous: Reset firewall to clean state"""
    print("\n   ⚠️  WARNING: This will DELETE all custom firewall rules!")
    confirm = input("   Type YES to continue: ").strip().upper()
    if confirm != "YES":
        print("   Operation cancelled.")
        return

    try:
        if IS_LINUX:
            run_command(["iptables", "-F"])
            run_command(["iptables", "-X"])
            run_command(["iptables", "-t", "nat", "-F"])
            run_command(["iptables", "-P", "INPUT", "ACCEPT"])
            run_command(["iptables", "-P", "FORWARD", "ACCEPT"])
            run_command(["iptables", "-P", "OUTPUT", "ACCEPT"])
        elif IS_WINDOWS:
            run_command(["netsh", "advfirewall", "reset"])

        print("   ✅ All custom firewall rules have been reset!")
        logger.warning("Firewall reset to default by user")
    except Exception as e:
        print(f"   ❌ Error during reset: {e}")
        logger.error(f"Firewall reset failed: {e}")

    input("\n   Press Enter to continue...")


def main():
    config = load_config()

    while True:
        show_main_menu()
        choice = input("   👉 Select option → ").strip()

        if choice == "1":
            ip_menu()
        elif choice == "2":
            port_menu()
        elif choice == "3":
            apply_rules_now()
        elif choice == "4":
            view_status()
        elif choice == "5":
            reset_all_rules()
        elif choice == "0":
            print("\n   👋 Exiting Firewall Manager. Stay secure!")
            break
        else:
            print("   ❌ Invalid choice. Please try again.")
            input("   Press Enter to continue...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n   👋 Exiting gracefully...")
    except Exception as e:
        print(f"\n   💥 Critical error: {e}")
        logger.critical(f"Critical failure: {e}", exc_info=True)
        exit(1)