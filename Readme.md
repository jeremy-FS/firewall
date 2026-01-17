```markdown
# IP & Port Firewall Manager CLI

**Cross-platform (Linux + Windows) firewall management tool**
 
Supported platforms: **Linux (iptables)** & **Windows (netsh advfirewall)**  
License: MIT

### What this script actually does

Modern, user-friendly command-line tool that lets you:

- Manage **allow** and **block** lists for IPv4 addresses
- Block/unblock individual TCP/UDP ports
- Set default policy (DROP everything except explicitly allowed)
- Apply rules immediately after each change
- View current status summary
- Reset all custom rules (with confirmation)
- Keep persistent lists across reboots (stored in `~/.firewall_cli/` on Linux, `%USERPROFILE%\.firewall_cli\` on Windows)
- Create automatic backups of current iptables rules before changes (Linux only)
- Provide clean, colorful output with proper UX

**Important notes about current functionality:**

- Daily per-IP connection limit feature is **NOT** implemented yet (planned)
- nftables support is **NOT** fully implemented (detects nft but still uses iptables)
- Windows Firewall advanced features (like program-based rules) are **NOT** supported yet
- No IPv6 support
- No rate limiting / connection limiting beyond basic block/allow

### Requirements

- **Python** ≥ 3.6
- **Linux**: root privileges (`sudo`) + iptables installed
- **Windows**: Administrator privileges

### Installation & Usage (single file – no dependencies beyond standard library)

```bash
# 1. Save the script as firewall_cli.py anywhere

# 2. Linux (run with sudo)
sudo python3 firewall_cli.py

# 3. Windows (run as Administrator)
# Right-click cmd/powershell → Run as administrator
python firewall_cli.py
```

### Main Menu

```
════════════════════════════════════════════════════════════
         🤖 Enhanced Firewall Manager CLI 2025         
         IP & Port Control - Linux & Windows         
════════════════════════════════════════════════════════════

   [1]  IP Address Management
   [2]  Port Management
   [3]  Apply / Refresh Rules Now
   [4]  View Current Status
   [5]  Reset All Rules (Danger!)
   [0]  Exit
```

### IP Address Management Menu

```
   [1]  Add IP to ALLOW list          ← whitelist (highest priority)
   [2]  Remove IP from ALLOW list
   [3]  Add IP to BLOCK list          ← explicit deny
   [4]  Remove IP from BLOCK list
   [5]  View Allow/Block Lists
   [0]  Back
```

### Port Management Menu

```
   [1]  Block a Port
   [2]  Unblock a Port
   [3]  View Blocked Ports
   [0]  Back
```

### Storage Location

All persistent data is stored in:

- Linux:  `~/.firewall_cli/`
- Windows: `%USERPROFILE%\.firewall_cli\`

Files created:
- `ip_allow.txt`
- `ip_block.txt`
- `port_block.txt`
- `config.json` (future use)
- `firewall.log` (operations log)

### Security Notes & Recommendations

- Always run with **elevated privileges** (sudo / Administrator)
- Default policy is **DROP** – only explicitly allowed traffic passes
- Regularly backup your firewall state:
  - Linux: `iptables-save > backup.rules`
  - Windows: `netsh advfirewall export "C:\firewall.wfw"`
- Consider combining with fail2ban / crowdsec for dynamic blocking
- For production servers prefer declarative tools (ansible, puppet, ufw, firewalld)

### Planned Features (roadmap – not yet implemented)

- Daily per-IP connection/time limit
- Full nftables support
- IPv6 management
- Rate limiting / connection limiting
- Program/path based rules (Windows)
- Import/export rules
- Dry-run mode
- GUI version (tkinter or textual)

### Legal / Ethical Note

This tool gives you **very powerful control** over network traffic.  
Use responsibly.  
Misconfiguration can lock you out of your own server.

Happy (and safe) firewalling! 🛡️
