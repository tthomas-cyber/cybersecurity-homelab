# Tools and Methodology

## Penetration Testing Methodology
Every assessment follows this structure:

1. **Reconnaissance** — Passive information gathering
2. **Scanning** — Active network and service enumeration  
3. **Exploitation** — Attempting to compromise identified vulnerabilities
4. **Post-Exploitation** — Privilege escalation and persistence
5. **Documentation** — Findings reported in professional format

## Core Tools

### Nmap — Network Scanner
```bash
# Host discovery
nmap -sn 192.168.1.0/24

# Full port scan with service detection
nmap -sV -sC -p- -T4 [target]

# Vulnerability scan
nmap --script vuln [target]
```

### Metasploit — Exploitation Framework
```bash
# Start metasploit
msfconsole

# Search for exploits
search [vulnerability name]

# Use an exploit
use [exploit path]
show options
set RHOSTS [target]
run
```

### Gobuster — Directory Enumeration
```bash
# Web directory brute force
gobuster dir -u http://[target] -w /usr/share/wordlists/dirb/common.txt
```

### Nikto — Web Vulnerability Scanner
```bash
nikto -h http://[target]
```

### Netcat — Network Utility
```bash
# Listen for reverse shell
nc -lvnp 4444

# Connect to open port
nc [target] [port]
```
