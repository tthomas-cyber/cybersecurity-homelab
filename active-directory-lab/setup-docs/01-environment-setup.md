# AD Lab Setup — Phase 1: Environment Planning

## Date Started
May 14, 2026

## Objective
Build an isolated Active Directory environment to practice enterprise
penetration testing techniques safely without impacting real networks.

## Architecture Plan
VirtualBox Host-Only Network (192.168.56.0/24)
├── Windows Server 2019 DC (192.168.56.10) ← Domain Controller
└── Kali Linux WSL2 (172.28.206.26)        ← Attack Machine

## Software Required
- VirtualBox (already installed)
- Windows Server 2019 Evaluation ISO (free 180-day license)
- Kali Linux WSL2 (already installed)

## Why This Matters
Active Directory is present in approximately 90% of enterprise environments.
Every internal penetration test involves AD enumeration and attack techniques.
Building and attacking this environment directly mirrors real engagement scenarios.

## MITRE ATT&CK Techniques Covered
- T1558.003 — Kerberoasting
- T1558.004 — AS-REP Roasting  
- T1550.002 — Pass-the-Hash
- T1003.006 — DCSync
- T1069.002 — Domain Group Discovery
