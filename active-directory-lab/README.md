# Active Directory Attack Lab

## Overview
A home lab simulating a real enterprise Active Directory environment built to practice
modern penetration testing techniques used in professional engagements.

## Environment
- **Domain Controller:** Windows Server 2019
- **Domain Name:** corp.local
- **Attack Machine:** Kali Linux (WSL2)
- **Hypervisor:** VirtualBox
- **Network:** Host-only isolated network

## Techniques Practiced
- [ ] Domain enumeration with BloodHound
- [ ] Kerberoasting (CVE targeting service accounts)
- [ ] AS-REP Roasting
- [ ] Pass-the-Hash lateral movement
- [ ] DCSync credential dumping

## Tools Used
- BloodHound / SharpHound
- Impacket suite
- CrackMapExec
- Hashcat
- Rubeus

## Setup Documentation
Full build process documented in /setup-docs including:
- Windows Server 2019 installation
- Active Directory Domain Services configuration
- Vulnerable user and service account creation
- Network configuration

## Purpose
This lab simulates the internal network phase of a penetration test after
initial access has been obtained. All techniques practiced here reflect
real-world enterprise attack paths documented in MITRE ATT&CK framework.
