# AS-REP Roasting Attack Report

**Target Domain:** corp.local  
**Domain Controller:** 192.168.56.102  
**Date:** May 16, 2026  
**Tester:** Tyler Thomas  
**Technique:** AS-REP Roasting  
**MITRE ATT&CK:** T1558.004  

## Overview
AS-REP Roasting targets Active Directory accounts with Kerberos pre-authentication disabled. When pre-authentication is disabled, an attacker can request an authentication token for that account without knowing the password. The response contains data encrypted with the user's password hash which can be taken offline for cracking. Unlike Kerberoasting, this attack requires no valid domain credentials whatsoever.

## Why This Matters In Real Engagements
This attack can be executed from an unauthenticated position on the network making it particularly dangerous. Legacy applications sometimes require pre-authentication to be disabled for compatibility reasons leaving accounts permanently exposed. Combined with weak passwords this provides unauthenticated initial access to a domain account.

## Attack Methodology

### Step 1 — Identify Vulnerable Accounts
Queried domain controller for accounts with pre-authentication disabled without any credentials:
impacket-GetNPUsers corp.local/bbrown -no-pass -dc-ip 192.168.56.102

Result: AS-REP hash returned for bbrown without requiring any authentication.

### Step 2 — Offline Password Cracking
hashcat -m 18200 asrep-hash.txt rockyou.txt

| Account | Cracked | Password |
|---|---|---|
| bbrown | Yes | qwerty456 |

### Step 3 — Impact
With bbrown's credentials an attacker now has:
- Authenticated domain access
- Ability to enumerate all domain objects
- Platform to launch further attacks including Kerberoasting
- Potential access to systems where bbrown has permissions

## Key Differences From Kerberoasting

| | Kerberoasting | AS-REP Roasting |
|---|---|---|
| Credentials needed | One valid domain account | None |
| Target accounts | Accounts with SPNs | Accounts without pre-auth |
| Hash type | TGS-REP (13100) | AS-REP (18200) |
| MITRE ID | T1558.003 | T1558.004 |

## Detection Opportunities
- Windows Event ID 4768 — Kerberos authentication ticket requested
- Alert on AS-REP requests using RC4 encryption (etype 23)
- Baseline normal authentication patterns and alert on anomalies
- Monitor for bulk AS-REP requests from single source

## Remediation Recommendations
1. Enable pre-authentication on all accounts immediately
2. Audit all accounts for DoesNotRequirePreAuth flag:
```powershell
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```
3. Reset bbrown password to random 25+ character string
4. Enforce strong password policy across all accounts
5. Implement fine-grained password policies for privileged accounts
6. Enable AES encryption for Kerberos authentication

## Tools Used
- Impacket GetNPUsers — AS-REP hash extraction
- Hashcat mode 18200 — AS-REP hash cracking
- Rockyou wordlist — Password dictionary
