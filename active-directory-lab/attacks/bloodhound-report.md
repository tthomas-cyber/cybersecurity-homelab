# BloodHound Active Directory Enumeration Report

**Target Domain:** corp.local  
**Domain Controller:** 192.168.56.102  
**Date:** May 16, 2026  
**Tester:** Tyler Thomas  
**Tool:** BloodHound Community Edition v9.1.0  
**MITRE ATT&CK:** T1069.002, T1087.002  

## Overview
BloodHound is an Active Directory reconnaissance tool that uses graph theory to map relationships between domain objects and identify attack paths to high-value targets. It collects data via SharpHound and visualizes complex permission chains that would be impossible to identify manually.

## Data Collection
SharpHound collector executed on domain-joined system with standard user credentials:
SharpHound.exe -c All --domain corp.local

Collection categories: Users, Groups, Computers, Sessions, ACLs, Trusts, Containers

## Critical Finding — Direct Path To Domain Admin

### Attack Path Identified
JSMITH@CORP.LOCAL → MemberOf → DOMAIN ADMINS@CORP.LOCAL

### Impact
jsmith is a direct member of Domain Admins. Any compromise of jsmith's credentials results in immediate Domain Admin access — full control of the entire Active Directory environment including:
- All domain computers
- All domain user accounts  
- Active Directory infrastructure
- Group Policy
- DNS

### How This Was Reached
1. AS-REP Roasting identified bbrown as a target with pre-auth disabled
2. bbrown credentials obtained via hash cracking
3. Kerberoasting with bbrown credentials identified svc_web as vulnerable
4. BloodHound enumeration revealed jsmith is Domain Admin
5. jsmith credentials cracked via Kerberoasting (Password123!)
6. Full Domain Admin access achieved

## Attack Chain Summary
Initial Access
↓

AS-REP Roast bbrown (no credentials needed)
↓

Crack bbrown hash → qwerty456
↓

Kerberoast with bbrown credentials
↓

Crack svc_web hash → Password1!
↓

BloodHound enumeration reveals jsmith = Domain Admin
↓

Crack jsmith hash → Password123!
↓

DOMAIN ADMIN

## Why BloodHound Matters In Real Engagements
Manual enumeration of Active Directory permissions across thousands of users and groups is impossible. BloodHound automates this and surfaces attack paths that would never be found manually. It is standard tooling in professional penetration tests and used by threat actors including APT groups.

## Detection Opportunities
- Monitor for SharpHound execution patterns — large volume of LDAP queries in short time
- Windows Event ID 4662 — Object access in Active Directory
- Alert on bulk LDAP enumeration from single source
- Monitor for unusual Kerberos ticket requests following LDAP enumeration

## Remediation Recommendations
1. Remove jsmith from Domain Admins — apply principle of least privilege
2. Audit all Domain Admin members regularly:
```powershell
Get-ADGroupMember -Identity "Domain Admins"
```
3. Implement tiered administration model — separate admin accounts for privileged tasks
4. Enable Advanced Audit Policy for AD object access
5. Deploy Microsoft Defender for Identity — detects BloodHound collection patterns
6. Regular BloodHound runs by defenders to find paths before attackers do
