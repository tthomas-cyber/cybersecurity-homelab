# SMB Enumeration Report

**Target:** 192.168.56.102
**Date:** 2026-06-03 18:50:02
**Tool:** SMBEnum by tthomas-cyber

---

## Service Discovery

| Port | Protocol | Status |
|------|----------|--------|
| 445 | SMB | Open |

## Authentication Testing

| Test | Result |
|------|--------|
| Null Session | Rejected |

## Enumerated Shares

| Share Name |
|------------|
| ADMIN$ |
| C$ |
| IPC$ |
| NETLOGON |
| SYSVOL |
| Reconnecting |
| Unable |

## Recommendations

1. Enable SMB signing on all Windows systems
2. Disable null session access
3. Restrict SMB access via firewall to trusted hosts
4. Monitor Event ID 4624 for anonymous logon attempts
