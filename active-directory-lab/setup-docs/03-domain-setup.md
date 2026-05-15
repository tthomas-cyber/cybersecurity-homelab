# AD Lab Setup — Phase 3: Domain Configuration

## Date
May 15, 2026

## Domain Details
- Domain Name: corp.local
- NetBIOS Name: CORP
- Domain Controller: DC01
- IP Address: 192.168.56.x

## Users Created

### Regular Users
| Username | Password | Notes |
|---|---|---|
| jsmith | Password123! | Domain Admin — privilege escalation target |
| sjones | Winter2024! | Standard user |
| mwilson | Company123! | Standard user |
| bbrown | Qwerty456! | AS-REP Roastable — no pre-auth required |

### Service Accounts
| Username | Password | SPN | Notes |
|---|---|---|---|
| svc_sql | SqlService2019! | MSSQLSvc/dc01.corp.local:1433 | Kerberoastable |
| svc_web | WebSvc123! | HTTP/web.corp.local | Kerberoastable |

## Vulnerabilities Intentionally Configured
- jsmith is Domain Admin with weak password
- bbrown has pre-authentication disabled (AS-REP Roastable)
- svc_sql and svc_web have SPNs registered (Kerberoastable)
- Passwords follow common enterprise weak password patterns

## Why These Vulnerabilities Matter
These misconfigurations reflect real enterprise environments where:
- Service accounts have SPNs and weak passwords
- Some accounts have pre-auth disabled for legacy compatibility
- Privileged users reuse weak passwords
