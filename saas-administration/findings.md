# Splunk + Microsoft 365 Audit Log Pipeline — Findings

**Date:** 2026-06-17
**Analyst:** Tyler Thomas
**Environment:** Microsoft 365 E5 Developer Tenant (Chalked333.onmicrosoft.com)
**Tool:** Splunk Enterprise 10.4.0 + Splunk Add-on for Microsoft Office 365 (v6.0.2)
**Index:** default | **Sourcetype:** o365:management:activity

---

## Objective

The goal of this lab was to connect Splunk to a Microsoft 365 tenant via the Office 365 Management Activity API, verify that audit events were flowing correctly, and identify events that would be relevant to a SOC analyst monitoring for suspicious activity.

---

## Pipeline Architecture

```
M365 Tenant (Chalked333.onmicrosoft.com)
        |
        | Office 365 Management Activity API
        | (Audit.AzureActiveDirectory, Audit.Exchange, Audit.General)
        |
Azure AD App Registration ("Chalked")
  - Application permissions: ActivityFeed.Read, ServiceHealth.Read
  - Admin consent granted
        |
Splunk TA for Microsoft Office 365 (v6.0.2)
  - Tenant: Chalk | Endpoint: Worldwide
  - Poll interval: 300 seconds
        |
Splunk Enterprise (chalk:8000)
  - index=default
  - sourcetype=o365:management:activity
```

---

## Events Captured

### Summary

| Operation | Workload | Count | ResultStatus |
|---|---|---|---|
| ApiEndpointCallEvent | PowerPlatform | 3 | Succeeded |
| TeamSettingChanged | MicrosoftTeams | 2 | N/A |
| **Total** | | **5** | |

---

### Finding 1 — Microsoft Teams Channel Privacy Modified

**Operation:** `TeamSettingChanged`
**Workload:** MicrosoftTeams
**User:** TylerThomas@Chalked333.onmicrosoft.com
**Timestamps:** 2026-06-17T07:45:27, 2026-06-17T07:45:28
**Team:** Finance-Department

Two back-to-back `TeamSettingChanged` events were captured showing the Finance-Department Teams channel being switched from Private to Public and then back to Private within one second of each other.

| Event | Setting | Old Value | New Value |
|---|---|---|---|
| 1 | Team access type | Private | Public |
| 2 | Team access type | (empty) | Private |

**Why this matters from a SOC perspective:**

A finance team channel going from Private to Public is the kind of thing that should immediately get a SOC analyst's attention. That change exposes internal financial conversations, shared files, and the full membership list to anyone in the organization. In a real investigation, you'd want to know whether this was an accidental misconfiguration or something more deliberate — either way it warrants a follow-up with the user. In a BEC (Business Email Compromise) or insider threat scenario, making a sensitive channel public before exfiltrating its contents is a realistic attack pattern.

**Detection Query:**

```spl
index=* sourcetype="o365:management:activity"
Operation="TeamSettingChanged"
| eval privacy_change=if(NewValue="Public" AND (like(lower(TeamName),"%finance%") OR like(lower(TeamName),"%hr%") OR like(lower(TeamName),"%exec%")), "HIGH RISK", "Review")
| table CreationTime, UserId, TeamName, OldValue, NewValue, privacy_change
| sort -CreationTime
```

---

### Finding 2 — Power Platform API Endpoint Activity

**Operation:** `ApiEndpointCallEvent`
**Workload:** PowerPlatform
**User:** TylerThomas@Chalked333.onmicrosoft.com
**Timestamps:** 2026-06-17T07:46:16, 2026-06-17T07:57:31, 2026-06-16T03:57:42
**ResultStatus:** Succeeded

Three successful API calls were logged against Power Platform endpoints, including one against `/maven/agent365/securityalerts/riskyagentssummary` — part of Power Platform's security agent framework.

**Why this matters from a SOC perspective:**

Power Platform API calls don't get a lot of attention in smaller SOC environments, but they should. Unauthorized automation flows, API abuse from a compromised admin account, or unusual call patterns outside business hours are all things worth catching. These three events are benign — they came from my own admin account during setup — but in production, the same event type from an unexpected user or at 3am would be worth investigating. The main value here is establishing a baseline: once you know what normal looks like, anomalies stand out.

**Detection Query:**

```spl
index=* sourcetype="o365:management:activity"
Operation="ApiEndpointCallEvent" Workload="PowerPlatform"
| table CreationTime, UserId, Operation, ResultStatus
| sort -CreationTime
```

---

## Troubleshooting Log

Getting this pipeline working wasn't straightforward. I'm documenting the errors I hit and how I resolved them because that process is part of the lab — understanding *why* things break is just as useful as knowing how to configure them correctly.

| Error | Root Cause | Fix |
|---|---|---|
| AF20020 — content type not valid | Splunk TA was sending lowercase content type values to a case-sensitive API endpoint | Resolved after Microsoft's audit backend finished provisioning for the tenant |
| AF10001 — permission set empty | The ActivityFeed.Read permission hadn't been added to the Azure AD app registration | Added Office 365 Management APIs → ActivityFeed.Read (Application type) and granted admin consent |
| Tenant does not exist | Unified audit logging was not enabled on the fresh Developer tenant; backend takes time to provision | Confirmed enabled via `Get-AdminAuditLogConfig`; error cleared after ~12-24 hour propagation window |
| Orphaned tenant reference (404) | Splunk inputs were referencing a stale config object ID from a previous failed setup attempt | Deleted and recreated the Management Activity input, selecting the account by name rather than GUID |
| GCC endpoint mismatch | The TA was configured for US Government Cloud instead of Worldwide | Changed the cloud endpoint setting to Worldwide in the TA tenant configuration |

One thing I learned through this that's worth calling out: **a successful OAuth token does not mean your API call will succeed.** The AF10001 error made this concrete — the authentication step worked fine and returned a valid token, but the token carried no permissions for the Management Activity API because ActivityFeed.Read hadn't been granted yet. Auth and authorization are two separate things, and that distinction matters when you're troubleshooting API integrations.

---

## Next Steps

- [ ] Generate sign-in activity to capture AzureActiveDirectory workload events (failed logins, MFA prompts, role assignments)
- [ ] Build a saved Splunk alert for `TeamSettingChanged` with `NewValue=Public` on sensitive teams
- [ ] Add detection for inbox rule creation (`New-InboxRule`) once Exchange audit events are flowing
- [ ] Build a simple Splunk dashboard with panels broken out by workload
