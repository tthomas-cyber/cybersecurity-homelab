# Phishing Simulation Report — Campaign 01

**Campaign Name:** Corp-Password-Reset-Test  
**Date:** May 23, 2026  
**Tester:** Tyler Thomas  
**Tool:** GoPhish  
**Scope:** Self-owned test accounts in controlled lab environment  

## Executive Summary
A simulated phishing campaign was conducted to demonstrate social engineering
assessment methodology used in real penetration testing engagements. The campaign
simulated a credential harvesting attack using an urgent password reset pretext
targeting corporate employees.

## Campaign Configuration

| Setting | Value |
|---|---|
| Email Template | IT-Password-Reset |
| Pretext | Urgent corporate password expiration |
| Landing Page | Fake corporate password reset portal |
| Sending Profile | Mailtrap sandbox |
| Target Group | Test-Targets (3 users) |

## Target List

| Name | Email | Position |
|---|---|---|
| John Smith | jsmith@corp.local | Manager |
| Sarah Jones | sjones@corp.local | HR Staff |
| Tyler Thomas | tytyp2002@gmail.com | IT Staff |

## Campaign Results

| Metric | Count | Percentage |
|---|---|---|
| Emails Sent | 1 | 33% |
| Emails Opened | 0 | 0% |
| Links Clicked | 0 | 0% |
| Credentials Submitted | 0 | 0% |
| Emails Reported | 0 | 0% |

## Email Template Analysis
The phishing email used an urgency-based pretext — a common and effective
social engineering technique. Key elements:

- **Urgency:** 24 hour password expiration deadline
- **Authority:** Sent from apparent IT Support team
- **Fear:** Threat of losing system access
- **Call to action:** Prominent Reset Password button

These elements mirror real world phishing campaigns used by threat actors
targeting corporate environments.

## Landing Page Analysis
The credential harvesting page mimicked a corporate IT portal using:
- Company branding and color scheme
- Professional layout matching Microsoft 365 aesthetic
- Email and password capture fields
- Redirect to legitimate page after submission to avoid suspicion

## Technical Setup

### Tools Used
- GoPhish — Campaign management and tracking
- Mailtrap — SMTP sandbox for safe email testing
- Custom HTML — Email template and landing page

### Infrastructure
- GoPhish server running locally on port 3333
- All emails caught by Mailtrap sandbox
- No real users targeted or affected

## Observations
Two of three emails failed to deliver due to non-existent target domains
(corp.local) — expected behavior in isolated lab environment. In a real
engagement all target email addresses would be valid corporate addresses
provided by the client.

## Real World Application
In a real phishing assessment engagement:
1. Client provides authorized target list
2. Scope and rules of engagement documented in writing
3. Campaign launched against real corporate emails
4. Results analyzed for click rates and credential submission
5. Awareness training recommended based on findings
6. Full report delivered to client security team

## Defensive Recommendations
1. Implement email filtering to catch urgency-based subject lines
2. Enable multi-factor authentication — renders harvested passwords useless
3. Deploy anti-phishing training for all employees
4. Configure DMARC, DKIM, and SPF records to reduce spoofing
5. Establish clear process for employees to report suspicious emails
6. Conduct regular phishing simulations to measure awareness improvement

## MITRE ATT&CK Mapping
- T1566.001 — Spearphishing Attachment
- T1566.002 — Spearphishing Link
- T1598 — Phishing for Information
- T1056.003 — Web Portal Capture
