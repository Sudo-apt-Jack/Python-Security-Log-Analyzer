# Security Incident Investigation Report

**Case ID:** LAB-004  
**Title:** Repeated Authentication Failures Followed by Success  
**Environment:** Python Security Log Analyzer (simulated CSV data)  
**Classification:** Suspicious authentication pattern — unconfirmed  
**Status:** Lab investigation / no real-world incident  
**Date of simulated activity:** October 20, 2025

## Executive summary

The analyzer detected five failed login attempts against the `admin` account from the simulated source IP `203.0.113.10` within two minutes. A successful login from the same IP and username occurred 30 seconds after the fifth failure. The lab detection engine generated a HIGH alert for possible brute-force behavior and a CRITICAL alert for a successful login following repeated failures. The evidence does **not** establish that an account was compromised.

## Scope and evidence

- Source: `sample_logs.csv`, a synthetic authentication log.
- Detection: `detection_rules.py`, configured for five failures within a rolling five-minute window.
- Output: `security_alerts.csv` and the local Streamlit dashboard.
- All timestamps are naive sample timestamps; no timezone is specified.
- `203.0.113.10` is a private, illustrative IP address.

## Timeline

| Timestamp | Event | Source IP | Username |
|---|---|---|---|
| 2026-10-10 10:00:00 | Failed login | 203.0.113.10 | admin |
| 2026-10-10 10:00:30 | Failed login | 203.0.113.10 | admin |
| 2026-10-10 10:01:00 | Failed login | 203.0.113.10 | admin |
| 2026-10-10 10:01:30 | Failed login | 203.0.113.10 | admin |
| 2026-10-10 10:02:00 | Failed login; HIGH alert threshold reached | 203.0.113.10 | admin |
| 2026-10-10 10:02:30 | Successful login; CRITICAL correlation alert | 203.0.113.10 | admin |

## Findings

1. Five failed attempts occurred within the configured five-minute detection window.
2. A successful authentication followed the failures for the same source IP and username.
3. The analyzer produced two lab-defined alerts: HIGH (possible brute force) and CRITICAL (success after failures).
4. This pattern could be caused by an authorized user entering an incorrect password repeatedly; the data alone cannot distinguish that from malicious activity.

## Analyst assessment

**Disposition:** Suspicious pattern; additional evidence required.  
**Confidence:** High that the configured rules matched the synthetic events; low confidence about malicious intent or compromise.

## Recommended investigation steps (real environment)

- Verify whether the source IP, user, device, and login time are expected.
- Review authentication logs for adjacent events and other affected accounts.
- Check MFA, device, and identity-provider records when authorized and available.
- Contact the account owner or administrator through an approved process if needed.
- Escalate and contain only if supporting evidence or established procedures justify it.

## Outcome

No real account or endpoint was affected. The case demonstrates alert triage, timeline reconstruction, evidence interpretation, and documentation using simulated data.

## Limitations

This is a synthetic demonstration, not a validated real-world intrusion. The report is based only on the sample CSV and the analyzer's configured rules. No packet captures, endpoint telemetry, or identity-provider records were examined.
