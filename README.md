# MITRE ATT&CK Detection Rules

A collection of hand-built Sigma detection rules mapped to MITRE ATT&CK techniques, 
with full reasoning documented for each: why the behavior is suspicious, what it looks 
like in logs, and how an analyst should investigate it.

## Why this exists

Most rule repositories are copy-paste collections. This one focuses on depth: 
every rule includes the underlying attacker logic, not just detection syntax.

## Structure

rules/ → Sigma rule (.yml) + explanation (.md) for each technique

## Methodology
Each rule documents five things: what happened, why it's suspicious, which logs 
detect it, known false positives, and investigation steps. The goal isn't just 
detection syntax, it's showing the reasoning an analyst would use to triage it.

## Rules

| Technique | ATT&CK ID | Status |
|---|---|---|
| PowerShell spawning Rundll32 | T1218.011 | ✅ |
| Word spawning PowerShell | T1566.001 | ✅ |
| Discovery Commands (Non-Interactive Parent) | T1033 / T1082 | ✅ |
| LSASS Memory Access | T1003.001 | ✅ |

## Author

Maheen Hasan --- CEH certified
