# Wazuh Enterprise SIEM Lab

A 6-day hands-on home lab simulating an enterprise Security Operations Center environment. Built on Wazuh 4.14.4 with Windows 11 and Kali Linux endpoints, this project covers the full SOC workflow — from initial deployment through detection engineering, attack simulation, incident response, and threat intelligence integration.

**Built by:** Ronak Mishra — SOC Analyst, Ottawa, ON  
**GitHub:** [github.com/ronakmishra28](https://github.com/ronakmishra28) | **Medium:** [@ronakonweb](https://medium.com/@ronakonweb) | **LinkedIn:** [linkedin.com/in/ronakmishra28](https://linkedin.com/in/ronakmishra28)  
**Lab Duration:** April 18–23, 2026  
**Status:** Complete

---

## Lab Environment

| Component | Details |
|-----------|---------|
| Host Machine | MacBook M4 Pro, 24GB RAM |
| Hypervisor | Parallels Desktop |
| Wazuh Manager | Ubuntu 22.04 ARM64 — IP: 10.0.0.33 |
| Agent 001 | Windows 11 Enterprise — IP: 10.0.0.32 |
| Agent 002 | Kali Linux 2025.2 — IP: 10.0.0.100 |
| Wazuh Version | 4.14.4 |
| Network | Parallels Shared Network — 10.0.0.0/24 |

---

## What I Built

### Multi-Agent SIEM Deployment
Deployed Wazuh manager on Ubuntu with two connected agents — Windows 11 Enterprise and Kali Linux 2025.2. Configured Windows audit policy to capture process creation (4688), authentication events (4624/4625), scheduled task creation (4698), and user account changes (4720). Enabled PowerShell Script Block Logging (Event ID 4104) and Module Logging (4103) for full PowerShell visibility across the environment.

### Custom Detection Rules — MITRE ATT&CK Mapped
Wrote five custom detection rules from scratch targeting real attack techniques:

| Rule ID | Technique | MITRE | Severity |
|---------|-----------|-------|----------|
| 100002 | PowerShell encoded command execution | T1059.001 | 12 |
| 100003 | PowerShell download cradle | T1105 | 12 |
| 100004 | Office application spawning shell process | T1566.001 | 15 (CRITICAL) |
| 100005 | New local Windows user account created | T1136.001 | 10 |
| 100006 | Multiple failed logons from same IP (brute force) | T1110 | 12 |

All rules use PCRE2 regex pattern matching against `win.eventdata` fields from Windows Event Log data. Rule 100006 uses frequency-based correlation — fires when 5+ failed logins from the same IP occur within a 2-minute window.

### Attack Simulation & Detection Validation
Simulated five real attack techniques from Kali Linux against the Windows target and validated detection:

- **Brute force authentication** — 10 failed logons via `net use` → Rule 100006 fired ✅
- **PowerShell encoded command** (`-EncodedCommand`) → Rule 100002 fired ✅
- **PowerShell download cradle** (`Invoke-WebRequest`) → Rule 100003 fired ✅
- **Scheduled task persistence** (WindowsUpdateHelper) → Event 4698 detected ✅
- **Nmap port scan** → Not detected (detection gap documented, requires Suricata) ✅

### Detection Gaps — Documented With Mitigations
Two detection gaps identified and formally documented:

**Gap 1 — Network scanning invisible to log-based SIEM**  
Nmap scans generate no Windows Event Log entries. Detection requires network-layer IDS (Suricata) deployed on the network segment, not endpoint-based logging.

**Gap 2 — Hydra blocked before authentication**  
Windows 11 blocks Hydra at the TCP handshake level before NTLM negotiation begins. No 4625 events generated. Simulated using native `net use` which triggers proper authentication events.

### Incident Response — Full IR Exercise
Worked a complete incident response exercise on a simulated multi-stage attack. Reconstructed the attack chain from Wazuh alerts:

- 11:31 — Brute force authentication (Rule 100006)
- 11:42 — Encoded PowerShell execution (Rule 100002)
- 11:52 — Scheduled task persistence created (Event 4698)

Performed containment (agent isolation via `agent_control -i 001`), eradication (removed WindowsUpdateHelper scheduled task, verified no backdoor accounts or malicious services), and recovery. Produced formal incident report IR-2026-001.

### Integrations & Threat Intelligence

**VirusTotal Integration**  
Connected Wazuh FIM to VirusTotal API. When FIM detects a file created or modified in monitored directories, Wazuh automatically computes the SHA256/MD5 hash and queries VirusTotal's 70+ AV engine database. Unknown files return Rule 87103 (`found:0`). Known malware returns Rule 87105 with malicious engine count. Reduces manual investigation time for file-based alerts.

**Active Response**  
Configured `win_route-null` Active Response to automatically block attacker IPs via Windows Firewall when brute force rule 100006 fires. Auto-unblocks after 60-second timeout. Configuration verified correct. Production testing confirmed the integration chain functions — rule fires, command reaches execd, script executes. Full end-to-end IP block requires a real external source IP; localhost loopback (`::1`) is intentionally excluded from firewall blocking to prevent network stack disruption.

**Vulnerability Detection**  
Enabled Wazuh syscollector to inventory all software on the Windows agent (verified 20+ applications including Microsoft Edge 147.0.3912.72, Teams, Outlook). CVE feed configured to update every 60 minutes from NVD. Feed downloaded successfully twice during the lab period.

**Kali Linux auditd**  
Installed and configured `auditd` on Kali for syscall-level Linux visibility. Watch rules monitoring `/etc/passwd`, `/etc/shadow`, `/bin/bash`, and `/usr/bin/nc`. Triggered shadow file read and confirmed 51 Wazuh alerts from Kali including MITRE T1548.003 mapping (Sudo and Sudo Caching). Pipeline: kernel syscall → audit.log → Wazuh agent → manager → dashboard.

---

## Repository Structure

```
wazuh-enterprise-siem-lab/
├── README.md
├── rules/
│   └── local_rules.xml              # 5 custom detection rules
├── day-01-foundation/
│   ├── day-01-foundation.md         # Lab setup, architecture, agent deployment
│   └── screenshots/
├── day-02-log-sources/
│   ├── day-02-log-sources.md        # PowerShell logging, SCA, baseline building
│   └── screenshots/
├── day-03-detection-engineering/
│   ├── day-03-detection-engineering.md  # Writing 5 custom Wazuh rules
│   └── screenshots/
├── day-04-attack-simulation/
│   ├── day-04-attack-simulation.md  # Attack simulation, detection validation, gaps
│   └── screenshots/
├── day-05-incident-response/
│   ├── IR-2026-001.md               # Formal incident report
│   └── screenshots/
└── day-06-integrations/
    ├── day-06-integrations.md       # VirusTotal, Active Response, Vuln Detection, auditd
    └── screenshots/
```

---

## Key Skills Demonstrated

**SIEM Operations**
- Wazuh deployment and multi-agent management
- Log source configuration and indexer pipeline troubleshooting
- Alert triage and investigation using Discover and dashboards
- Wazuh rule engine architecture (decoders → rules → alerts)

**Detection Engineering**
- Writing custom rules using PCRE2 regex against structured log fields
- MITRE ATT&CK framework mapping
- Frequency-based correlation for multi-event detection
- Distinguishing detection gaps from false positives

**Threat Intelligence**
- VirusTotal API integration for automated file reputation enrichment
- Hash-based malware identification
- Understanding limitations (zero-day blind spots, defense in depth)

**Incident Response**
- Alert-driven attack chain reconstruction
- Timeline analysis across multiple rule firings
- Agent isolation and containment procedures
- Formal IR documentation (Executive Summary → Timeline → Containment → Eradication → Recovery → Lessons Learned)

**Windows Security**
- Windows Event IDs and their security significance (4624, 4625, 4688, 4698, 4720)
- Audit policy configuration via `auditpol`
- PowerShell Script Block Logging and why it defeats obfuscation
- Active Directory and local authentication event analysis

**Linux Security**
- auditd installation and syscall-level watch rule configuration
- Audit log forwarding to SIEM
- MITRE ATT&CK mapping from Linux audit events

**Vulnerability Management**
- Wazuh syscollector software inventory
- CVE feed configuration and NVD integration
- CVSS scoring and remediation prioritization framework

---

## Detection Rules

```xml
<group name="local,windows,custom_detections,">

  <!-- PowerShell Encoded Command — T1059.001 -->
  <rule id="100002" level="12">
    <if_sid>67027</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)-enc|-encodedcommand</field>
    <description>ALERT: PowerShell encoded command execution - possible obfuscated attack</description>
    <mitre><id>T1059.001</id></mitre>
    <group>attack,powershell,obfuscation,</group>
  </rule>

  <!-- PowerShell Download Cradle — T1105 -->
  <rule id="100003" level="12">
    <if_sid>67027</if_sid>
    <field name="win.eventdata.commandLine" type="pcre2">(?i)DownloadString|DownloadFile|Invoke-WebRequest|iwr\s|wget\s|curl\s</field>
    <description>ALERT: PowerShell download cradle detected - possible malware download</description>
    <mitre><id>T1105</id></mitre>
    <group>attack,powershell,download,</group>
  </rule>

  <!-- Office App Spawning Shell — T1566.001 -->
  <rule id="100004" level="15">
    <if_sid>67027</if_sid>
    <field name="win.eventdata.parentProcessName" type="pcre2">(?i)winword\.exe|excel\.exe|powerpnt\.exe|outlook\.exe</field>
    <field name="win.eventdata.newProcessName" type="pcre2">(?i)cmd\.exe|powershell\.exe|wscript\.exe|cscript\.exe|mshta\.exe</field>
    <description>CRITICAL: Office application spawned shell process - macro attack likely</description>
    <mitre><id>T1566.001</id></mitre>
    <group>attack,macro,office,critical,</group>
  </rule>

  <!-- New User Account Created — T1136.001 -->
  <rule id="100005" level="10">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">4720</field>
    <description>ALERT: New Windows user account created - verify if authorized</description>
    <mitre><id>T1136.001</id></mitre>
    <group>attack,persistence,account_creation,</group>
  </rule>

  <!-- Brute Force Detection — T1110 -->
  <rule id="100006" level="12" frequency="5" timeframe="120">
    <if_matched_sid>60122</if_matched_sid>
    <same_field>win.eventdata.ipAddress</same_field>
    <description>ALERT: Multiple failed Windows logons from same IP - possible brute force</description>
    <mitre><id>T1110</id></mitre>
    <group>attack,brute_force,authentication,</group>
  </rule>

</group>
```

---

## Daily Logs

| Day | Focus | Status |
|-----|-------|--------|
| [Day 1](day-01-foundation/) | Lab setup, agent deployment, Windows audit policy, Event ID 4688 verification | ✅ Complete |
| [Day 2](day-02-log-sources/) | PowerShell Script Block Logging, SCA CIS benchmarks, baseline building | ✅ Complete |
| [Day 3](day-03-detection-engineering/) | 5 custom detection rules, MITRE ATT&CK mapping, rule testing | ✅ Complete |
| [Day 4](day-04-attack-simulation/) | Attack simulation from Kali, detection validation, gap analysis | ✅ Complete |
| [Day 5](day-05-incident-response/) | Full IR exercise, agent isolation, formal incident report IR-2026-001 | ✅ Complete |
| [Day 6](day-06-integrations/) | VirusTotal, Active Response, vulnerability detection, Kali auditd | ✅ Complete |

---

## What I Would Do Next

- Deploy Suricata IDS and integrate with Wazuh to close the network scanning detection gap
- Move to Splunk SIEM — translate all 5 custom rules to SPL and compare detection capabilities
- Add a third Windows endpoint to simulate lateral movement detection
- Implement Wazuh agent groups to manage endpoint configs at scale
- Build a SOC dashboard with custom visualizations per MITRE tactic

---

## Connect

**LinkedIn:** [linkedin.com/in/ronakmishra28](https://linkedin.com/in/ronakmishra28)  
**Portfolio:** [ronakmishra28.github.io](https://ronakmishra28.github.io)  
**Medium:** [@ronakonweb](https://medium.com/@ronakonweb)
