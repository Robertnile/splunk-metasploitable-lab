#  Project Report — Splunk SIEM Home Lab

**Author:** Nwodu Robert  
**Role:** Aspiring SOC Analyst | Training at Luke Tech Limited, Canada  
**GitHub:** [@Robertnile](https://github.com/Robertnile)  
**Location:** Nigeria  

---

## Table of Contents

- [Objective](#objective)
- [Scope](#scope)
- [Lab Environment](#lab-environment)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Attack Scenarios & Detections](#attack-scenarios--detections)
  - [1. Nmap Reconnaissance Scan](#1-nmap-reconnaissance-scan)
  - [2. SSH Brute Force](#2-ssh-brute-force)
  - [3. Reverse Shell / C2 Traffic](#3-reverse-shell--c2-traffic)
  - [4. Privilege Escalation — New User Creation](#4-privilege-escalation--new-user-creation)
- [Detection Queries (SPL)](#detection-queries-spl)
- [Remediation Summary](#remediation-summary)
- [Key Findings](#key-findings)
- [Lessons Learned](#lessons-learned)
- [Conclusion](#conclusion)

---

## Objective

The goal of this project was to build an isolated SIEM home lab environment, simulate real-world attack techniques against a vulnerable Linux target (Metasploitable3), and detect those attacks using **Splunk Enterprise** as the SIEM platform — combined with **Zeek** for network-level visibility.

The project covers the full SOC workflow: log ingestion, baseline baselining, attack simulation, detection engineering, alert creation, and dashboard building — using only open-source and free tools.

---

## Scope

The lab covers **4 attack scenarios** against a single Linux target:

| # | Attack Technique | Category |
|---|-----------------|----------|
| 1 | Nmap port and service reconnaissance scan | Reconnaissance |
| 2 | SSH brute force using Hydra | Credential Access |
| 3 | Reverse shell / C2 beaconing via Netcat (port 4444) | Command & Control |
| 4 | Privilege escalation via new user creation (useradd) | Privilege Escalation |

All attacks were carried out from a **Kali Linux** attacker machine against a **Metasploitable3 (Ubuntu)** victim machine.

---

## Lab Environment

The lab runs entirely in **Oracle VirtualBox** with three virtual machines:

| VM | Role | OS | IP Address |
|----|------|----|------------|
| Splunk Server | SIEM / Log Aggregator | Ubuntu (Splunk Enterprise) | 192.168.122.7 |
| Metasploitable3 | Victim Machine | Ubuntu (Metasploitable3) | 192.168.122.8 |
| Kali Linux | Attacker Machine | Kali Linux | 192.168.122.3 |

**Log collection architecture:**

- Metasploitable3 system logs (`auth.log`, `syslog`) → forwarded to Splunk via **Universal Forwarder** on port 9997
- Network traffic → captured by **Zeek** and forwarded to Splunk as structured `conn.log`, `dns.log`, and `http.log` data
- Splunk indexes all logs and allows real-time searching, alerting, and dashboards

**Splunk configuration files used:**
- `inputs.conf` — defines log sources on the forwarder
- `props.conf` — sets sourcetypes for correct parsing
- `transforms.conf` — handles field extractions and routing

---

## MITRE ATT&CK Mapping

| # | Technique | MITRE ID | Tool Used | Target |
|---|-----------|----------|-----------|--------|
| 1 | Reconnaissance — Network Service Scanning | T1046 | Nmap | Metasploitable3 |
| 2 | Credential Access — Brute Force SSH | T1110.001 | Hydra / Medusa | Metasploitable3 |
| 3 | Command & Control — Non-Standard Port | T1571 | Netcat | Metasploitable3 |
| 4 | Privilege Escalation — Create Account | T1136.001 | sudo useradd | Metasploitable3 |

---

## Attack Scenarios & Detections

### 1. Nmap Reconnaissance Scan

**What was done:** A full Nmap scan (`-sV -sC`) was run from Kali Linux against the Metasploitable3 target to enumerate open ports and running services.

**How it was detected:** Zeek's `conn.log` captured a large volume of short-lived TCP connections from `192.168.122.3` to many different ports on the target in a very short time window — a classic indicator of port scanning behaviour.

**SPL detection:** `index=zeek sourcetype=zeek:conn` filtered by source IP, grouped by destination ports, and thresholded at more than 20 unique ports from a single IP.

**Result:** ✅ Detected — Kali IP flagged as scanning 65,000+ ports.

---

### 2. SSH Brute Force

**What was done:** A brute force attack was launched against the SSH service (port 22) on Metasploitable3 using a wordlist, generating hundreds of failed authentication attempts in `auth.log`.

**How it was detected:** Two detection methods were used:
- **Host-based:** Splunk ingested `auth.log` via Universal Forwarder. SPL query searched for `"Failed password"` and `"authentication failure"`, grouped by source IP and user, and triggered an alert when the count exceeded 5 failures.
- **Network-based:** Zeek `conn.log` showed repeated TCP connections to port 22 from `192.168.122.3`.

**Splunk alert created:** Real-time alert fires when failed logins from a single IP exceed threshold — confirmed triggered in Splunk's Triggered Alerts panel.

**Result:** ✅ Detected — alert triggered, source IP and targeted user identified.

---

### 3. Reverse Shell / C2 Traffic

**What was done:** A Netcat listener was established on the victim machine on port 4444, simulating a reverse shell callback to a C2 server. The connection was held open for an extended duration to simulate active C2 beaconing.

**How it was detected:** Zeek `conn.log` captured the long-lived TCP connection from `192.168.122.8` to port 4444. The SPL query filtered for connections to non-standard ports with duration greater than 10 seconds or outbound bytes exceeding 1,000 — both indicators of interactive shell or beaconing traffic.

**Result:** ✅ Detected — connection flagged with source/destination IPs, port, duration, and byte counts visible in Splunk.

---

### 4. Privilege Escalation — New User Creation

**What was done:** A new user account was created on the victim machine using `sudo useradd`, simulating an attacker establishing persistence through a new privileged account.

**How it was detected:** Splunk ingested `auth.log` and `syslog`. The SPL query searched for keywords `"new user"`, `"new group"`, and `COMMAND=*useradd*` / `COMMAND=*usermod*` in the `linux_secure` sourcetype.

**Dashboard built:** A **Linux Account & Privilege Monitoring** dashboard was created in Splunk to surface account creation and privilege abuse events in real time.

**Result:** ✅ Detected — new user creation event captured with timestamp, host, and user context.

---

## Detection Queries (SPL)

### SSH Brute Force Detection

```spl
index=main sourcetype=linux_secure "Failed password" OR "authentication failure"
| stats count by src_ip user
| where count > 5
| sort -count
```

Triggers on high failed login attempts from the same IP/user combination.

---

### New User / Privilege Escalation Detection

```spl
index=main sourcetype=linux_secure ("new user" OR "new group" OR "COMMAND=*useradd*" OR "COMMAND=*usermod*")
| table _time host user _raw
| sort -_time
```

Detects suspicious account creation or privilege modification via sudo.

---

### Reverse Shell / C2 Traffic Detection (Zeek)

```spl
index=zeek sourcetype=zeek:conn id_orig_h=192.168.122.8 id_resp_p=4444
| table _time id_orig_h id_orig_p id_resp_h id_resp_p proto service duration orig_bytes resp_bytes conn_state
| where duration > 10 OR orig_bytes > 1000
```

Identifies long-lived outbound TCP connections to non-standard ports, indicative of reverse shell or C2 beaconing.

---

### Nmap Scan Detection (Zeek)

```spl
index=zeek sourcetype=zeek:conn id_orig_h=192.168.122.3
| stats count values(id_resp_p) as scanned_ports by id_orig_h id_resp_h
| where count > 20
| sort -count
```

Flags any IP scanning more than 20 unique destination ports — a strong indicator of automated reconnaissance.

---

## Remediation Summary

| Attack | Remediation Steps |
|--------|-------------------|
| **Nmap Reconnaissance** | Deploy a firewall (e.g. `ufw`) to restrict exposed ports. Only expose services that are necessary. Use port knocking or VPN for admin access. |
| **SSH Brute Force** | Install and configure `fail2ban` to auto-ban IPs after repeated failures. Enforce SSH key-based authentication only and disable password login (`PasswordAuthentication no` in `sshd_config`). Apply account lockout policies. |
| **Reverse Shell / C2** | Block non-standard outbound ports at the firewall level. Monitor for unusual long-lived connections using Zeek and Splunk. Use application allowlisting to restrict execution of tools like `nc`. |
| **Privilege Escalation — New User** | Restrict `sudo` access to named commands only via `/etc/sudoers`. Alert on all new user or group creation events in real time. Regularly audit user accounts with `getent passwd`. |

---

## Key Findings

- **Zeek's `conn.log` is extremely effective** for network-based detections — it captured the Nmap scan, SSH brute force patterns, and the reverse shell connection without any agent on the attacker machine.
- **Splunk Universal Forwarder** successfully shipped `auth.log` events in near real time, enabling host-based detection of the brute force and privilege escalation within seconds of the event.
- **Alert tuning matters** — the SSH brute force alert required a threshold of more than 5 failed attempts rather than 1, to avoid false positives from legitimate mistyped passwords.
- **`props.conf` and `transforms.conf` configuration** is critical for correct log parsing in Splunk. Incorrect sourcetype assignments caused early ingestion failures that required systematic troubleshooting to resolve.
- **Baseline traffic collection** before attacks was valuable — comparing normal Zeek conn.log volume against attack traffic made anomalies clearly visible.
- All 4 attack techniques were **successfully detected** using a combination of host-based (Splunk + Universal Forwarder) and network-based (Zeek) telemetry.

---

## Lessons Learned

**Log forwarding and parsing:**
Configuring the Universal Forwarder and receiving port correctly was the most technically challenging part of the project. Small mismatches in `props.conf` sourcetype names caused silent ingestion failures. The lesson: always verify data is arriving in Splunk before running detections.

**Zeek as a network layer:**
Zeek's `conn.log` proved to be a powerful complement to host-based logs. It provided network-level evidence of the Nmap scan and reverse shell even without any logs from the attacker machine itself — demonstrating why network visibility is essential in a real SOC.

**Detection thresholds:**
Writing effective SPL queries requires understanding what normal looks like. The SSH brute force query initially produced too many false positives until a count threshold was applied.

**Documentation discipline:**
Keeping notes on every step — including failed attempts and configurations — helped build this report and will be valuable in a real SOC analyst role where ticket and investigation documentation is essential.

**Patience and systematic troubleshooting:**
When things broke (log parsing failures, misconfigured inputs, Zeek conn.log not appearing in Splunk), stepping back and fixing one variable at a time led to the solution every time. This mindset is as important as technical skill.

---

## Conclusion

This project demonstrates a practical, end-to-end SIEM workflow — from lab setup through attack simulation, log ingestion, detection engineering, alerting, and dashboard creation — using entirely open-source tools in an isolated VirtualBox environment.

The combination of **Splunk** for log aggregation and alerting, and **Zeek** for network-level visibility, mirrors the kind of dual-layer telemetry used in real SOC environments. Every attack technique was successfully detected, and the experience of building detections from scratch — rather than using pre-built rules — gave genuine insight into how attackers can evade poorly tuned detection logic.

This lab directly supports skills relevant to **SOC Analyst**, **Detection Engineer**, and **Threat Hunter** roles.

---

> **Disclaimer:** This lab is built entirely in an isolated VirtualBox environment for educational purposes only. All attack techniques were simulated against machines I own and control. No real systems or data were involved.
