# SOC Incident Report: Multi-Vector Authentication Attack

> Simulated multi-vector authentication attack detected and investigated using Splunk SIEM with cross-platform correlation (Linux, Windows, VPN).

---

## Incident Overview

**Severity:** High  
**Status:** Investigated & Contained  
**Analyst:** Tejinder Singh  
**Environment:** Linux, Windows, pfSense (OpenVPN), Splunk SIEM  

---

## Attack Description

This project simulates a **multi-stage, credential-based attack campaign** originating from a single threat actor (**192.168.1.60**) targeting multiple authentication services across the environment.

The attacker systematically attempted to gain unauthorized access using:

- SSH brute force attacks against Linux systems  
- Password spraying across multiple user accounts  
- RDP brute force attacks targeting Windows endpoints  
- VPN authentication abuse via OpenVPN  

---

## Attack Behavior Pattern

The attack follows a realistic intrusion sequence:

1. Initial access attempts via exposed services (SSH, RDP, VPN)  
2. Credential harvesting through brute force and password spraying  
3. Successful authentication following repeated failures  
4. Potential lateral movement using compromised credentials  

---

## Real-World Relevance

This attack pattern closely resembles real-world scenarios observed in:

- Ransomware initial access campaigns  
- Credential stuffing operations  
- Internal network compromise attempts  

---

## SOC Investigation Methodology

### Step 1 — Detection Trigger
- Alerts were triggered based on abnormal authentication activity  
- High volumes of failed login attempts were observed across multiple systems  

---

### Step 2 — Identify Source of Activity
- Extracted source IP addresses from logs  
- Identified attacker IP: **192.168.1.60**

---

### Step 3 — Cross-Source Correlation

Correlated attacker activity across:

- Linux logs (`/var/log/auth.log`)  
- Windows Security logs (Event ID **4625 / 4624**)  
- pfSense / OpenVPN logs  

---

### Step 4 — Analyze Authentication Behavior
- Multiple failed attempts across different user accounts  
- Password spray pattern identified  
- Successful authentication observed after repeated failures  

---

### Step 5 — Timeline Reconstruction

| Stage | Activity |
|------|----------|
| 1 | SSH brute force attempts |
| 2 | Password spraying across users |
| 3 | RDP authentication failures |
| 4 | Successful login (Event ID 4624) |
| 5 | VPN authentication abuse |

---

### Analyst Insight

This behavior indicates:

- Use of automated attack tools (e.g., Hydra or similar scripts)  
- A credential harvesting strategy  
- An early-stage intrusion attempt  

---

## Response Actions (SOC Playbook)

### Immediate Containment
- Blocked attacker IP (**192.168.1.60**) at the firewall  
- Disabled targeted or potentially compromised accounts  

---

### Remediation
- Enforced strong password policies  
- Implemented account lockout thresholds  
- Enabled multi-factor authentication (MFA) for VPN and RDP access  

---

### Further Investigation
- Checked for signs of lateral movement  
- Reviewed privileged account activity  
- Investigated potential persistence mechanisms  

---

### Detection Improvements
- Implement geo-location anomaly detection  
- Establish behavioral baselines per user  
- Tune detection thresholds based on environment-specific activity  

---

## Incident Severity

-> Classified as **HIGH severity incident**

**Justification:**
- Multi-system targeting  
- High likelihood of credential compromise  
- Successful authentication observed  

---

## False Positives & Detection Tuning

### Possible False Positives
- IT administrators performing bulk authentication tasks  
- Vulnerability scanners generating repeated login attempts  
- Misconfigured services retrying authentication  

---

### Tuning Strategies
- Whitelist trusted internal IP ranges  
- Adjust thresholds based on system baselines  
- Correlate failed and successful authentication events  

---

## Detection Engineering Insights

- Time-based aggregation significantly improves detection accuracy  
- Single-source alerts are insufficient without correlation  
- Combining **failed and successful login patterns** increases detection confidence  
- Multi-system visibility is critical for identifying coordinated attacks  

---

## Key Indicators of Compromise (IOCs)

- Attacker IP: **192.168.1.60**  
- Multiple failed authentication attempts across SSH, RDP, and VPN  
- Successful login after repeated failures  
- Targeted privileged accounts (e.g., Administrator)  

---

## Lessons Learned

- Credential-based attacks often span multiple systems  
- Cross-source correlation is essential for effective SOC visibility  
- Detection tuning is required to balance noise and accuracy  
- Centralized SIEM solutions enable faster and more effective incident response  

---

## SOC Analyst Summary

This project demonstrates a realistic SOC investigation involving a coordinated credential-based attack across multiple systems.

Using SIEM-based detection and cross-source correlation, a single threat actor was identified and tracked across Linux, Windows, and VPN environments.

### Key Takeaways:

- Centralized logging enables comprehensive visibility  
- Detection engineering improves alert accuracy  
- Cross-platform correlation is critical in modern SOC environments  
- Structured incident response reduces risk and response time  

---
