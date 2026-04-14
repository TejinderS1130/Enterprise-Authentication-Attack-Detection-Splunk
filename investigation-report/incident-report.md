# Incident Report

## Incident Summary
A coordinated authentication-based attack was detected originating from IP 192.168.1.60, targeting multiple services including SSH, RDP, and VPN.

## Affected Systems
- Ubuntu Server (SSH)
- Windows Endpoint (RDP)
- OpenVPN Service (pfSense)

## Indicators of Compromise (IOCs)
- Source IP: 192.168.1.60
- High volume of failed authentication attempts
- Multiple accounts targeted
- Cross-system login attempts

## Attack Techniques
- Brute Force (T1110)
- Password Spraying (T1110.003)
- Valid Accounts (T1078)

## Findings
The attacker attempted to gain access through multiple entry points, indicating a coordinated credential-based attack strategy.

## Actions Taken
- Identified attacker IP
- Correlated activity across systems
- Triggered alerts for abnormal behavior

## Recommendations
- Implement account lockout policies
- Enforce MFA across services
- Monitor cross-system authentication patterns
