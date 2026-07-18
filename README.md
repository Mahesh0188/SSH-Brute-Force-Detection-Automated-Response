# SSH-Brute-Force-Detection-Automated-Response
Detects SSH brute force attacks, analyzes source IP reputation with VirusTotal, and automatically blocks malicious IPs using Wazuh-driven incident response.

A Python-based Security Operations Center (SOC) automation project that integrates with Wazuh SIEM to detect SSH brute-force attacks, enrich alerts with VirusTotal threat intelligence, automate incident response, create Jira tickets, and contain malicious attackers by automatically blocking their IP addresses.

---

Project Overview

Security Operations Centers (SOCs) generate a large volume of security alerts that require rapid investigation and response. Manual analysis can increase response time and allow attackers to continue malicious activities.

This project automates the incident response lifecycle for SSH brute-force attacks by continuously monitoring Wazuh alerts, validating attacker reputation using VirusTotal, calculating attack risk, automatically blocking malicious IP addresses through iptables, and generating Jira incident tickets for tracking and documentation.

The objective is to demonstrate practical SOC automation by integrating SIEM monitoring, threat intelligence, automated containment, and incident management into a unified security workflow.

---

Key Features

- Real-time monitoring of Wazuh security alerts
- Automated SSH brute-force attack detection
- Continuous monitoring of Wazuh alert logs
- Automatic extraction of attacker source IP addresses
- VirusTotal IP reputation lookup
- Dynamic risk assessment based on SIEM severity and threat intelligence
- Automatic malicious IP blocking using iptables
- Jira incident ticket creation and management
- MITRE ATT&CK technique mapping
- Duplicate incident prevention
- Real-time SOC incident response console
- Structured incident logging

---

Architecture

Attacker
    │
    ▼
Target Linux Machine
    │
    ▼
Wazuh Agent
    │
    ▼
Wazuh Manager (SIEM)
    │
    ▼
SOC Automation Platform (Python)
    │
    ├── Monitor Security Alerts
    ├── Detect SSH Brute Force
    ├── Extract Source IP
    ├── Query VirusTotal
    ├── Calculate Risk Score
    ├── Create Jira Incident
    ├── Block Malicious IP
    └── Log Incident Details

---

Technologies Used

- Python 3
- Wazuh SIEM
- Ubuntu Linux
- Kali linux 
- VirusTotal API
- Jira REST API
- iptables Firewall
- JSON Log Processing
- MITRE ATT&CK Framework
- GitHub

---

Detection Workflow

1. Continuously monitor Wazuh security alerts.
2. Detect SSH brute-force attacks using Wazuh detection rules.
3. Extract the attacker source IP address.
4. Query VirusTotal for IP reputation.
5. Calculate attack risk using Wazuh severity and VirusTotal results.
6. Automatically create a Jira incident ticket.
7. Automatically block malicious IP addresses using iptables.
8. Record the incident and continue monitoring for future attacks.

---

Automated Incident Response

When an SSH brute-force attack is detected, the platform automatically:

- Identifies the attack using Wazuh alerts
- Enriches the alert with VirusTotal threat intelligence
- Calculates the attack risk level
- Creates a Jira incident ticket
- Blocks the malicious source IP using iptables
- Prevents duplicate incident handling
- Records the incident for auditing and investigation

---

MITRE ATT&CK Mapping

Attack| Technique| Tactic
SSH Brute Force| T1110 – Brute Force| Credential Access

---

Incident Information Displayed

The real-time incident response console displays:

- Alert Count
- Attack Type
- Source IP Address
- Victim Host
- Wazuh Rule ID
- Wazuh Severity Level
- VirusTotal Analysis
- Risk Level
- Incident Status
- Containment Status

---

Project Structure

SOC-Automation-Platform/
│
├── autobrutedefense.py
├── README.md
├── requirements.txt
├── LICENSE
└── screenshots/

---

Installation

Clone the repository:

git clone https://github.com/<your-username>/SOC-Automation-Platform.git

Install the required dependencies:

pip install -r requirements.txt

Configure the following before execution:

- Wazuh Manager
- VirusTotal API Key
- Jira API Credentials

Run the application:

python3 autobrutedefense.py

---

Skills Demonstrated

- Security Operations Center (SOC) Operations
- Incident Detection and Response
- SIEM Monitoring and Alert Analysis
- Security Automation
- Threat Intelligence Integration
- Linux Administration
- Python Automation
- Firewall Management
- MITRE ATT&CK Framework
- REST API Integration
- Log Analysis
- Incident Management

---

License

This project is licensed under the MIT License.

---

Author:

Uma Maheswar Karri

SOC Automation | Blue Team | Python | Wazuh | Threat Intelligence | Incident Response
