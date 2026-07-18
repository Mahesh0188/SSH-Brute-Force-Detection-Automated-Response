import os
import json
import time
import subprocess
import ipaddress
import requests

from requests.auth import HTTPBasicAuth



EMAIL = "xxxxxxx@xxx.com"
# VICTIM DETAILS
VICTIM_USER = "xxxxxxxx"
VICTIM_IP = "xxx.xxx.xx.xx"
SSH_TARGET = f"{VICTIM_USER}@{VICTIM_IP}"

JIRA_API_TOKEN = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

JIRA_URL = "https://xxxxxxxxxxxx.atlassian.net/rest/api/3/issue"

PROJECT_KEY = "KAN"

auth = HTTPBasicAuth(
    EMAIL,
    JIRA_API_TOKEN
)
HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}


VT_API_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

VT_HEADERS = {
    "x-apikey": VT_API_KEY
}


ALERT_FILE = "/var/ossec/logs/alerts/alerts.json"



# Never block these IPs
ALLOWLIST = [
    "127.0.0.1",
    "::1"
]

# Wazuh level required for automatic containment
AUTO_BLOCK_LEVEL = 10

# VirusTotal malicious engine threshold
HIGH_RISK_THRESHOLD = 5


# Tracks an entire attack per source IP
incident_memory = {}

# Remember last processed alert position
last_position = 0

# SSH_RULES
SSH_RULES = {

    "5760",  # SSH authentication failed

    "5763",  # SSH brute force trying to get access to the system. Authentication failed

}



def monitor_alerts():

    global last_position

    try:

        with open(ALERT_FILE, "r") as f:

            # Start from end of file so old alerts are ignored
            f.seek(0, 2)

            last_position = f.tell()

            print("Waiting for Wazuh alerts...\n")

            while True:

                f.seek(last_position)

                line = f.readline()

                if not line:

                    time.sleep(1)
                    continue

                last_position = f.tell()

                try:

                    alert = json.loads(line)

                    process_alert(alert)

                except json.JSONDecodeError:

                    continue

    except FileNotFoundError:

        print("alerts.json not found.")

    except PermissionError:

        print("Permission denied.")
        print("Run using sudo.")



def process_alert(alert):

    info = extract_alert_data(alert)

    # Ignore non-SSH rules
    if info["rule_id"] not in SSH_RULES:
        return

    ip = info["ip"]

    if ip == "Unknown":
        return

    if ip not in incident_memory:

        incident_memory[ip] = {

            "attempts": 0,

            "highest_level": 0,

            "rule_path": [],

            "highest_rule": "",

            "highest_severity": "LOW",
            
            "confirmed": False,

            "blocked": False,

            "jira_created": False,
            
            "jira_key": "",

            "first_seen": info["timestamp"],

            "last_seen": info["timestamp"]

        }
    incident = incident_memory[ip]

    incident["attempts"] += 1

    incident["highest_level"] = max(
        incident["highest_level"],
        info["level"]
    )

    incident["last_seen"] = info["timestamp"]



    if (
        not incident["rule_path"]
        or incident["rule_path"][-1] != info["rule_id"]
    ):
        incident["rule_path"].append(info["rule_id"])

    # Highest Rule Reached

    if info["level"] >= incident["highest_level"]:
        incident["highest_rule"] = info["rule_id"]

    # Confirmed Brute Force

    if info["rule_id"] == "5763":
        incident["confirmed"] = True


    malicious, suspicious = check_virustotal(ip)


    risk = calculate_risk(
        info,
        malicious,
        suspicious
    )

    severity_rank = {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4
    }

    if (
        severity_rank[risk["severity"]]
        > severity_rank[incident["highest_severity"]]
    ):
        incident["highest_severity"] = risk["severity"]


    handle_response(
        info,
        risk,
        malicious,
        suspicious
    )


    draw_dashboard(
        info,
        risk,
        malicious,
        suspicious
    )


ATTACK_MAP = {

    
    "5760": (
        "SSH Authentication Failure",
        "T1110",
        "Credential Access"
    ),


    "5763": (
        "SSH Brute Force Detected",
        "T1110",
        "Credential Access"
    ),

}


def identify_attack(rule_id):

    if rule_id in ATTACK_MAP:

        return ATTACK_MAP[rule_id]

    return (
        "Unknown Alert",
        "N/A",
        "Unknown"
    )
def extract_alert_data(alert):

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    data = alert.get("data", {})

    attack_name, mitre_id, mitre_stage = identify_attack(
	str(rule.get("id", "")),
	)

    return {

        "rule_id": str(rule.get("id", "UNKNOWN")),

        "description": rule.get(
            "description",
            "No description"
        ),

        "level": int(rule.get("level", 0)),

        "timestamp": alert.get(
            "timestamp",
            "Unknown"
        ),

        "agent": agent.get(
            "name",
            "Unknown-Agent"
        ),

        "ip": (
            data.get("srcip")
            or data.get("src_ip")
            or data.get("srcipv4")
            or "Unknown"
        ),

        "attack": attack_name,
        "mitre": mitre_id,
        "stage":mitre_stage
        
    }




def check_virustotal(ip):

    if ip == "Unknown":
        return 0, 0

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"

    try:

        response = requests.get(
            url,
            headers=VT_HEADERS,
            timeout=10
        )

        if response.status_code != 200:
            print("VirusTotal lookup failed.")
            return 0, 0

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        return malicious, suspicious

    except requests.RequestException as e:

        print("VirusTotal Error:", e)

        return 0, 0


def calculate_risk(info, malicious, suspicious):

    severity = "LOW"
    action = "Monitor"
    block = False

    if info["rule_id"] == "5763":

        severity = "HIGH"
        action = "Automatic IP Block"
        block = True


    if malicious >= HIGH_RISK_THRESHOLD:

        severity = "CRITICAL"
        action = "Automatic IP Block"
        block = True

    elif suspicious > 0 and severity == "LOW":

        severity = "MEDIUM"
        action = "Monitor Closely"

    return {

        "severity": severity,
        "action": action,
        "block": block

    }


RESET  = "\033[0m"
BOLD   = "\033[1m"

RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"


def severity_color(level):

    if level == "LOW":
        return GREEN

    elif level == "MEDIUM":
        return YELLOW

    elif level == "HIGH":
        return RED

    elif level == "CRITICAL":
        return RED + BOLD

    return RESET


def vt_status(malicious, suspicious):

    if malicious > 0:
        return f"{RED}Malicious ({malicious}){RESET}"

    if suspicious > 0:
        return f"{YELLOW}Suspicious ({suspicious}){RESET}"

    return f"{GREEN}Clean{RESET}"



def draw_dashboard(info, risk, malicious, suspicious):

    os.system("clear")

    incident = incident_memory.get(info["ip"], {})

    alerts = incident.get("attempts", 1)

    severity = incident.get(
        "highest_severity",
        risk["severity"]
    )

    colour = severity_color(severity)



    path = incident.get("rule_path", [])

    display_path = []

    for rule in path:

        if rule not in display_path:
            display_path.append(rule)

        if rule == "5763":
            break

    if len(display_path) == 1:

        rule_progress = display_path[0]

    else:

        rule_progress = (
            f"{display_path[0]} -> "
            f"{RED}{BOLD}{display_path[-1]} ✓{RESET}"
        )

# STATUS

    if incident.get("blocked"):

        status = f"{GREEN} THREAT CONTAINED{RESET}"

    elif severity in ("HIGH", "CRITICAL"):

        status = f"{RED}ACTIVE ATTACK{RESET}"

    elif severity == "MEDIUM":

        status = f"{YELLOW}UNDER MONITORING{RESET}"

    else:

        status = f"{GREEN}MONITORING{RESET}"

    print(f"{CYAN}{BOLD}")
    print("-------------------------------------------------")
    print("           SOC AUTOMATION PLATFORM ")
    print("      Real-Time Incident Response Console "       )
    print("-------------------------------------------------")
    print(RESET)

    print(f"Status          : {status}")
    print()

    print("---------------- ACTIVE INCIDENT ----------------")

    print(f"Alerts Seen     : {alerts}")

    print(f"Attack          : {info['attack']}")

    print(f"Rule Progress   : {rule_progress}")

    print(f"Highest Level   : {incident.get('highest_level', info['level'])}")

    print()

    print(f"Source IP       : {info['ip']}")

    print(f"Victim Host     : {info['agent']}")

    print(f"Victim IP       : {VICTIM_IP}")

    print()

    print(f"VirusTotal      : {vt_status(malicious, suspicious)}")

    print(f"Severity        : {colour}{severity}{RESET}")

    if incident.get("blocked"):

        action = f"{GREEN}Contained Automatically{RESET}"

    elif risk["block"]:

        action = f"{RED}Automatic IP Block{RESET}"

    elif risk["severity"] == "MEDIUM":

        action = f"{YELLOW}Monitor Closely{RESET}"

    else:

        action = f"{GREEN}Monitor{RESET}"

    print(f"Action          : {action}")

    print()

    if incident.get("blocked"):

        print(f"Containment     : {GREEN}SUCCESS{RESET}")

    else:

        print("Containment     : Pending")

    if incident.get("jira_created"):

        print(
             f"Jira            : "
             f"{GREEN}{incident.get('jira_key')} (CREATED)  {RESET}"
        )

    else:

        print("Jira            : Waiting")

    print()

    print(f"Last Update     : {incident.get('last_seen')}")

    print("======================================================")




def block_ip(ip):
    if ip == "Unknown":
        return False

    try:
        ipaddress.ip_address(ip)
    except ValueError:
        print(f"[ERROR] Invalid IP: {ip}")
        return False

    if ip in ALLOWLIST:
        print(f"[INFO] {ip} is allowlisted.")
        return False

    try:
        # Check if already blocked
        exists = subprocess.run(
            [
                "ssh",
                SSH_TARGET,
                "sudo",
                "iptables",
                "-C",
                "INPUT",
                "-s",
                ip,
                "-j",
                "DROP"
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        if exists.returncode == 0:
            print(f"[INFO] {ip} already blocked on Victim.")
            return True

        # Add DROP rule
        subprocess.run(
            [
                "ssh",
                SSH_TARGET,
                "sudo",
                "iptables",
                "-I",
                "INPUT",
                "1",
                "-s",
                ip,
                "-j",
                "DROP"
            ],
            check=True
        )

        # Verify rule
        verify = subprocess.run(
            [
                "ssh",
                SSH_TARGET,
                "sudo",
                "iptables",
                "-L",
                "INPUT",
                "-n"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        if any(ip in line and "DROP" in line for line in verify.stdout.splitlines()):
            print(f"[SUCCESS] {ip} successfully blocked on Victim.")
            return True

        print(f"[ERROR] Could not verify blocking of {ip} on Victim.")
        return False

    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Remote firewall operation failed: {e}")
        return False


def create_jira_ticket(info, malicious, suspicious, risk, block_success):

    incident = incident_memory.get(info["ip"])

    if incident is None : 
        return
    # Ticket already created for this incident
    if incident["jira_created"]:
        return

    if risk["block"]:

        if block_success:

            resolution = "Resolved by Automation"
            priority = "Medium"

            summary = "SSH Brute Force Automatically Contained"

            action_taken = (
                f"Source IP {info['ip']} was automatically blocked.\n"
                "Containment verified successfully."
            )

        else:

            resolution = "Manual Response Required"
            priority = "Highest"

            summary = "Automatic Containment Failed"

            action_taken = (
                f"Automatic IP block failed for {info['ip']}.\n"
                "Immediate SOC analyst intervention required."
            )

    else:

        resolution = "Monitoring"

        priority = "Low"

        summary = "Repeated SSH Authentication Failures"

        action_taken = (
            "Authentication failures detected.\n"
            "Monitoring continues until escalation threshold is reached."
        )

    payload = {
        "fields": {
            "project": {
                "key": PROJECT_KEY
            },
            "summary": summary,
            "issuetype": {
                "name": "Task"
            },
            "priority": {
                "name": priority
            },
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [
                            {
                                "type": "text",
                                "text":
                                    f"Attack: {info['attack']}\n"
                                    f"Source IP: {info['ip']}\n"
                                    f"Victim Host: {VICTIM_USER}\n"
                                    f"Victim IP: {VICTIM_IP}\n"
                                    f"Wazuh Rule: {info['rule_id']}\n"
                                    f"Wazuh Level: {info['level']}\n"
                                    f"VirusTotal Malicious: {malicious}\n"
                                    f"VirusTotal Suspicious: {suspicious}\n\n"
                                    f"Resolution: {resolution}\n\n"
                                    f"{action_taken}"
                            }
                        ]
                    }
                ]
            }
        }
    }

    response = requests.post(
        JIRA_URL,
        json=payload,
        headers=HEADERS,
        auth=auth
    )

    if response.status_code == 201:

        ticket = response.json()

        issue_key = ticket["key"]

        print(
            f"{GREEN}[JIRA]{RESET} Ticket Created : {issue_key}"
        )

        if incident:

            incident["jira_created"] = True

            incident["jira_key"] = issue_key

    else:

        print(f"{RED}[JIRA ERROR]{RESET} HTTP {response.status_code}")

        print(response.text)

        if incident:

            incident["jira_created"] = False

            incident["jira_key"] = ""
        


def handle_response(info, risk, malicious, suspicious):

    ip = info["ip"]

    if ip == "Unknown":
        return

    incident = incident_memory[ip]

    if incident["blocked"]:
        return


    if risk["block"]:

        print("\nAttempting IP Block from Victim...")

        success = block_ip(ip)

        if success:

            incident["blocked"] = True
            
            create_jira_ticket(
                info,
                malicious,
                suspicious,
                risk,
                True
            )

            print(f"{GREEN}[SUCCESS]{RESET} Containment Successful")

            # jira_ticket(info, risk)

        else:
             create_jira_ticket(
                info,
                malicious,
                suspicious,
                risk,
                False
             )

             print(f"{RED}[FAILED]{RESET} Automatic Containment Failed")
             print("Manual SOC investigation required.")

        return


    if risk["severity"] == "MEDIUM":
             create_jira_ticket(
                info,
                malicious,
                suspicious,
                risk,
                False
            )

    return



def main():

    print("\n======================================")
    print("     SSH-BRUTE FORCE ATTACK-DEFENDER    ")
    print("======================================")
    print("Monitoring Wazuh alerts...\n")

    monitor_alerts()


if __name__ == "__main__":

    main()