"""
Gen-AI Threat Synthesizer & SOC Playbook Generator
Generates natural language incident intelligence briefs, MITRE ATT&CK mapping, and remediation playbooks.
"""
from typing import Dict, Any, List


MITRE_MAPPINGS = {
    "sql_injection": {
        "tactic": "Initial Access / Exploitation",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "kill_chain_stage": "Exploitation"
    },
    "impossible_travel": {
        "tactic": "Defense Evasion / Initial Access",
        "technique_id": "T1078.004",
        "technique_name": "Valid Accounts: Cloud Accounts",
        "kill_chain_stage": "Credential Abuse"
    },
    "brute_force": {
        "tactic": "Credential Access",
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "kill_chain_stage": "Credential Access"
    },
    "port_scan": {
        "tactic": "Discovery",
        "technique_id": "T1046",
        "technique_name": "Network Service Discovery",
        "kill_chain_stage": "Reconnaissance"
    },
    "privilege_escalation": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1068",
        "technique_name": "Exploitation for Privilege Escalation",
        "kill_chain_stage": "Privilege Escalation"
    },
    "data_exfiltration": {
        "tactic": "Exfiltration",
        "technique_id": "T1048.003",
        "technique_name": "Exfiltration Over Alternative Protocol",
        "kill_chain_stage": "Actions on Objectives"
    },
    "benign": {
        "tactic": "Normal Operations",
        "technique_id": "N/A",
        "technique_name": "Authorized Operational Workload",
        "kill_chain_stage": "Baseline Telemetry"
    }
}


def synthesize_threat_intelligence(
    alert: Dict[str, Any],
    risk_level: str,
    explainability: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Synthesize natural language incident brief, MITRE ATT&CK taxonomy, and SOC response playbook.
    """
    alert_name = alert.get("alert_name") or alert.get("title") or "Security Alert"
    source_ip = alert.get("source_ip") or alert.get("ip") or "Unknown IP"
    username = alert.get("username") or alert.get("user") or "System"
    resource = alert.get("resource") or alert.get("endpoint") or "API Gateway"
    attack_type = alert.get("attack_type", "").lower()
    payload = alert.get("payload") or alert.get("sensitive_payload") or ""

    # 1. Determine MITRE Technique
    if "sql" in attack_type or "sql" in alert_name.lower() or "select" in str(payload).lower():
        mitre = MITRE_MAPPINGS["sql_injection"]
        threat_profile = "External Web Application Attacker / Database Enumerator"
    elif "travel" in attack_type or "travel" in alert_name.lower() or alert.get("impossible_travel_speed_kmh", 0) > 400:
        mitre = MITRE_MAPPINGS["impossible_travel"]
        threat_profile = "Compromised Credentials / Session Token Hijacker"
    elif "brute" in attack_type or "failed" in alert_name.lower() or alert.get("failed_login_count", 0) >= 5:
        mitre = MITRE_MAPPINGS["brute_force"]
        threat_profile = "Automated Credential Stuffing Botnet"
    elif "scan" in attack_type or "port" in alert_name.lower() or alert.get("port_scan_distinct_ports", 0) >= 10:
        mitre = MITRE_MAPPINGS["port_scan"]
        threat_profile = "Network Reconnaissance Probe"
    elif "privilege" in attack_type or alert.get("privilege_escalation") is True:
        mitre = MITRE_MAPPINGS["privilege_escalation"]
        threat_profile = "Adversary Seeking Administrative Persistence"
    elif alert.get("outbound_bytes_mb", 0) > 10 or "exfil" in attack_type:
        mitre = MITRE_MAPPINGS["data_exfiltration"]
        threat_profile = "Active Threat Actor performing Data Exfiltration"
    else:
        mitre = MITRE_MAPPINGS["benign"]
        threat_profile = "Routine Internal Infrastructure / Automated CI Probe"

    # 2. Executive Incident Summary
    if risk_level == "High":
        executive_summary = (
            f"CRITICAL INCIDENT DETECTED: A high-severity security anomaly was triggered on {resource} by identity '{username}' "
            f"from source {source_ip}. Telemetry indicates active {mitre['technique_name']} ({mitre['technique_id']}) within "
            f"the {mitre['kill_chain_stage']} stage. The attack vector exhibits strong markers of malicious intent with elevated "
            f"anomaly confidence. Immediate defensive containment is strongly advised."
        )
        blast_radius = "High - Potential compromise of backend payment databases or privileged credentials."
        action_priority = "P1 - CRITICAL (15-minute SLA)"
        playbook = [
            f"1. [CONTAINMENT] Isolate source entity {source_ip} via edge firewall rule and revoke active JWT tokens for user '{username}'.",
            f"2. [FORENSICS] Capture memory dump and container snapshot of target resource '{resource}'.",
            f"3. [AUDIT] Check database access logs for queries matching payload signatures during the last 60 minutes.",
            f"4. [ERADICATION] Force global password & MFA reset for account '{username}'.",
            f"5. [NOTIFICATION] Escalate incident ticket to Lead Incident Commander and Legal/Compliance if PII was exposed."
        ]
    elif risk_level == "Medium":
        executive_summary = (
            f"ELEVATED THREAT DETECTED: Suspicious activity observed targeting {resource} from {source_ip}. "
            f"Pattern aligns with {mitre['technique_name']} ({mitre['technique_id']}). Anomaly scores suggest automated scanning "
            f"or unauthorized credential testing."
        )
        blast_radius = "Medium - Limited to perimeter reconnaissance or rate-limited authentication failures."
        action_priority = "P2 - HIGH (2-hour SLA)"
        playbook = [
            f"1. [MONITOR] Place temporary rate limit (5 req/min) on IP {source_ip}.",
            f"2. [VERIFY] Contact user '{username}' via out-of-band communication (Slack/SMS) to verify login authenticity.",
            f"3. [AUDIT] Correlate with concurrent alerts in SIEM for IP {source_ip} over a 4-hour window.",
            f"4. [CLOSE/ESCALATE] Escalate to High if repeated failures continue past threshold."
        ]
    else:
        executive_summary = (
            f"INFORMATIONAL / BENIGN: Routine event on {resource}. The event parameters match standard fintech baseline operations. "
            f"No unauthorized escalation or data loss observed."
        )
        blast_radius = "Low - Zero operational or compliance impact."
        action_priority = "P4 - INFORMATIONAL (No SLA breach)"
        playbook = [
            "1. [LOG] Retain alert in telemetry store for 90 days baseline training.",
            "2. [CLOSE] Auto-resolve alert as Benign Baseline."
        ]

    return {
        "executive_summary": executive_summary,
        "threat_actor_profile": threat_profile,
        "mitre_attack": mitre,
        "blast_radius_assessment": blast_radius,
        "action_priority": action_priority,
        "remediation_playbook": playbook,
        "synthesized_by": "ThreatSynth Gen-AI Reasoning Engine v1.0"
    }
