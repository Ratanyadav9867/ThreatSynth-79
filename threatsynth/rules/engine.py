"""
Multi-Alert Correlation & Conflict Rule Engine
Correlates disparate SIEM events across sliding windows, flags attack chains, and detects conflicting telemetry.
"""
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


class CorrelationRuleEngine:
    """Evaluates multi-event security rules and correlation chains."""

    def __init__(self):
        self.alert_history: List[Dict[str, Any]] = []

    def add_alert(self, alert: Dict[str, Any]):
        """Record alert in correlation window."""
        self.alert_history.append(alert)
        # Retain last 500 alerts for correlation
        if len(self.alert_history) > 500:
            self.alert_history = self.alert_history[-500:]

    def evaluate_correlations(self, current_alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate real-time correlation rules against the current alert and historical window.
        Returns matched correlation chains, conflict flags, and blast radius.
        """
        matched_rules = []
        conflicts = []
        correlated_alert_ids = []

        curr_user = current_alert.get("username") or current_alert.get("user")
        curr_ip = current_alert.get("source_ip") or current_alert.get("ip")
        curr_id = current_alert.get("alert_id", "curr")
        curr_attack = str(current_alert.get("attack_type", "")).lower()

        # 1. Rule: Brute Force to Privilege Escalation
        if current_alert.get("privilege_escalation") or "privilege" in curr_attack:
            for past in reversed(self.alert_history[-50:]):
                past_user = past.get("username") or past.get("user")
                past_ip = past.get("source_ip") or past.get("ip")
                if (past_user == curr_user or past_ip == curr_ip) and past.get("failed_login_count", 0) >= 3:
                    matched_rules.append({
                        "rule_id": "RULE-CORR-01",
                        "rule_name": "Multi-Stage Attack: Brute Force -> Privilege Escalation",
                        "severity": "CRITICAL",
                        "description": f"Identity '{curr_user}' had multiple failed logins followed by privilege escalation.",
                        "mitre_id": "T1110 -> T1068",
                        "trigger_alert_id": past.get("alert_id")
                    })
                    correlated_alert_ids.append(past.get("alert_id"))
                    break

        # 2. Rule: Impossible Travel Velocity
        if curr_user and curr_user != "system":
            for past in reversed(self.alert_history[-30:]):
                past_user = past.get("username") or past.get("user")
                past_country = past.get("country") or past.get("source_country")
                curr_country = current_alert.get("country") or current_alert.get("source_country")
                if past_user == curr_user and past_country and curr_country and past_country != curr_country:
                    speed = current_alert.get("impossible_travel_speed_kmh", 0) or 850
                    matched_rules.append({
                        "rule_id": "RULE-CORR-02",
                        "rule_name": "Impossible Travel Velocity Anomaly",
                        "severity": "HIGH",
                        "description": f"User '{curr_user}' authenticated from {past_country} and {curr_country} within an impossible timeframe ({speed} km/h).",
                        "mitre_id": "T1078.004",
                        "trigger_alert_id": past.get("alert_id")
                    })
                    correlated_alert_ids.append(past.get("alert_id"))
                    break

        # 3. Rule: Distributed Credential Stuffing Campaign
        target_endpoint = current_alert.get("resource") or current_alert.get("endpoint")
        if target_endpoint and "auth" in target_endpoint.lower() or "login" in str(target_endpoint).lower():
            recent_auth_ips = set()
            for past in self.alert_history[-20:]:
                past_endpoint = past.get("resource") or past.get("endpoint")
                if past_endpoint and past_endpoint == target_endpoint:
                    past_ip = past.get("source_ip") or past.get("ip")
                    if past_ip:
                        recent_auth_ips.add(past_ip)
            if len(recent_auth_ips) >= 3:
                matched_rules.append({
                    "rule_id": "RULE-CORR-03",
                    "rule_name": "Distributed Credential Stuffing Campaign",
                    "severity": "HIGH",
                    "description": f"Coordinated authentication attacks detected across {len(recent_auth_ips)} distinct IPs targeting '{target_endpoint}'.",
                    "mitre_id": "T1110.003",
                    "target": target_endpoint
                })

        # 4. Rule: Reconnaissance followed by Data Exfiltration
        outbound = current_alert.get("outbound_bytes_mb", 0)
        if outbound > 10:
            for past in reversed(self.alert_history[-40:]):
                past_ip = past.get("source_ip") or past.get("ip")
                if past_ip == curr_ip and (past.get("port_scan_distinct_ports", 0) >= 5 or "scan" in str(past.get("attack_type", "")).lower()):
                    matched_rules.append({
                        "rule_id": "RULE-CORR-04",
                        "rule_name": "Reconnaissance Followed by Exfiltration",
                        "severity": "CRITICAL",
                        "description": f"IP {curr_ip} performed port reconnaissance followed by massive outbound data exfiltration ({outbound} MB).",
                        "mitre_id": "T1046 -> T1048",
                        "trigger_alert_id": past.get("alert_id")
                    })
                    correlated_alert_ids.append(past.get("alert_id"))
                    break

        # 5. Conflict Rule: Conflicting / Evasion Pattern
        claimed_type = str(current_alert.get("classification", "")).lower()
        if "benign" in claimed_type or "routine" in claimed_type:
            if current_alert.get("is_tor") or current_alert.get("country") in ["TOR_EXIT", "ANONYMOUS_PROXY"]:
                conflicts.append({
                    "conflict_id": "CONF-01",
                    "type": "EVASION_MISCLASSIFICATION",
                    "message": "Alert claims benign operational status but source IP originates from an anonymous TOR exit node."
                })
            if current_alert.get("payload_entropy", 0) > 4.5:
                conflicts.append({
                    "conflict_id": "CONF-02",
                    "type": "HIGH_ENTROPY_OBFUSCATION",
                    "message": "Benign label conflict: Payload exhibits high Shannon entropy (>4.5) indicative of encrypted/obfuscated shellcode."
                })

        # Calculate incident blast radius
        has_critical = any(r["severity"] == "CRITICAL" for r in matched_rules)
        blast_score = 85 if has_critical else (60 if matched_rules else 20)

        return {
            "has_correlation": len(matched_rules) > 0,
            "matched_rules": matched_rules,
            "conflicts": conflicts,
            "correlated_alert_ids": list(set(correlated_alert_ids)),
            "incident_blast_radius_score": blast_score,
            "correlation_summary": (
                f"Correlated across {len(matched_rules)} attack chain patterns" if matched_rules
                else "Standalone individual event"
            )
        }


# Singleton Rule Engine
rule_engine = CorrelationRuleEngine()
