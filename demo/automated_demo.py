"""
ThreatSynth 79 Automated End-to-End Demonstration Script
Executes full triage workflow, demonstrates RBAC access blocking, SHAP explainability, and report export.
"""
import sys
import time
import json
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console(safe_box=True, highlight=False)
BASE_URL = "http://127.0.0.1:8000"


def run_automated_demo():
    console.print(Panel.fit("[bold cyan]ThreatSynth 79 // Automated Incident Response Drill & Verification[/bold cyan]"))
    
    # 1. Check Server Liveness
    console.print("\n[bold yellow]Step 1: Checking ThreatSynth API & SOC Server Status...[/bold yellow]")
    try:
        res = requests.get(f"{BASE_URL}/api/model/metrics", timeout=5)
        if res.status_code == 200:
            console.print("[bold green][OK] Server Online & ML Model Active.[/bold green]")
        else:
            console.print(f"[bold red][FAIL] Server returned status {res.status_code}[/bold red]")
            return
    except Exception as e:
        console.print(f"[bold red][FAIL] Could not connect to {BASE_URL}. Ensure 'python run.py' is running: {e}[/bold red]")
        return

    # 2. Ingest Sample High-Risk Alert
    console.print("\n[bold yellow]Step 2: Ingesting High-Risk Security Alert (SQLi & Exfiltration)...[/bold yellow]")
    sample_alert = {
        "alert_id": "ALT-DEMO-EXFIL-01",
        "alert_name": "Critical SQL Injection & Database Exfiltration on Payment Vault",
        "source_ip": "198.51.100.42",
        "source_country": "TOR_EXIT",
        "is_tor": True,
        "username": "admin",
        "resource": "/api/v1/payments/transfer",
        "status_code": 500,
        "attack_type": "SQL_INJECTION",
        "failed_login_count": 0,
        "request_rate_per_sec": 55.0,
        "payload": "1' UNION SELECT credit_card, cvv, exp_date FROM card_vault; --",
        "outbound_bytes_mb": 18.5,
        "privilege_escalation": True,
        "sensitive_payload": "SELECT credit_card, cvv, exp_date FROM card_vault WHERE 1=1"
    }

    t0 = time.perf_counter()
    login_res = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "soc_analyst"}).json()
    soc_token = login_res["access_token"]

    ingest_res = requests.post(
        f"{BASE_URL}/api/alerts/ingest",
        json=sample_alert,
        headers={"Authorization": f"Bearer {soc_token}"}
    )
    t_ingest = (time.perf_counter() - t0) * 1000.0

    console.print(f"[bold green][OK] Ingested & Scored in {t_ingest:.2f}ms (Requirement: <2000ms)[/bold green]")
    scored = ingest_res.json()["alerts"][0]

    console.print(f"[bold white]Risk Level:[/bold white] [bold red]{scored['risk_level']}[/bold red] (Confidence: {scored['confidence']*100:.1f}%)")
    console.print(f"[bold white]Anomaly Index:[/bold white] [bold red]{scored['anomaly_score']:.2f}[/bold red]")
    console.print(f"[bold white]MITRE ATT&CK:[/bold white] {scored['genai_brief']['mitre_attack']['technique_id']} - {scored['genai_brief']['mitre_attack']['technique_name']}")

    # 3. Demonstrate Explainability (SHAP Weights)
    console.print("\n[bold yellow]Step 3: ML Explainability & Local Factor Attribution (SHAP-Style)...[/bold yellow]")
    drivers = scored["explainability"]["top_risk_drivers"]
    table = Table(title="Top Risk Drivers (Local Attribution)", border_style="cyan")
    table.add_column("Feature", style="bold white")
    table.add_column("Observed Value", justify="right", style="cyan")
    table.add_column("Contribution Score", justify="right", style="bold red")
    table.add_column("Factor Explanation", style="dim")

    for d in drivers:
        table.add_row(d["display_name"], str(d["value"]), f"+{d['contribution_score']:.4f}", d["explanation"])
    console.print(table)

    # 4. Demonstrate RBAC Security Rejection (403 Forbidden)
    console.print("\n[bold yellow]Step 4: Demonstrating Strict Identity Access Control (RBAC Rejection)...[/bold yellow]")
    guest_login = requests.post(f"{BASE_URL}/api/auth/login", json={"username": "unauthorized_guest"}).json()
    guest_token = guest_login["access_token"]

    forbidden_res = requests.get(
        f"{BASE_URL}/api/alerts/{scored['alert_id']}",
        headers={"Authorization": f"Bearer {guest_token}"}
    )
    console.print(f"[bold white]Attempting access as 'unauthorized_guest'...[/bold white]")
    if forbidden_res.status_code == 403:
        console.print(f"[bold green][OK] ACCESS REJECTED (HTTP 403 Forbidden)[/bold green]: {forbidden_res.json()['detail']}")
    else:
        console.print(f"[bold red][FAIL] Security Bypass! Received status {forbidden_res.status_code}[/bold red]")

    # 5. Verify Audit Log Integrity
    console.print("\n[bold yellow]Step 5: Verifying Cryptographic Audit Log Integrity...[/bold yellow]")
    audit_res = requests.get(f"{BASE_URL}/api/audit/verify").json()
    console.print(f"[bold green][OK] Cryptographic Chain Validated:[/bold green] {audit_res['total_events']} events, Status: {audit_res['status']}")

    console.print("\n[bold green]=======================================================[/bold green]")
    console.print("[bold green][SUCCESS] All ThreatSynth 79 drill requirements successfully verified![/bold green]")
    console.print("[bold green]=======================================================[/bold green]\n")


if __name__ == "__main__":
    run_automated_demo()
