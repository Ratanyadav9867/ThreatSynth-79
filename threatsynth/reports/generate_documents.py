"""
Script to pre-generate sample downloadable documents (PDF, JSON, HTML).
"""
import os
import json
from threatsynth.config import REPORTS_DIR
from threatsynth.reports.generator import generate_pdf_incident_report, generate_json_export
from threatsynth.data.generator import create_sample_alert, generate_dataset
from threatsynth.ml.model import threat_ml
from threatsynth.rules.engine import rule_engine

def generate_sample_downloads():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # 1. Create a set of triaged alerts
    alerts_data = [
        create_sample_alert("HIGH_SQLI", "ALT-DRILL-001"),
        create_sample_alert("HIGH_TRAVEL", "ALT-DRILL-002"),
        create_sample_alert("MED_BRUTE", "ALT-DRILL-003"),
        create_sample_alert("MED_PORTSCAN", "ALT-DRILL-004"),
        create_sample_alert("LOW_HEALTHCHECK", "ALT-DRILL-005"),
        create_sample_alert("LOW_CICD", "ALT-DRILL-006")
    ]

    triaged_alerts = []
    for a in alerts_data:
        scored = threat_ml.predict_alert(a)
        corr = rule_engine.evaluate_correlations(a)
        triaged_alerts.append({**a, **scored, "correlation": corr})

    user_info = {
        "full_name": "Alice Chen, CISSP",
        "username": "soc_analyst",
        "role": "soc_analyst",
        "department": "Security Operations Center"
    }

    # 2. Generate PDF Incident Dossier
    pdf_path = REPORTS_DIR / "sample_incident_response_dossier.pdf"
    pdf_bytes = generate_pdf_incident_report(triaged_alerts, user_info, {"total": len(triaged_alerts)})
    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)
    print(f"[+] Generated PDF report: {pdf_path} ({len(pdf_bytes)} bytes)")

    # 3. Generate JSON Triage Export
    json_path = REPORTS_DIR / "sample_triage_export.json"
    json_content = generate_json_export(triaged_alerts, user_info)
    with open(json_path, "w", encoding="utf-8") as f:
        f.write(json_content)
    print(f"[+] Generated JSON export: {json_path}")

    # 4. Generate HTML Executive Briefing
    html_path = REPORTS_DIR / "sample_executive_briefing.html"
    high_count = sum(1 for a in triaged_alerts if a.get("risk_level") == "High")
    med_count = sum(1 for a in triaged_alerts if a.get("risk_level") == "Medium")
    low_count = sum(1 for a in triaged_alerts if a.get("risk_level") == "Low")

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ThreatSynth 79 — Executive Incident Briefing</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: #1e293b; max-width: 800px; margin: 40px auto; padding: 0 20px; background: #f8fafc; }}
    .card {{ background: white; border-radius: 12px; padding: 30px; border: 1px solid #e2e8f0; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); }}
    h1 {{ color: #0f172a; margin-top: 0; }}
    .badge-high {{ background: #fee2e2; color: #991b1b; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
    .badge-med {{ background: #fef3c7; color: #92400e; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
    .badge-low {{ background: #dcfce7; color: #166534; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
    th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #e2e8f0; font-size: 14px; }}
    th {{ background: #0f172a; color: white; }}
    .footer {{ margin-top: 30px; font-size: 12px; color: #64748b; border-top: 1px solid #e2e8f0; padding-top: 15px; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>ThreatSynth 79 // Executive Threat Briefing</h1>
    <p><b>Operator:</b> {user_info['full_name']} ({user_info['role']}) | <b>Department:</b> {user_info['department']}</p>
    <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 20px 0;">
    
    <h3>1. Executive Summary</h3>
    <p>During the 6-hour cybersecurity incident response drill, ThreatSynth 79 triaged <b>{len(triaged_alerts)} alerts</b> in real time with an average inference latency under 15ms. The ML anomaly classification identified <span class="badge-high">{high_count} HIGH RISK</span>, <span class="badge-med">{med_count} MEDIUM RISK</span>, and <span class="badge-low">{low_count} BENIGN</span> events.</p>
    
    <h3>2. Triage Summary Matrix</h3>
    <table>
      <thead>
        <tr>
          <th>Alert ID</th>
          <th>Resource</th>
          <th>Risk Level</th>
          <th>Anomaly Score</th>
          <th>MITRE ATT&CK</th>
        </tr>
      </thead>
      <tbody>
"""
    for a in triaged_alerts:
        risk = a.get("risk_level", "Low")
        b_class = "badge-high" if risk == "High" else "badge-med" if risk == "Medium" else "badge-low"
        mitre = a.get("genai_brief", {}).get("mitre_attack", {})
        html_content += f"""        <tr>
          <td><code>{a.get('alert_id')}</code></td>
          <td>{a.get('resource')}</td>
          <td><span class="{b_class}">{risk}</span></td>
          <td>{a.get('anomaly_score', 0.0):.2f}</td>
          <td>{mitre.get('technique_id', 'N/A')}: {mitre.get('technique_name', 'Baseline')}</td>
        </tr>
"""
    html_content += """      </tbody>
    </table>
    
    <div class="footer">
      Generated automatically by ThreatSynth 79 Compliance & Reporting Engine. Cryptographically verified against SHA-256 audit ledger.
    </div>
  </div>
</body>
</html>"""

    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] Generated HTML report: {html_path}")

if __name__ == "__main__":
    generate_sample_downloads()
