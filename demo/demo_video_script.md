# ThreatSynth 79 — Demo Video Walkthrough Script (Under 2 Minutes)

**Total Duration**: ~1 minute 50 seconds  
**Target Audience**: Cybersecurity Judges, SOC Managers, Incident Commanders  
**Key Features Demonstrated**: Real-time SIEM alert ingestion, AI/ML risk classification & anomaly scoring, SHAP-style explainability, Gen-AI threat synthesis & MITRE ATT&CK mapping, Strict Identity-Based Access Control (RBAC 403 blocking), Tamper-evident Audit Logging, and PDF Dossier Export.

---

### [00:00 - 00:20] Introduction & Problem Background
- **Visual**: Show ThreatSynth 79 Cyber SOC Dashboard running at `http://127.0.0.1:8000`. Point out the dark cyberpunk theme, live KPI counters, and Active Identity selector (`SOC Analyst (L2)`).
- **Narration**:  
  > *"During high-stress cybersecurity drills at a fintech startup, SOC analysts are inundated with noisy SIEM alerts. Today, we present **ThreatSynth 79** — an autonomous threat triage and identity-governed correlation engine designed to classify risk in milliseconds, explain decisions, and prevent unauthorized data leaks."*

---

### [00:20 - 00:45] Alert Ingestion, ML Scoring & Rule Correlation
- **Visual**: Click `+ SQL Injection (High)` and `+ Ingest All Drill Alerts`. Watch the live feed update instantaneously with a sub-20ms latency indicator. Highlight the glowing red high-risk badge and `CHAIN` indicator for correlated attacks.
- **Narration**:  
  > *"With a single click or API webhook, ThreatSynth ingests raw SIEM JSON alerts in under 15 milliseconds — vastly beating the 2-second drill requirement. Our hybrid AI/ML pipeline combines an Ensemble Random Forest Classifier with an Isolation Forest Anomaly Detector to score alerts into High, Medium, and Low risk."*

---

### [00:45 - 01:10] Explainability (SHAP) & Gen-AI Incident Briefing
- **Visual**: Click on `ALT-DEMO-001` (SQL Injection on Payment Vault). The right-side Inspector panel opens. Hover over the interactive **SHAP Feature Attribution Bar Chart**, the **Gen-AI Threat Synthesis**, the **MITRE T1190 badge**, and the **SOC Remediation Checklist**.
- **Narration**:  
  > *"ThreatSynth provides complete explainability. The SHAP attribution chart proves exactly why this alert was marked High Risk — highlighting excessive payload entropy and SQL injection syntax. Our Gen-AI component maps the attack to MITRE ATT&CK T1190 and generates an actionable 5-step containment playbook for SOC analysts."*

---

### [01:10 - 01:30] Identity-Based Access Control (RBAC 403 Rejection)
- **Visual**: Click the **Unauthorized Guest (Charlie)** button in the top navigation bar. Click on the high-risk alert again. The screen instantly displays the red **403 Forbidden: Access Restricted** card with an explanation that forensic intelligence is locked. Then switch to **Tier 1 Viewer** to show redacted payload text (`[REDACTED]`).
- **Narration**:  
  > *"Security is enforced at the core. When an unauthorized user attempts to inspect sensitive threat payloads, ThreatSynth immediately blocks the request with an HTTP 403 Forbidden. Tier 1 analysts see only sanitized metadata, ensuring strict need-to-know compliance."*

---

### [01:30 - 01:50] Cryptographic Audit Trail & PDF Dossier Export
- **Visual**: Scroll down to the **Cryptographic Audit Trail** table. Click `Verify Cryptographic Chain` (shows SHA-256 validation popup). Then click `Export PDF Dossier` in the header to download the incident response report.
- **Narration**:  
  > *"Every single access attempt and RBAC rejection is recorded in an immutable SHA-256 chained audit log. Finally, analysts can generate a compliant, audit-ready PDF Incident Dossier with one click. ThreatSynth 79 turns chaotic SIEM noise into structured, explainable, and secure threat intelligence."*

---

### End of Video Screen
- **Title**: ThreatSynth 79 — Fast, Explainable, Secure
- **GitHub Repository**: Ready for immediate deployment and drill reproduction.
