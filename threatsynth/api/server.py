"""
ThreatSynth 79 FastAPI Application Server
Integrates AI/ML Ingestion, Identity-Based Access Control, Rule Correlation, and SOC Dashboard.
"""
import os
import json
import time
from contextlib import asynccontextmanager
from typing import List, Dict, Any, Optional, Union
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Body, Response, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, Response

from threatsynth.config import STATIC_DIR, SAMPLES_DIR, MOCK_USERS
from threatsynth.core.auth import (
    authenticate_user,
    get_current_user,
    require_roles,
    sanitize_alert_for_role
)
from threatsynth.core.audit import audit_logger
from threatsynth.ml.model import threat_ml
from threatsynth.ml.features import batch_extract_features, FEATURE_NAMES
from threatsynth.rules.engine import rule_engine
from threatsynth.data.generator import generate_dataset, create_sample_alert, save_mvp_samples
from threatsynth.reports.generator import generate_pdf_incident_report, generate_json_export
from threatsynth.api.middleware import SecurityAuditMiddleware

# Global In-memory alerts store
ALERTS_STORE: List[Dict[str, Any]] = []


def init_system_state():
    """Ensure baseline ML model is trained and initial sample drill alerts exist."""
    save_mvp_samples()

    # Train model if not already trained
    if not threat_ml.is_trained:
        synthetic_train = generate_dataset(600)
        X = batch_extract_features(synthetic_train)
        y = [a["ground_truth_risk"] for a in synthetic_train]
        threat_ml.train(X, y)

    # Ingest MVP sample drill alerts into memory if empty
    if not ALERTS_STORE:
        sample_file = SAMPLES_DIR / "batch_incident_drill.json"
        if sample_file.exists():
            with open(sample_file, "r", encoding="utf-8") as f:
                samples = json.load(f)
                for item in samples:
                    scored = threat_ml.predict_alert(item)
                    corr = rule_engine.evaluate_correlations(item)
                    merged = {**item, **scored, "correlation": corr}
                    rule_engine.add_alert(merged)
                    ALERTS_STORE.append(merged)


# Auto-initialize state on module load
init_system_state()


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_system_state()
    yield


app = FastAPI(
    title="ThreatSynth 79 API",
    description="Real-Time AI/ML Threat Triage, Correlation & Identity-Based Access Control System",
    version="1.0.0",
    lifespan=lifespan
)

# CORS & Custom Security Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityAuditMiddleware)


# --- AUTH & IDENTITY PROVIDER ENDPOINTS ---

@app.post("/api/auth/login")
def login(payload: Dict[str, Any] = Body(...)):
    """Mock Identity Provider / OAuth 2.0 login and token issuance."""
    username = payload.get("username", "soc_analyst")
    password = payload.get("password")
    auth_data = authenticate_user(username, password)
    
    audit_logger.log(
        user_id=auth_data["user"].get("user_id", "usr-idp"),
        username=auth_data["user"].get("username", username),
        role=auth_data["user"].get("role", "soc_analyst"),
        action="IDENTITY_AUTHENTICATE",
        resource="/api/auth/login",
        status_code=200,
        details={"auth_method": "Mock_OAuth2_Stub"}
    )
    return auth_data


@app.get("/api/auth/users")
def list_mock_users():
    """List available mock user personas for testing RBAC."""
    return [
        {
            "username": u["username"],
            "full_name": u["full_name"],
            "role": u["role"],
            "department": u["department"],
            "description": u["description"]
        }
        for u in MOCK_USERS.values()
    ]


# --- ALERT INGESTION & TRIAGE ENDPOINTS ---

@app.post("/api/alerts/ingest")
async def ingest_alerts(
    request: Request,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Ingest raw security alerts via JSON payload.
    Processes in real-time (<2s latency requirement).
    """
    start_time = time.perf_counter()
    try:
        raw_data = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON payload: {str(e)}")

    alerts_to_process = []
    if isinstance(raw_data, list):
        alerts_to_process.extend(raw_data)
    elif isinstance(raw_data, dict):
        alerts_to_process.append(raw_data)
    else:
        raise HTTPException(status_code=400, detail="Alert payload must be a JSON object or array of objects.")

    if not alerts_to_process:
        raise HTTPException(status_code=400, detail="No alert items provided in payload.")

    processed_results = []
    user_role = current_user.get("role", "unauthorized_guest")

    for raw_alert in alerts_to_process:
        if "alert_id" not in raw_alert:
            raw_alert["alert_id"] = f"ALT-{int(time.time()*1000)}-{len(ALERTS_STORE)+1}"
        if "timestamp" not in raw_alert:
            raw_alert["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # 1. Score via ML Model
        ml_result = threat_ml.predict_alert(raw_alert)

        # 2. Correlate with rule engine
        correlation_result = rule_engine.evaluate_correlations(raw_alert)

        full_record = {
            **raw_alert,
            **ml_result,
            "correlation": correlation_result,
            "ingested_by": current_user.get("username", "anonymous"),
            "ingested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        rule_engine.add_alert(full_record)
        ALERTS_STORE.insert(0, full_record)

        sanitized = sanitize_alert_for_role(full_record, user_role)
        processed_results.append(sanitized)

    latency_ms = (time.perf_counter() - start_time) * 1000.0

    audit_logger.log(
        user_id=current_user.get("user_id", "usr-anonymous"),
        username=current_user.get("username", "anonymous"),
        role=user_role,
        action="INGEST_ALERTS",
        resource="/api/alerts/ingest",
        status_code=200,
        duration_ms=latency_ms,
        details={"count": len(processed_results), "latency_ms": round(latency_ms, 2)}
    )

    return {
        "status": "SUCCESS",
        "processed_count": len(processed_results),
        "ingestion_latency_ms": round(latency_ms, 2),
        "alerts": processed_results
    }


@app.post("/api/alerts/upload")
async def upload_alerts_file(
    file: UploadFile = File(...),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Ingest alerts via .json file upload."""
    content = await file.read()
    try:
        parsed = json.loads(content.decode("utf-8"))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON file: {str(e)}")

    alerts_to_process = parsed if isinstance(parsed, list) else [parsed]
    processed_results = []
    user_role = current_user.get("role", "unauthorized_guest")

    for raw_alert in alerts_to_process:
        if "alert_id" not in raw_alert:
            raw_alert["alert_id"] = f"ALT-{int(time.time()*1000)}-{len(ALERTS_STORE)+1}"
        if "timestamp" not in raw_alert:
            raw_alert["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        ml_result = threat_ml.predict_alert(raw_alert)
        correlation_result = rule_engine.evaluate_correlations(raw_alert)

        full_record = {
            **raw_alert,
            **ml_result,
            "correlation": correlation_result,
            "ingested_by": current_user.get("username", "anonymous"),
            "ingested_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        }

        rule_engine.add_alert(full_record)
        ALERTS_STORE.insert(0, full_record)

        sanitized = sanitize_alert_for_role(full_record, user_role)
        processed_results.append(sanitized)

    return {
        "status": "SUCCESS",
        "processed_count": len(processed_results),
        "alerts": processed_results
    }


@app.get("/api/alerts")
def list_alerts(
    risk: Optional[str] = None,
    limit: int = 50,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List triaged alerts with RBAC sanitization applied based on caller's identity."""
    user_role = current_user.get("role", "unauthorized_guest")
    
    filtered = ALERTS_STORE
    if risk:
        filtered = [a for a in filtered if a.get("risk_level", "").lower() == risk.lower()]

    results = [sanitize_alert_for_role(a, user_role) for a in filtered[:limit]]
    return {
        "total_count": len(ALERTS_STORE),
        "returned_count": len(results),
        "user_role": user_role,
        "alerts": results
    }


@app.get("/api/alerts/{alert_id}")
def get_alert_detail(
    alert_id: str,
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """
    Get deep-dive forensic alert details, SHAP explainability, and AI Playbooks.
    STRICT RBAC: Only 'soc_analyst' and 'admin' can access.
    """
    user_role = current_user.get("role", "unauthorized_guest")
    
    if user_role not in ["admin", "soc_analyst"]:
        audit_logger.log(
            user_id=current_user.get("user_id", "usr-guest"),
            username=current_user.get("username", "guest"),
            role=user_role,
            action=f"ACCESS_ALERT_DENIED_{alert_id}",
            resource=f"/api/alerts/{alert_id}",
            status_code=403,
            details={"attempted_role": user_role, "required_roles": ["admin", "soc_analyst"]}
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access Denied: Role '{user_role}' is not authorized to view sensitive forensic threat intelligence and risk summaries."
        )

    for a in ALERTS_STORE:
        if a.get("alert_id") == alert_id:
            audit_logger.log(
                user_id=current_user.get("user_id"),
                username=current_user.get("username"),
                role=user_role,
                action=f"VIEW_ALERT_FORENSICS_{alert_id}",
                resource=f"/api/alerts/{alert_id}",
                status_code=200
            )
            return sanitize_alert_for_role(a, user_role)

    raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")


# --- RULE CORRELATION & CONFLICTS ---

@app.get("/api/rules/correlated")
def get_correlated_incidents(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """View active multi-alert correlation chains and conflict warnings."""
    correlated = [a for a in ALERTS_STORE if a.get("correlation", {}).get("has_correlation")]
    conflicts = []
    for a in ALERTS_STORE:
        conf_list = a.get("correlation", {}).get("conflicts", [])
        if conf_list:
            conflicts.append({"alert_id": a.get("alert_id"), "conflicts": conf_list})

    return {
        "correlated_incidents_count": len(correlated),
        "conflicts_count": len(conflicts),
        "correlated_alerts": correlated[:15],
        "conflicts": conflicts
    }


# --- ML RETRAINING ENDPOINT ---

@app.post("/api/model/retrain")
def retrain_model(
    samples_count: int = 500,
    current_user: Dict[str, Any] = Depends(require_roles(["admin"]))
):
    """
    Retrain the ML classifier and anomaly detector with fresh synthetic data.
    Requires 'admin' role.
    """
    start_time = time.perf_counter()
    new_dataset = generate_dataset(samples_count)
    X = batch_extract_features(new_dataset)
    y = [a["ground_truth_risk"] for a in new_dataset]
    
    metrics = threat_ml.train(X, y)
    duration_ms = (time.perf_counter() - start_time) * 1000.0

    audit_logger.log(
        user_id=current_user.get("user_id"),
        username=current_user.get("username"),
        role=current_user.get("role"),
        action="MODEL_RETRAIN",
        resource="/api/model/retrain",
        status_code=200,
        duration_ms=duration_ms,
        details={"samples_trained": samples_count, "accuracy": metrics["accuracy"]}
    )

    return {
        "status": "MODEL_RETRAINED_SUCCESSFULLY",
        "retrain_duration_ms": round(duration_ms, 2),
        "metrics": metrics
    }


@app.get("/api/model/metrics")
def get_model_metrics():
    """Retrieve current ML model performance metrics and feature importances."""
    importances = {}
    if threat_ml.classifier and hasattr(threat_ml.classifier, "feature_importances_"):
        for name, imp in zip(FEATURE_NAMES, threat_ml.classifier.feature_importances_):
            importances[name] = round(float(imp), 4)

    return {
        "is_trained": threat_ml.is_trained,
        "metrics": threat_ml.metrics_,
        "feature_importances": importances,
        "feature_names": FEATURE_NAMES
    }


# --- AUDIT & COMPLIANCE ENDPOINTS ---

@app.get("/api/audit/logs")
def get_audit_logs(
    limit: int = 50,
    role: Optional[str] = None,
    outcome: Optional[str] = None
):
    """Query recent immutable audit logs."""
    logs = audit_logger.query(role=role, outcome=outcome, limit=limit)
    return {
        "total_in_memory": len(audit_logger._memory_logs),
        "returned_count": len(logs),
        "logs": logs
    }


@app.get("/api/audit/verify")
def verify_audit_chain():
    """Verify cryptographic SHA-256 integrity of the audit log chain."""
    return audit_logger.verify_integrity()


# --- REPORTS & EXPORTS ---

@app.get("/api/reports/pdf")
def export_pdf_report(
    current_user: Dict[str, Any] = Depends(require_roles(["admin", "soc_analyst"]))
):
    """Generate and download a comprehensive Incident Response PDF report."""
    pdf_bytes = generate_pdf_incident_report(
        alerts=ALERTS_STORE,
        user_info=current_user,
        system_metrics={"total": len(ALERTS_STORE)}
    )
    
    audit_logger.log(
        user_id=current_user.get("user_id"),
        username=current_user.get("username"),
        role=current_user.get("role"),
        action="EXPORT_PDF_REPORT",
        resource="/api/reports/pdf",
        status_code=200
    )

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=threatsynth_incident_report.pdf"}
    )


@app.get("/api/reports/json")
def export_json_report(
    current_user: Dict[str, Any] = Depends(require_roles(["admin", "soc_analyst"]))
):
    """Export complete triage dataset in JSON format."""
    json_str = generate_json_export(ALERTS_STORE, current_user)
    return Response(
        content=json_str,
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=threatsynth_triage_export.json"}
    )


# --- SAMPLE DATA ENDPOINT ---

@app.get("/api/samples")
def get_sample_alerts():
    """Get sample JSON alert payloads for quick testing."""
    samples = []
    if SAMPLES_DIR.exists():
        for p in sorted(SAMPLES_DIR.glob("*.json")):
            try:
                with open(p, "r", encoding="utf-8") as f:
                    samples.append({"file_name": p.name, "data": json.load(f)})
            except Exception:
                pass
    return samples


# Mount static assets & serve dashboard frontend
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

@app.get("/")
def serve_index():
    """Serve single-page Cyber SOC Dashboard frontend."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return JSONResponse({"status": "ThreatSynth 79 API Online", "docs": "/docs"})
