"""
Tests for PDF and JSON Incident Report Generation
"""
from threatsynth.reports.generator import generate_pdf_incident_report, generate_json_export
from threatsynth.data.generator import create_sample_alert


def test_pdf_report_generation():
    """Verify PDF incident report generation produces valid PDF bytes."""
    alerts = [
        create_sample_alert("HIGH_SQLI"),
        create_sample_alert("MED_BRUTE"),
        create_sample_alert("LOW_HEALTHCHECK")
    ]
    user_info = {
        "full_name": "Alice Chen, CISSP",
        "username": "soc_analyst",
        "role": "soc_analyst"
    }

    pdf_bytes = generate_pdf_incident_report(alerts, user_info, {"total": len(alerts)})
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 500
    # PDF magic header
    assert pdf_bytes.startswith(b"%PDF")


def test_json_report_export():
    """Verify JSON report export structure."""
    alerts = [create_sample_alert("HIGH_TRAVEL")]
    user_info = {"username": "admin", "role": "admin"}
    json_str = generate_json_export(alerts, user_info)

    assert isinstance(json_str, str)
    assert "export_metadata" in json_str
    assert "alerts" in json_str
