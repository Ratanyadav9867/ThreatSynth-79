"""
Tests for ML Classification, Anomaly Scoring, SHAP Explainability & Gen-AI Synthesizer
"""
import pytest
import numpy as np
from threatsynth.ml.model import threat_ml
from threatsynth.ml.features import extract_features_from_alert, FEATURE_NAMES
from threatsynth.data.generator import create_sample_alert, generate_dataset


def test_feature_extraction():
    """Verify feature vector extraction and entropy calculation."""
    alert = create_sample_alert("HIGH_SQLI")
    vec, metadata = extract_features_from_alert(alert)

    assert isinstance(vec, np.ndarray)
    assert len(vec) == len(FEATURE_NAMES)
    assert metadata["has_sqli"] is True
    assert metadata["is_admin"] is True


def test_high_risk_classification():
    """Verify SQL injection alert is classified as High Risk."""
    alert = create_sample_alert("HIGH_SQLI")
    result = threat_ml.predict_alert(alert)

    assert result["risk_level"] == "High"
    assert result["anomaly_score"] >= 0.40
    assert "explainability" in result
    assert "top_risk_drivers" in result["explainability"]
    assert len(result["explainability"]["top_risk_drivers"]) > 0


def test_low_risk_classification():
    """Verify routine healthcheck alert is classified as Low Risk."""
    alert = create_sample_alert("LOW_HEALTHCHECK")
    result = threat_ml.predict_alert(alert)

    assert result["risk_level"] == "Low"
    assert result["anomaly_score"] < 0.50


def test_genai_synthesis_and_mitre_mapping():
    """Verify Gen-AI natural language brief and MITRE ATT&CK taxonomy generation."""
    alert = create_sample_alert("HIGH_TRAVEL")
    result = threat_ml.predict_alert(alert)
    genai = result["genai_brief"]

    assert "executive_summary" in genai
    assert "mitre_attack" in genai
    assert genai["mitre_attack"]["technique_id"] == "T1078.004"
    assert len(genai["remediation_playbook"]) >= 3


def test_model_retrain_pipeline():
    """Verify ML model retrain workflow."""
    dataset = generate_dataset(150)
    from threatsynth.ml.features import batch_extract_features
    X = batch_extract_features(dataset)
    y = [a["ground_truth_risk"] for a in dataset]

    metrics = threat_ml.train(X, y)
    assert metrics["accuracy"] >= 0.85
    assert metrics["f1_macro"] >= 0.80
    assert metrics["samples_trained"] == 150
