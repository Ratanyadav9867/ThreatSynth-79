"""
ThreatSynth Core ML Model Engine
Combines Random Forest Multi-Class Classification with Isolation Forest Anomaly Detection.
"""
import os
import joblib
import numpy as np
from typing import Dict, Any, List, Tuple, Optional
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, accuracy_score, f1_score
from threatsynth.config import MODEL_PATH, RANDOM_STATE, HIGH_RISK_ANOMALY_THRESHOLD, MEDIUM_RISK_ANOMALY_THRESHOLD
from threatsynth.ml.features import FEATURE_NAMES, extract_features_from_alert, batch_extract_features
from threatsynth.ml.explainability import explain_prediction
from threatsynth.ml.genai import synthesize_threat_intelligence


class ThreatSynthML:
    """Production ML Pipeline for Real-Time Threat Classification and Anomaly Scoring."""

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or MODEL_PATH
        self.classifier: Optional[RandomForestClassifier] = None
        self.anomaly_detector: Optional[IsolationForest] = None
        self.classes_: List[str] = ["Low", "Medium", "High"]
        self.metrics_: Dict[str, Any] = {}
        self.is_trained: bool = False
        self._load_or_initialize()

    def _load_or_initialize(self):
        """Load pre-trained model if file exists, else initialize untrained."""
        if os.path.exists(self.model_path):
            try:
                bundle = joblib.load(self.model_path)
                self.classifier = bundle["classifier"]
                self.anomaly_detector = bundle["anomaly_detector"]
                self.classes_ = bundle.get("classes", ["Low", "Medium", "High"])
                self.metrics_ = bundle.get("metrics", {})
                self.is_trained = True
                print(f"[ThreatSynthML] Successfully loaded model from {self.model_path}")
                return
            except Exception as e:
                print(f"[ThreatSynthML] Error loading model: {e}. Will re-initialize.")
        self._initialize_default_models()

    def _initialize_default_models(self):
        """Create fresh model instances with optimal hyperparameters."""
        self.classifier = RandomForestClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=2,
            class_weight="balanced",
            random_state=RANDOM_STATE
        )
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.15,
            random_state=RANDOM_STATE
        )
        self.is_trained = False

    def train(self, X: np.ndarray, y: List[str]) -> Dict[str, Any]:
        """Train classifier and anomaly detector on telemetry feature matrix."""
        # 1. Fit supervised Random Forest
        self.classifier.fit(X, y)
        self.classes_ = list(self.classifier.classes_)

        # 2. Fit unsupervised Isolation Forest
        self.anomaly_detector.fit(X)

        # 3. Calculate evaluation metrics
        y_pred = self.classifier.predict(X)
        acc = accuracy_score(y, y_pred)
        f1 = f1_score(y, y_pred, average="macro")
        report = classification_report(y, y_pred, output_dict=True, zero_division=0)

        self.metrics_ = {
            "accuracy": round(float(acc), 4),
            "f1_macro": round(float(f1), 4),
            "samples_trained": int(len(y)),
            "features_count": len(FEATURE_NAMES),
            "classes": self.classes_,
            "detailed_report": report
        }
        self.is_trained = True
        self.save()
        return self.metrics_

    def score_anomaly(self, feature_vector: np.ndarray) -> float:
        """
        Compute normalized anomaly score between 0.0 (normal) and 1.0 (highly anomalous).
        Uses Isolation Forest decision function with sigmoid mapping.
        """
        raw_score = self.anomaly_detector.decision_function(feature_vector.reshape(1, -1))[0]
        # raw_score is typically between -0.5 (anomalous) and +0.5 (normal)
        # We invert and map to [0, 1]
        normalized = 1.0 / (1.0 + np.exp(4.0 * raw_score))
        return round(float(np.clip(normalized, 0.0, 1.0)), 4)

    def predict_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Full real-time inference pipeline:
        Feature extraction -> Supervised Risk Classification -> Anomaly Scoring -> Explainability -> Gen-AI Synthesis.
        """
        if not self.is_trained:
            # Fallback if un-trained
            return {
                "risk_level": "Medium",
                "confidence": 0.5,
                "anomaly_score": 0.5,
                "probabilities": {"Low": 0.33, "Medium": 0.34, "High": 0.33},
                "explainability": {"status": "Model untrained"},
                "genai_brief": {"executive_summary": "System model is in baseline initialization."}
            }

        vec, metadata = extract_features_from_alert(alert)
        vec_2d = vec.reshape(1, -1)

        # 1. Supervised prediction & class probabilities
        predicted_class = self.classifier.predict(vec_2d)[0]
        proba = self.classifier.predict_proba(vec_2d)[0]
        proba_dict = {cls_name: round(float(p), 4) for cls_name, p in zip(self.classes_, proba)}
        confidence = proba_dict.get(predicted_class, 0.85)

        # 2. Anomaly scoring
        anomaly_score = self.score_anomaly(vec)

        # 3. Hybrid safety override: If anomaly score is extreme, elevate Low -> Medium or Medium -> High
        final_risk = predicted_class
        if anomaly_score >= HIGH_RISK_ANOMALY_THRESHOLD and final_risk == "Low":
            final_risk = "Medium"
        if metadata.get("has_sqli") or metadata.get("speed_kmh", 0) > 600 or metadata.get("priv_escalation"):
            final_risk = "High"

        # 4. Generate SHAP-style Explainability
        explainability = explain_prediction(
            model=self.classifier,
            anomaly_model=self.anomaly_detector,
            feature_vector=vec,
            predicted_risk=final_risk,
            probabilities=proba_dict
        )

        # 5. Generate Gen-AI Brief & MITRE ATT&CK Playbook
        genai_brief = synthesize_threat_intelligence(
            alert=alert,
            risk_level=final_risk,
            explainability=explainability
        )

        return {
            "risk_level": final_risk,
            "confidence": confidence,
            "anomaly_score": anomaly_score,
            "probabilities": proba_dict,
            "extracted_features": metadata,
            "explainability": explainability,
            "genai_brief": genai_brief
        }

    def save(self, path: Optional[str] = None):
        """Serialize model bundle to disk."""
        target = path or self.model_path
        os.makedirs(os.path.dirname(target), exist_ok=True)
        bundle = {
            "classifier": self.classifier,
            "anomaly_detector": self.anomaly_detector,
            "classes": self.classes_,
            "metrics": self.metrics_
        }
        joblib.dump(bundle, target)
        print(f"[ThreatSynthML] Model bundle persisted to {target}")


# Global singleton instance
threat_ml = ThreatSynthML()
