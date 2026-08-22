"""
ThreatSynth 79 System Launcher
Starts the full Cyber SOC Triage System, ML Engine, and Web Application.
"""
import sys
import uvicorn
from threatsynth.data.generator import save_mvp_samples, generate_dataset
from threatsynth.ml.model import threat_ml
from threatsynth.ml.features import batch_extract_features


def initialize_system():
    """Ensure sample datasets and ML model artifacts are trained and ready."""
    print("===================================================================")
    print("  ThreatSynth 79 // Autonomous Cyber SOC & Real-Time Threat Triage")
    print("===================================================================")
    print("[*] Generating synthetic FinTech SIEM sample alerts...")
    save_mvp_samples()

    if not threat_ml.is_trained:
        print("[*] Training baseline ML classification & anomaly detection models...")
        synthetic_train = generate_dataset(800)
        X = batch_extract_features(synthetic_train)
        y = [a["ground_truth_risk"] for a in synthetic_train]
        metrics = threat_ml.train(X, y)
        print(f"[+] ML Pipeline Ready. Baseline Accuracy: {metrics['accuracy']*100:.2f}%, F1: {metrics['f1_macro']:.4f}")
    else:
        print("[+] Pre-trained ML model loaded successfully.")

    print("[*] Launching ThreatSynth 79 Cyber SOC Engine on http://127.0.0.1:8000")
    print("===================================================================")


if __name__ == "__main__":
    initialize_system()
    uvicorn.run("threatsynth.api.server:app", host="127.0.0.1", port=8000, reload=False)
