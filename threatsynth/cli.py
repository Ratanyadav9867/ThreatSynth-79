"""
ThreatSynth 79 Command-Line Interface (CLI)
Provides administration, model retraining, batch ingestion, and audit trail verification.
"""
import sys
import json
import argparse
import uvicorn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from threatsynth.config import MODEL_PATH
from threatsynth.ml.model import threat_ml
from threatsynth.ml.features import batch_extract_features, FEATURE_NAMES
from threatsynth.data.generator import generate_dataset
from threatsynth.core.audit import audit_logger

console = Console(safe_box=True, highlight=False)


def cmd_train(args):
    """Train or retrain ML model from synthetic data or provided JSON file."""
    console.print(Panel.fit("[bold cyan]ThreatSynth 79 // ML Model Training Pipeline[/bold cyan]"))
    
    if args.file:
        console.print(f"[yellow]Loading training data from {args.file}...[/yellow]")
        with open(args.file, "r", encoding="utf-8") as f:
            dataset = json.load(f)
    else:
        samples = args.samples or 800
        console.print(f"[yellow]Generating {samples} synthetic FinTech security alerts...[/yellow]")
        dataset = generate_dataset(samples)

    X = batch_extract_features(dataset)
    y = [a.get("ground_truth_risk") or a.get("classification") or "Low" for a in dataset]

    with console.status("[bold green]Fitting Random Forest & Isolation Forest Models..."):
        metrics = threat_ml.train(X, y)

    table = Table(title="Model Training Evaluation Metrics", border_style="cyan")
    table.add_column("Metric", style="bold white")
    table.add_column("Score / Value", style="bold green")

    table.add_row("Overall Accuracy", f"{metrics['accuracy'] * 100:.2f}%")
    table.add_row("Macro F1-Score", f"{metrics['f1_macro']:.4f}")
    table.add_row("Samples Trained", str(metrics["samples_trained"]))
    table.add_row("Features Analyzed", str(metrics["features_count"]))
    table.add_row("Target Classes", ", ".join(metrics["classes"]))
    table.add_row("Model Artifact Path", str(MODEL_PATH))

    console.print(table)
    console.print("[bold green][OK] Model bundle successfully trained and saved![/bold green]\n")


def cmd_evaluate(args):
    """Display model performance metrics and feature importances."""
    console.print(Panel.fit("[bold cyan]ThreatSynth 79 // Model Performance & Feature Importances[/bold cyan]"))
    
    if not threat_ml.is_trained:
        console.print("[red]Model is not trained yet. Run 'python -m threatsynth.cli train' first.[/red]")
        return

    table = Table(title="Global Feature Importances (Random Forest)", border_style="magenta")
    table.add_column("Rank", justify="center", style="cyan")
    table.add_column("Feature Name", style="bold white")
    table.add_column("Importance Weight", justify="right", style="green")

    if hasattr(threat_ml.classifier, "feature_importances_"):
        imps = list(zip(FEATURE_NAMES, threat_ml.classifier.feature_importances_))
        imps.sort(key=lambda x: x[1], reverse=True)
        for rank, (name, val) in enumerate(imps, 1):
            table.add_row(str(rank), name, f"{val:.4f}")

    console.print(table)


def cmd_ingest(args):
    """Ingest a JSON alert file from CLI and print triage result."""
    console.print(Panel.fit(f"[bold cyan]ThreatSynth 79 // Alert Ingestion: {args.file}[/bold cyan]"))
    
    with open(args.file, "r", encoding="utf-8") as f:
        data = json.load(f)

    alerts = data if isinstance(data, list) else [data]
    for alert in alerts:
        res = threat_ml.predict_alert(alert)
        risk = res["risk_level"]
        color = "red" if risk == "High" else "yellow" if risk == "Medium" else "green"

        console.print(f"\n[bold white]Alert ID:[/bold white] {alert.get('alert_id', 'N/A')}")
        console.print(f"[bold white]Title:[/bold white] {alert.get('alert_name', 'Security Alert')}")
        console.print(f"[bold white]Risk Level:[/bold white] [{color} bold]{risk}[/{color} bold] (Confidence: {res['confidence']:.2f})")
        console.print(f"[bold white]Anomaly Score:[/bold white] {res['anomaly_score']:.2f}")
        console.print(f"[bold white]Explainability Summary:[/bold white] {res['explainability']['explanation_summary']}")
        
        genai = res.get("genai_brief", {})
        console.print(f"[bold cyan]Gen-AI Threat Brief:[/bold cyan] {genai.get('executive_summary')}")
        console.print(f"[bold magenta]MITRE ATT&CK:[/bold magenta] {genai.get('mitre_attack', {}).get('technique_id')} - {genai.get('mitre_attack', {}).get('technique_name')}")


def cmd_audit(args):
    """Inspect and verify cryptographic audit log chain."""
    console.print(Panel.fit("[bold cyan]ThreatSynth 79 // Cryptographic Audit Log Verification[/bold cyan]"))
    
    verification = audit_logger.verify_integrity()
    if verification["valid"]:
        console.print(f"[bold green][OK] AUDIT INTEGRITY SECURE: {verification['total_events']} events cryptographically verified.[/bold green]")
        console.print(f"[dim]Latest Hash: {verification.get('latest_hash')}[/dim]")
    else:
        console.print(f"[bold red][FAIL] AUDIT TAMPERING DETECTED: {verification}[/bold red]")

    recent = audit_logger.query(limit=args.limit or 10)
    table = Table(title="Recent Audit Events", border_style="blue")
    table.add_column("Timestamp", style="dim")
    table.add_column("User (Role)", style="bold white")
    table.add_column("Action", style="cyan")
    table.add_column("Status", justify="center")
    table.add_column("Outcome")

    for e in recent:
        status_style = "green" if e["status_code"] == 200 else "red" if e["status_code"] == 403 else "yellow"
        table.add_row(
            e["timestamp"][:19].replace("T", " "),
            f"{e['username']} ({e['role']})",
            e["action"],
            f"[{status_style}]{e['status_code']}[/{status_style}]",
            f"[{status_style}]{e['outcome']}[/{status_style}]"
        )
    console.print(table)


def cmd_serve(args):
    """Launch the ThreatSynth FastAPI server and Cyber SOC Dashboard."""
    console.print(Panel.fit("[bold green]Starting ThreatSynth 79 Cyber SOC Engine on http://127.0.0.1:8000[/bold green]"))
    uvicorn.run("threatsynth.api.server:app", host=args.host, port=args.port, reload=args.reload)


def main():
    parser = argparse.ArgumentParser(description="ThreatSynth 79 CLI Management Utility")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    p_train = subparsers.add_parser("train", help="Train/retrain ML classification & anomaly models")
    p_train.add_argument("--samples", type=int, default=800, help="Number of synthetic samples to train on")
    p_train.add_argument("--file", type=str, help="Path to custom JSON training dataset")
    p_train.set_defaults(func=cmd_train)

    p_eval = subparsers.add_parser("evaluate", help="View model evaluation and feature weights")
    p_eval.set_defaults(func=cmd_evaluate)

    p_ingest = subparsers.add_parser("ingest", help="Ingest a JSON security alert file")
    p_ingest.add_argument("file", type=str, help="Path to JSON alert file")
    p_ingest.set_defaults(func=cmd_ingest)

    p_audit = subparsers.add_parser("audit", help="Verify and inspect cryptographic audit log")
    p_audit.add_argument("--limit", type=int, default=15, help="Number of entries to display")
    p_audit.set_defaults(func=cmd_audit)

    p_serve = subparsers.add_parser("serve", help="Launch ThreatSynth 79 web server")
    p_serve.add_argument("--host", type=str, default="127.0.0.1")
    p_serve.add_argument("--port", type=int, default=8000)
    p_serve.add_argument("--reload", action="store_true")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
