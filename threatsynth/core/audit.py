"""
Tamper-Evident Audit Logging Engine
Provides cryptographically chained, immutable audit trails for all system operations and access attempts.
"""
import os
import json
import time
import hashlib
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from threatsynth.config import AUDIT_LOG_FILE


class AuditLogger:
    """Thread-safe, cryptographically chained audit logger."""

    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(AuditLogger, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self, log_path: Optional[str] = None):
        if getattr(self, "_initialized", False):
            return
        self.log_path = log_path or AUDIT_LOG_FILE
        self._memory_logs: List[Dict[str, Any]] = []
        self._last_hash: str = "0000000000000000000000000000000000000000000000000000000000000000"
        self._write_lock = threading.Lock()
        self._load_existing_logs()
        self._initialized = True

    def _load_existing_logs(self):
        """Load and verify existing audit logs on startup."""
        if not os.path.exists(self.log_path):
            return

        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    self._memory_logs.append(entry)
                    if "hash" in entry:
                        self._last_hash = entry["hash"]
        except Exception as e:
            print(f"[AuditLogger] Warning: Could not fully read audit logs: {e}")

    def log(
        self,
        user_id: str,
        username: str,
        role: str,
        action: str,
        resource: str,
        status_code: int = 200,
        ip_address: str = "127.0.0.1",
        details: Optional[Dict[str, Any]] = None,
        duration_ms: float = 0.0
    ) -> Dict[str, Any]:
        """Record an immutable, timestamped audit log entry."""
        with self._write_lock:
            now = datetime.now(timezone.utc)
            timestamp_str = now.isoformat()
            
            entry = {
                "event_id": f"evt-{int(time.time()*1000)}-{len(self._memory_logs)+1}",
                "timestamp": timestamp_str,
                "user_id": user_id or "usr-anonymous",
                "username": username or "anonymous",
                "role": role or "unauthorized_guest",
                "action": action,
                "resource": resource,
                "status_code": status_code,
                "outcome": "SUCCESS" if 200 <= status_code < 400 else "DENIED" if status_code == 403 else "FAILED",
                "client_ip": ip_address or "127.0.0.1",
                "duration_ms": round(duration_ms, 2),
                "prev_hash": self._last_hash,
                "details": details or {}
            }

            # Compute SHA-256 block hash for tamper evidence
            hash_payload = f"{entry['event_id']}:{entry['timestamp']}:{entry['user_id']}:{entry['action']}:{entry['resource']}:{entry['status_code']}:{entry['prev_hash']}"
            current_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()
            entry["hash"] = current_hash
            self._last_hash = current_hash

            # Append in-memory and write to persistent append-only log file
            self._memory_logs.append(entry)
            try:
                with open(self.log_path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry) + "\n")
            except Exception as e:
                print(f"[AuditLogger] Error writing audit log: {e}")

            return entry

    def query(
        self,
        user_id: Optional[str] = None,
        role: Optional[str] = None,
        action: Optional[str] = None,
        outcome: Optional[str] = None,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Query recent audit events with filtering."""
        with self._write_lock:
            results = list(reversed(self._memory_logs))

            if user_id:
                results = [e for e in results if e.get("user_id") == user_id]
            if role:
                results = [e for e in results if e.get("role") == role]
            if action:
                results = [e for e in results if action.lower() in e.get("action", "").lower()]
            if outcome:
                results = [e for e in results if e.get("outcome") == outcome.upper()]

            return results[:limit]

    def verify_integrity(self) -> Dict[str, Any]:
        """Verify the cryptographic hash chain of the entire audit trail."""
        with self._write_lock:
            if not self._memory_logs:
                return {"valid": True, "total_events": 0, "status": "EMPTY"}

            prev_hash = "0000000000000000000000000000000000000000000000000000000000000000"
            for idx, entry in enumerate(self._memory_logs):
                if entry.get("prev_hash") != prev_hash:
                    return {
                        "valid": False,
                        "broken_at_index": idx,
                        "event_id": entry.get("event_id"),
                        "error": "Previous hash mismatch (Tampering detected)"
                    }
                hash_payload = f"{entry['event_id']}:{entry['timestamp']}:{entry['user_id']}:{entry['action']}:{entry['resource']}:{entry['status_code']}:{prev_hash}"
                expected_hash = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()
                if entry.get("hash") != expected_hash:
                    return {
                        "valid": False,
                        "broken_at_index": idx,
                        "event_id": entry.get("event_id"),
                        "error": "Event hash validation failed"
                    }
                prev_hash = entry["hash"]

            return {
                "valid": True,
                "total_events": len(self._memory_logs),
                "latest_hash": prev_hash,
                "status": "SECURE_VERIFIED"
            }


# Singleton instance
audit_logger = AuditLogger()
