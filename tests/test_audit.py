"""
Tests for Tamper-Evident Cryptographic Audit Logging
"""
from threatsynth.core.audit import AuditLogger


def test_audit_logging_and_hash_chain():
    """Verify cryptographic SHA-256 block chaining in audit logger."""
    logger = AuditLogger()

    # Log several actions
    logger.log("usr-1", "user1", "soc_analyst", "VIEW_ALERT", "/api/alerts/1", 200)
    logger.log("usr-2", "user2", "unauthorized_guest", "VIEW_PAYLOAD", "/api/alerts/1", 403)
    logger.log("usr-3", "user3", "admin", "RETRAIN_MODEL", "/api/model/retrain", 200)

    # Verify integrity
    integrity = logger.verify_integrity()
    assert integrity["valid"] is True
    assert integrity["total_events"] >= 3
    assert integrity["status"] == "SECURE_VERIFIED"
