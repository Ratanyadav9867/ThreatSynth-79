"""
Security Audit and Ingestion Latency Tracking Middleware
"""
import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from threatsynth.core.audit import audit_logger


class SecurityAuditMiddleware(BaseHTTPMiddleware):
    """Intercepts all requests, tracks processing latency, and records audit logs."""

    async def dispatch(self, request: Request, call_next):
        start_time = time.perf_counter()
        client_ip = request.client.host if request.client else "127.0.0.1"
        path = request.url.path
        method = request.method

        response: Response = await call_next(request)
        duration_ms = (time.perf_counter() - start_time) * 1000.0

        # Inject performance & latency headers
        response.headers["X-ThreatSynth-Latency-MS"] = f"{duration_ms:.2f}"
        response.headers["X-ThreatSynth-Status"] = "SECURE"

        # Log sensitive or API endpoint access
        if path.startswith("/api/") and path != "/api/audit/logs":
            # Extract basic auth hint if present
            auth_header = request.headers.get("Authorization", "")
            user_id = "usr-anonymous"
            role = "unauthorized_guest"
            username = "guest"
            
            if "admin" in auth_header:
                role, username, user_id = "admin", "admin", "usr-admin-01"
            elif "soc_analyst" in auth_header:
                role, username, user_id = "soc_analyst", "soc_analyst", "usr-analyst-02"
            elif "tier1_viewer" in auth_header:
                role, username, user_id = "tier1_viewer", "tier1_viewer", "usr-tier1-03"

            action_desc = f"{method} {path}"
            audit_logger.log(
                user_id=user_id,
                username=username,
                role=role,
                action=action_desc,
                resource=path,
                status_code=response.status_code,
                ip_address=client_ip,
                duration_ms=duration_ms,
                details={"method": method, "query": str(request.query_params)}
            )

        return response
