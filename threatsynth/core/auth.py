"""
Authentication and Role-Based Access Control (RBAC) Module
Implements Identity-Based Access Control, JWT signing/verification, and mock OAuth 2.0 / IdP.
"""
import time
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any, List
import jwt
from fastapi import Header, HTTPException, status, Depends
from threatsynth.config import JWT_SECRET, JWT_ALGORITHM, JWT_EXPIRATION_MINUTES, MOCK_USERS


def generate_jwt_token(user: Dict[str, Any]) -> str:
    """Generate a signed RFC 7519 JWT for an authenticated identity."""
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user["user_id"],
        "username": user["username"],
        "full_name": user["full_name"],
        "role": user["role"],
        "department": user["department"],
        "email": user["email"],
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXPIRATION_MINUTES)).timestamp()),
        "iss": "threatsynth-idp-mock-oauth2"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_jwt_token(token: str) -> Dict[str, Any]:
    """Decode and validate a JWT token signature and expiration."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token has expired. Please authenticate again."
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid authentication token: {str(e)}"
        )


def authenticate_user(username_or_token: str, password: Optional[str] = None) -> Dict[str, Any]:
    """
    Authenticate against the Mock Identity Provider / OAuth 2.0 stub.
    Supports either username + password OR direct token lookup.
    """
    # 1. Direct username lookup
    if username_or_token in MOCK_USERS:
        user_info = MOCK_USERS[username_or_token]
        if password is None or password == user_info["password"]:
            token = generate_jwt_token(user_info)
            return {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": JWT_EXPIRATION_MINUTES * 60,
                "user": {
                    "user_id": user_info["user_id"],
                    "username": user_info["username"],
                    "full_name": user_info["full_name"],
                    "role": user_info["role"],
                    "department": user_info["department"],
                    "email": user_info["email"],
                    "description": user_info["description"]
                }
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials supplied."
            )

    # 2. Token lookup
    if username_or_token.startswith("Bearer "):
        raw_token = username_or_token.split(" ", 1)[1]
    else:
        raw_token = username_or_token

    payload = decode_jwt_token(raw_token)
    return {
        "access_token": raw_token,
        "token_type": "Bearer",
        "user": payload
    }


def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    """
    FastAPI dependency to extract and validate the authenticated user from the Authorization header.
    Defaults to anonymous/guest if missing.
    """
    if not authorization:
        # Fallback to unauthorized guest role
        return {
            "user_id": "usr-anonymous",
            "username": "anonymous",
            "full_name": "Anonymous Guest",
            "role": "unauthorized_guest",
            "department": "External",
            "email": "anonymous@external.net"
        }

    token = authorization
    if authorization.startswith("Bearer "):
        token = authorization[7:]

    # Check if a direct username was sent as shorthand in mock mode
    if token in MOCK_USERS:
        return MOCK_USERS[token]

    try:
        return decode_jwt_token(token)
    except HTTPException:
        # If token was invalid, treat as guest with error
        raise


def require_roles(allowed_roles: List[str]):
    """
    FastAPI dependency factory to enforce Role-Based Access Control (RBAC).
    Raises HTTP 403 Forbidden if user's role is not permitted.
    """
    def role_checker(current_user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
        user_role = current_user.get("role", "unauthorized_guest")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: Role '{user_role}' is not authorized to perform this operation. Required: {', '.join(allowed_roles)}"
            )
        return current_user

    return role_checker


def sanitize_alert_for_role(alert: Dict[str, Any], user_role: str) -> Dict[str, Any]:
    """
    Redact sensitive forensic intelligence for lower-tier roles (Tier 1 Viewer / Unauthorized).
    SOC Analysts and Admins see full payload, explainability weights, and AI playbooks.
    """
    sanitized = alert.copy()
    if user_role in ["admin", "soc_analyst"]:
        # Full access
        sanitized["access_level"] = "FULL_ACCESS"
        return sanitized

    # Redact sensitive data for tier1_viewer
    sanitized["access_level"] = "REDACTED_TIER1"
    sanitized["sensitive_payload"] = "[REDACTED - RESTRICTED TO SOC ANALYSTS & ADMINS]"
    sanitized["raw_event"] = "[REDACTED - FORENSIC ACCESS RESTRICTED]"
    sanitized["ai_summary"] = "[REDACTED - REQUIRE SOC ANALYST ROLE TO VIEW RISK EXPLANATIONS]"
    sanitized["remediation_playbook"] = ["[REDACTED - RESTRICTED PLAYBOOK]"]
    if "explainability" in sanitized:
        sanitized["explainability"] = {
            "status": "RESTRICTED",
            "message": "Detailed SHAP factor weights and decision contributions are restricted to SOC Analysts."
        }
    return sanitized
