"""
Main FastAPI Control Plane & Interactive Demo Server
Serves:
- Interactive "Gemini Enterprise Agent Platform — Live Demo Cockpit" UI at `/`
- Agent Registry API (`/api/registry/*`)
- Agent Gateway & Policy Decision Point API (`/api/gateway/*`)
- Model Armor Configuration & Live Inspection API (`/api/model-armor/*`)
- Standard A2A Protocol Endpoints (`/a2a/anthropic/.well-known/agent.json`, `/a2a/copilot/.well-known/agent.json`, `/a2a/*/tasks/send`)
- 3P Credential & Payload Inspector API (`/api/a2a/inspections`)
"""

from __future__ import annotations
import hashlib
import hmac
import json
import os
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional
from fastapi import Cookie, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

try:
    from google.auth.transport import requests as google_auth_requests
    from google.oauth2 import id_token as google_id_token
except ImportError:
    google_auth_requests = None  # type: ignore
    google_id_token = None  # type: ignore

from .agent_gateway import (
    EXECUTION_AUDIT_LOG,
    GatewayExecutionRequest,
    run_agent_gateway_flow,
)
from .agent_registry import RegisterExternalAgentRequest, registry_store
from .external_agents_a2a import (
    LAST_RECEIVED_3P_INSPECTIONS,
    execute_anthropic_a2a_task,
    execute_copilot_a2a_task,
    get_anthropic_agent_card,
    get_copilot_agent_card,
)
from .mcp_servers import mcp_simulator
from .model_armor_service import model_armor_engine

app = FastAPI(
    title="Gemini Enterprise Agent Platform — Governance, Gateway & Model Armor Demo",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"


class GatewayTogglePayload(BaseModel):
    registered_in_registry: Optional[bool] = None
    gateway_enabled: Optional[bool] = None
    psc_egress_approved: Optional[bool] = None


class JiraPoisonTogglePayload(BaseModel):
    poisoned: bool


class GoogleLoginPayload(BaseModel):
    credential: str  # Cryptographically signed Google / Firebase OIDC ID token (JWT)


ALLOWED_DOMAINS = tuple(
    d.strip().lower()
    for d in os.getenv("ALLOWED_DOMAINS", "google.com").split(",")
    if d.strip()
)
SESSION_COOKIE_NAME = "agd_session"
SESSION_HMAC_SECRET = os.getenv(
    "SESSION_HMAC_SECRET",
    "agent-governance-demo-cockpit-secure-session-key-v1",
).encode("utf-8")
FIREBASE_AUTH_API_KEY = os.getenv("FIREBASE_AUTH_API_KEY", "").strip()
FIREBASE_AUTH_DOMAIN = os.getenv("FIREBASE_AUTH_DOMAIN", "").strip()
FIREBASE_AUTH_PROJECT_ID = os.getenv("FIREBASE_AUTH_PROJECT_ID", "").strip()


def _create_signed_session_cookie(email: str, ttl_seconds: int = 86400 * 7) -> str:
    exp = int(time.time()) + ttl_seconds
    payload = f"{email.lower().strip()}|{exp}"
    sig = hmac.new(SESSION_HMAC_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}|{sig}"


def _verify_signed_session_cookie(cookie_val: Optional[str]) -> Optional[str]:
    if not cookie_val or cookie_val.count("|") != 2:
        return None
    email, exp_str, sig = cookie_val.split("|", 2)
    try:
        exp = int(exp_str)
    except ValueError:
        return None
    if time.time() > exp:
        return None
    expected_payload = f"{email}|{exp_str}"
    expected_sig = hmac.new(
        SESSION_HMAC_SECRET, expected_payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(sig, expected_sig):
        return None
    domain = email.split("@", 1)[-1].lower().strip()
    if domain not in ALLOWED_DOMAINS:
        return None
    return email


def _verify_google_or_firebase_jwt(raw_token: str) -> str:
    """Cryptographically verifies a Google or Firebase OAuth 2.0 ID token and returns the verified email."""
    token = raw_token.strip()
    if not token:
        raise HTTPException(status_code=401, detail="Missing Google OAuth ID token.")

    # 1. Verify via google.oauth2.id_token (Firebase Auth SecureToken or Google OAuth2 certs)
    if google_id_token and google_auth_requests:
        try:
            id_info = google_id_token.verify_firebase_token(
                token,
                google_auth_requests.Request(),
                audience=FIREBASE_AUTH_PROJECT_ID or None,
            )
            if id_info and id_info.get("email") and id_info.get("email_verified", True):
                return str(id_info["email"]).lower().strip()
        except Exception:
            pass

        try:
            oauth_client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
            id_info = google_id_token.verify_oauth2_token(
                token,
                google_auth_requests.Request(),
                oauth_client_id or None,
            )
            if id_info and id_info.get("email") and id_info.get("email_verified", True):
                return str(id_info["email"]).lower().strip()
        except Exception:
            pass

    # 2. Verify directly with Google Identity Toolkit accounts:lookup endpoint
    if FIREBASE_AUTH_API_KEY:
        try:
            lookup_url = f"https://identitytoolkit.googleapis.com/v1/accounts:lookup?key={FIREBASE_AUTH_API_KEY}"
            req = urllib.request.Request(
                lookup_url,
                data=json.dumps({"idToken": token}).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                users = body.get("users") or []
                if users and users[0].get("email") and users[0].get("emailVerified", True):
                    return str(users[0]["email"]).lower().strip()
        except Exception as exc:
            raise HTTPException(
                status_code=401,
                detail=f"Google OAuth token cryptographic verification failed: {exc}",
            ) from exc

    raise HTTPException(status_code=401, detail="Invalid or expired Google OAuth ID token.")


def _resolve_authenticated_email(request: Request) -> Optional[str]:
    # 1. Primary: Google Cloud IAP header (if IAP is active in front of the service)
    raw_iap_email = request.headers.get("x-goog-authenticated-user-email", "")
    if raw_iap_email:
        email = raw_iap_email.split(":", 1)[-1].lower().strip()
        domain = email.split("@", 1)[-1] if "@" in email else ""
        if domain in ALLOWED_DOMAINS:
            return email

    # 2. Secondary: Cryptographically HMAC-signed session cookie issued after Google OAuth 2.0 login
    session_cookie = request.cookies.get(SESSION_COOKIE_NAME)
    verified_email = _verify_signed_session_cookie(session_cookie)
    if verified_email:
        return verified_email

    # 3. Localhost development fallback (127.0.0.1 / localhost only)
    if request.url.hostname in ("127.0.0.1", "localhost"):
        dev_email = os.getenv("DEV_USER_EMAIL", "developer@google.com")
        return dev_email
    return None


def _require_authenticated_email(request: Request) -> str:
    email = _resolve_authenticated_email(request)
    if not email:
        raise HTTPException(
            status_code=401,
            detail=f"Authentication required: Please sign in with an authorized corporate account ({', '.join(ALLOWED_DOMAINS)}).",
        )
    return email


@app.post("/api/auth/google-login")
def login_with_google_account(
    payload: GoogleLoginPayload,
    request: Request,
    response: Response,
) -> Dict[str, Any]:
    """Cryptographically verifies a Google OAuth 2.0 ID token and enforces domain restrictions."""
    verified_email = _verify_google_or_firebase_jwt(payload.credential)

    if not verified_email or "@" not in verified_email:
        raise HTTPException(status_code=400, detail="Google OAuth token did not contain a valid email address.")

    domain = verified_email.split("@", 1)[-1].lower().strip()
    if domain not in ALLOWED_DOMAINS:
        raise HTTPException(
            status_code=403,
            detail=(
                f"Access Denied: '{verified_email}' (@{domain}) is not permitted. "
                f"Access is restricted to authorized domains: {', '.join(ALLOWED_DOMAINS)}."
            ),
        )

    signed_cookie = _create_signed_session_cookie(verified_email)
    is_secure = request.url.scheme == "https" or request.headers.get("x-forwarded-proto") == "https"
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=signed_cookie,
        max_age=86400 * 7,
        httponly=True,
        secure=is_secure,
        samesite="lax",
    )
    response.delete_cookie("agy_demo_google_user")
    return {
        "status": "AUTHENTICATED",
        "email": verified_email,
        "domain": domain,
    }


@app.post("/api/auth/logout")
def logout_google_account(response: Response) -> Dict[str, Any]:
    response.delete_cookie(SESSION_COOKIE_NAME)
    response.delete_cookie("agy_demo_google_user")
    return {"status": "LOGGED_OUT"}


@app.get("/api/state")
def get_full_demo_state(request: Request) -> Dict[str, Any]:
    """Returns current authentication status and (only when authenticated as @google.com) the full demo state."""
    authenticated_email = _resolve_authenticated_email(request)
    oauth_client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "").strip()
    auth_info = {
        "authenticated": bool(authenticated_email),
        "email": authenticated_email or "",
        "iap_enforced": bool(request.headers.get("x-goog-authenticated-user-email")),
        "google_oauth_client_id": oauth_client_id,
        "firebase_auth": {
            "apiKey": FIREBASE_AUTH_API_KEY,
            "authDomain": FIREBASE_AUTH_DOMAIN,
            "projectId": FIREBASE_AUTH_PROJECT_ID,
        },
        "allowed_domains": list(ALLOWED_DOMAINS),
    }
    if not authenticated_email:
        return {
            "authenticated_user": auth_info,
            "registry": [],
            "model_armor": {},
            "mcp_settings": {},
            "recent_3p_inspections": [],
            "recent_audit_logs": [],
        }

    return {
        "authenticated_user": auth_info,
        "registry": [e.model_dump() for e in registry_store.list_entries()],
        "model_armor": model_armor_engine.config.model_dump(),
        "mcp_settings": {
            "jira_ticket_poisoned": mcp_simulator.jira_ticket_poisoned,
        },
        "recent_3p_inspections": LAST_RECEIVED_3P_INSPECTIONS[:10],
        "recent_audit_logs": [log.model_dump() for log in EXECUTION_AUDIT_LOG[:10]],
    }


@app.post("/api/reset")
def reset_demo_environment(request: Request) -> Dict[str, Any]:
    """Resets Agent Registry, Model Armor rules, and MCP settings to initial demo state."""
    _require_authenticated_email(request)
    registry_store.reset_to_defaults()
    model_armor_engine.apply_preset("STRICT_ENTERPRISE_SDP")
    mcp_simulator.jira_ticket_poisoned = True
    LAST_RECEIVED_3P_INSPECTIONS.clear()
    EXECUTION_AUDIT_LOG.clear()
    return get_full_demo_state(request)


# ---------------------------------------------------------------------------
# Use Case 1 & 2: Agent Registry & Agent Gateway Routing Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/registry")
def list_registry_entries(request: Request) -> Dict[str, Any]:
    _require_authenticated_email(request)
    return {"entries": [e.model_dump() for e in registry_store.list_entries()]}


@app.post("/api/registry/register")
def register_external_agent(req: RegisterExternalAgentRequest, request: Request) -> Dict[str, Any]:
    _require_authenticated_email(request)
    entry = registry_store.register_or_update(req)
    return {"status": "REGISTERED", "entry": entry.model_dump()}


@app.patch("/api/registry/{entry_id}/gateway")
def update_agent_gateway_status(entry_id: str, payload: GatewayTogglePayload, request: Request) -> Dict[str, Any]:
    _require_authenticated_email(request)
    try:
        entry = registry_store.update_gateway_flags(
            entry_id=entry_id,
            registered_in_registry=payload.registered_in_registry,
            gateway_enabled=payload.gateway_enabled,
            psc_egress_approved=payload.psc_egress_approved,
        )
        return {"status": "UPDATED", "entry": entry.model_dump()}
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Use Case 3: Model Armor Configuration & Ad-Hoc Inspection Endpoints
# ---------------------------------------------------------------------------
@app.get("/api/model-armor/config")
def get_model_armor_config(request: Request) -> Dict[str, Any]:
    _require_authenticated_email(request)
    return model_armor_engine.config.model_dump()


@app.post("/api/model-armor/config")
def update_model_armor_config(updates: Dict[str, Any], request: Request) -> Dict[str, Any]:
    _require_authenticated_email(request)
    cfg = model_armor_engine.update_config(updates)
    return {"status": "UPDATED", "config": cfg.model_dump()}


# ---------------------------------------------------------------------------
# Flow 4: 3P MCP Server Poisoned Ticket Toggle
# ---------------------------------------------------------------------------
@app.post("/api/mcp/jira-poison-toggle")
def toggle_jira_poison(payload: JiraPoisonTogglePayload, request: Request) -> Dict[str, Any]:
    _require_authenticated_email(request)
    mcp_simulator.jira_ticket_poisoned = payload.poisoned
    return {"jira_ticket_poisoned": mcp_simulator.jira_ticket_poisoned}


# ---------------------------------------------------------------------------
# Agent Gateway Execution Endpoint (Runs all Use Cases & Boundary Flows)
# ---------------------------------------------------------------------------
@app.post("/api/gateway/execute")
def execute_gateway_flow(
    req: GatewayExecutionRequest,
    request: Request,
) -> Dict[str, Any]:
    authed_email = _require_authenticated_email(request)
    req.user_email = authed_email
    result = run_agent_gateway_flow(req)
    return {
        "execution": result.model_dump(),
        "recent_3p_inspections": LAST_RECEIVED_3P_INSPECTIONS[:10],
    }


# ---------------------------------------------------------------------------
# Standard A2A Protocol Endpoints for External 3P Agents (Anthropic & Copilot)
# ---------------------------------------------------------------------------
@app.get("/a2a/anthropic/.well-known/agent.json")
def anthropic_well_known_agent_card(request: Request) -> JSONResponse:
    base_url = str(request.base_url).rstrip("/")
    return JSONResponse(get_anthropic_agent_card(base_url))


@app.post("/a2a/anthropic/tasks/send")
async def anthropic_a2a_tasks_send(request: Request) -> JSONResponse:
    payload = await request.json()
    headers = {k: v for k, v in request.headers.items()}
    return JSONResponse(execute_anthropic_a2a_task(payload, headers))


@app.get("/a2a/copilot/.well-known/agent.json")
def copilot_well_known_agent_card(request: Request) -> JSONResponse:
    base_url = str(request.base_url).rstrip("/")
    return JSONResponse(get_copilot_agent_card(base_url))


@app.post("/a2a/copilot/tasks/send")
async def copilot_a2a_tasks_send(request: Request) -> JSONResponse:
    payload = await request.json()
    headers = {k: v for k, v in request.headers.items()}
    return JSONResponse(execute_copilot_a2a_task(payload, headers))


# ---------------------------------------------------------------------------
# Serve Frontend UI
# ---------------------------------------------------------------------------
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")


@app.get("/privacy")
def serve_privacy() -> HTMLResponse:
    return HTMLResponse(
        """<!DOCTYPE html>
<html>
<head><title>Privacy Policy - Gemini Enterprise Agent Governance Demo</title></head>
<body style="font-family: sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; line-height: 1.6;">
  <h1>Privacy Policy</h1>
  <p><strong>Gemini Enterprise Agent Governance Demo Cockpit</strong></p>
  <p>This application is an internal and demonstration governance platform deployed on Google Cloud. It authenticates users using Google OAuth 2.0 / Identity-Aware Proxy to demonstrate agent registry, policy enforcement, Model Armor, and security controls.</p>
  <h3>Data Collection & Usage</h3>
  <p>The application only accesses the user's basic profile email address for authentication, authorization, and audit logging within the demonstration environment. No personal data is sold or shared with external parties.</p>
  <h3>Contact</h3>
  <p>For questions or access inquiries, contact the platform administrator.</p>
</body>
</html>"""
    )


@app.get("/")
def serve_index() -> FileResponse:
    return FileResponse(str(FRONTEND_DIR / "index.html"))
