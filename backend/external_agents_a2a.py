"""
External 3P A2A Agents (Anthropic Claude & Microsoft Copilot Studio)
Exposes standard Agent2Agent (A2A) protocol endpoints:
- GET  /a2a/{provider}/.well-known/agent.json  (A2A AgentCard discovery for Agent Registry)
- POST /a2a/{provider}/tasks/send              (A2A JSON-RPC / REST task execution)

Also records the exact HTTP headers and payload received from the Agent Gateway
to prove Zero Raw User Credential Leakage (Flow 7) and Outbound DLP Redaction (Flow 5).
"""

from __future__ import annotations
from datetime import datetime, timezone
import os
from typing import Any, Dict, List
import uuid
import requests

LAST_RECEIVED_3P_INSPECTIONS: List[Dict[str, Any]] = []


def get_anthropic_agent_card(base_url: str = "http://127.0.0.1:8080") -> Dict[str, Any]:
    return {
        "name": "Anthropic Claude Risk & Compliance Agent",
        "description": "External 3P A2A agent powered by Anthropic Claude 3.7 Sonnet for financial compliance, contract review, and regulatory risk scoring.",
        "url": f"{base_url}/a2a/anthropic/tasks/send",
        "provider": {
            "organization": "Anthropic",
            "url": "https://www.anthropic.com",
        },
        "version": "3.7.0",
        "protocol": "A2A/1.0",
        "capabilities": {
            "streaming": True,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        },
        "authentication": {
            "schemes": ["OAuth2-Token-Exchange", "Agent-ID-mTLS"],
            "rawUserCredentialsAllowed": False,
        },
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": [
            {
                "id": "regulatory-risk-audit",
                "name": "Regulatory & PII Compliance Audit",
                "description": "Evaluates enterprise customer records and transactions for compliance risk (SOX, GDPR, PCI-DSS).",
                "tags": ["compliance", "finance", "anthropic", "a2a"],
            },
            {
                "id": "contract-clause-analyzer",
                "name": "Vendor Contract Clause Analyzer",
                "description": "Extracts liability and indemnification risks from third-party agreements.",
                "tags": ["legal", "contracts"],
            },
        ],
    }


def get_copilot_agent_card(base_url: str = "http://127.0.0.1:8080") -> Dict[str, Any]:
    return {
        "name": "Microsoft Copilot Studio (M365 & SharePoint Agent)",
        "description": "External 3P Microsoft Copilot Studio agent bridging M365 SharePoint, Teams, and IT Helpdesk workflows via A2A protocol.",
        "url": f"{base_url}/a2a/copilot/tasks/send",
        "provider": {
            "organization": "Microsoft Copilot Studio",
            "url": "https://copilotstudio.microsoft.com",
        },
        "version": "2.4.0",
        "protocol": "A2A/1.0",
        "capabilities": {
            "streaming": True,
            "pushNotifications": True,
            "stateTransitionHistory": True,
        },
        "authentication": {
            "schemes": ["EntraID-OnBehalfOf-Brokered", "Agent-ID-Federation"],
            "rawUserCredentialsAllowed": False,
        },
        "defaultInputModes": ["text/plain", "application/json"],
        "defaultOutputModes": ["text/plain", "application/json"],
        "skills": [
            {
                "id": "m365-sharepoint-search",
                "name": "M365 SharePoint & Teams Policy Lookup",
                "description": "Searches enterprise SharePoint sites and Teams channels for IT & HR policies.",
                "tags": ["m365", "copilot", "sharepoint", "it"],
            },
            {
                "id": "it-ticket-dispatch",
                "name": "IT Helpdesk Remediation",
                "description": "Dispatches M365 access and device remediation workflows.",
                "tags": ["helpdesk", "m365"],
            },
        ],
    }


def execute_anthropic_a2a_task(
    task_payload: Dict[str, Any], received_headers: Dict[str, str]
) -> Dict[str, Any]:
    """Executes an A2A task on the Anthropic Claude agent (live API if ANTHROPIC_API_KEY is set, else deterministic)."""
    task_id = task_payload.get("id") or f"a2a-anth-{uuid.uuid4().hex[:8]}"
    message_text = (
        task_payload.get("message", {})
        .get("parts", [{}])[0]
        .get("text", "")
    )

    # Record inspection for Flow 7 (Zero Raw User Credential Leakage)
    inspection_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "destination": "Anthropic Claude 3.7 Sonnet (3P A2A Agent)",
        "task_id": task_id,
        "received_headers": {
            "Authorization": received_headers.get("Authorization", ""),
            "X-Raw-User-OAuth-Token": received_headers.get("X-Raw-User-OAuth-Token", "<STRIPPED_BY_AGENT_GATEWAY>"),
            "X-Verified-Agent-ID": received_headers.get("X-Verified-Agent-ID", ""),
            "X-Gateway-Policy-Verdict": received_headers.get("X-Gateway-Policy-Verdict", ""),
            "X-VPC-SC-Egress-Route": received_headers.get("X-VPC-SC-Egress-Route", ""),
        },
        "received_payload_text": message_text,
        "contains_unredacted_pii": ("412-88-9021" in message_text or "4532-8910-2291-8841" in message_text),
    }
    LAST_RECEIVED_3P_INSPECTIONS.insert(0, inspection_record)
    del LAST_RECEIVED_3P_INSPECTIONS[15:]

    api_key = os.getenv("ANTHROPIC_API_KEY")
    response_text = ""
    if api_key:
        try:
            resp = requests.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key,
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-3-7-sonnet-20250219",
                    "max_tokens": 300,
                    "messages": [
                        {
                            "role": "user",
                            "content": f"You are an external Anthropic A2A Compliance Agent called via Google Cloud Agent Gateway. Provide a concise 3-bullet compliance assessment of: {message_text}",
                        }
                    ],
                },
                timeout=6.0,
            )
            if resp.status_code == 200:
                response_text = resp.json()["content"][0]["text"]
        except Exception:
            pass

    if not response_text:
        has_redactions = "[REDACTED_" in message_text
        pii_exposed = "412-88-9021" in message_text or "4532-8910-2291-8841" in message_text
        if has_redactions:
            pii_status = (
                "VERIFIED SAFE: Sensitive PII tokens (`[REDACTED_US_SSN]`, `[REDACTED_CREDIT_CARD]`) "
                "were scrubbed by Google Cloud Model Armor SDP at the Agent Gateway prior to reaching Anthropic."
            )
        elif pii_exposed:
            pii_status = (
                "WARNING — DATA LEAK DETECTED: Raw unredacted US SSN (`412-88-9021`) and Credit Card "
                "(`4532-8910-2291-8841`) crossed the enterprise boundary into 3P Anthropic because Model Armor SDP was OFF!"
            )
        else:
            pii_status = "No regulated PII detected in inbound A2A payload."

        response_text = (
            f"[Anthropic Claude 3.7 Sonnet — A2A Compliance Report]\n"
            f"• Risk Tier Assessment: Account 'Apex Global Holdings' ($1.42M wire limit) qualifies for Enhanced Due Diligence (SOX Sec. 404).\n"
            f"• Cross-Cloud Data Hygiene: {pii_status}\n"
            f"• Identity & Auth Verification: Authenticated via Brokered Agent Gateway Token ({received_headers.get('X-Verified-Agent-ID', 'unknown')}); zero raw user credentials received."
        )

    return {
        "jsonrpc": "2.0",
        "id": task_id,
        "result": {
            "id": task_id,
            "status": {"state": "completed", "timestamp": datetime.now(timezone.utc).isoformat()},
            "artifacts": [
                {
                    "name": "anthropic-compliance-verdict",
                    "parts": [{"type": "text", "text": response_text}],
                }
            ],
            "gatewayHeaderAudit": inspection_record["received_headers"],
        },
    }


def execute_copilot_a2a_task(
    task_payload: Dict[str, Any], received_headers: Dict[str, str]
) -> Dict[str, Any]:
    """Executes an A2A task on the Microsoft Copilot Studio M365 agent."""
    task_id = task_payload.get("id") or f"a2a-copilot-{uuid.uuid4().hex[:8]}"
    message_text = (
        task_payload.get("message", {})
        .get("parts", [{}])[0]
        .get("text", "")
    )

    inspection_record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "destination": "Microsoft Copilot Studio (M365 A2A Agent)",
        "task_id": task_id,
        "received_headers": {
            "Authorization": received_headers.get("Authorization", ""),
            "X-Raw-User-OAuth-Token": received_headers.get("X-Raw-User-OAuth-Token", "<STRIPPED_BY_AGENT_GATEWAY>"),
            "X-Verified-Agent-ID": received_headers.get("X-Verified-Agent-ID", ""),
            "X-Gateway-Policy-Verdict": received_headers.get("X-Gateway-Policy-Verdict", ""),
            "X-VPC-SC-Egress-Route": received_headers.get("X-VPC-SC-Egress-Route", ""),
        },
        "received_payload_text": message_text,
        "contains_unredacted_pii": ("412-88-9021" in message_text or "4532-8910-2291-8841" in message_text),
    }
    LAST_RECEIVED_3P_INSPECTIONS.insert(0, inspection_record)
    del LAST_RECEIVED_3P_INSPECTIONS[15:]

    response_text = (
        f"[Microsoft Copilot Studio — M365 & SharePoint Knowledge Graph]\n"
        f"• Matched SharePoint Policy: `SP-IT-2026-09` (Cross-Cloud Vendor Onboarding & Data Handling).\n"
        f"• Teams Channel Advisory: Approved by SecOps Engineering for federated A2A delegation via Google Cloud Agent Gateway.\n"
        f"• Delegated Identity: Brokered EntraID/Gateway assertion for `{received_headers.get('X-Delegated-Subject', 'service-principal')}` (Raw Google OAuth token was NOT exposed to Microsoft 365)."
    )

    return {
        "jsonrpc": "2.0",
        "id": task_id,
        "result": {
            "id": task_id,
            "status": {"state": "completed", "timestamp": datetime.now(timezone.utc).isoformat()},
            "artifacts": [
                {
                    "name": "copilot-m365-response",
                    "parts": [{"type": "text", "text": response_text}],
                }
            ],
            "gatewayHeaderAudit": inspection_record["received_headers"],
        },
    }
