"""
Agent Sandbox & Agent Context Resources (Diagram 2)
Simulates:
1. Agent Sandbox (`code • shell • files`): Ephemeral code execution environment where direct
   internet/3P connections are blocked by VPC-SC unless routed through the Agent Gateway.
2. Agent Context Resources (`Memory Bank` & `Artifact Storage - GCS, per-task folders`):
   Strictly isolated per agent with harness-only access (`gs://enterprise-agent-context/{agent_id}/{task_id}/`).
"""

from __future__ import annotations
import os
from datetime import datetime, timezone
from typing import Any, Dict


def evaluate_sandbox_and_context_isolation(
    scenario_type: str,
    active_agent_id: str,
    target_resource_owner_agent_id: str,
    command_or_action: str,
) -> Dict[str, Any]:
    """Evaluates Agent Sandbox & Context Resource boundary controls from Diagram 2."""
    now = datetime.now(timezone.utc).isoformat()

    if scenario_type == "SANDBOX_DIRECT_INTERNET_EGRESS":
        return {
            "timestamp": now,
            "component": "Agent Sandbox (code • shell • files)",
            "agent_id": active_agent_id,
            "attempted_action": command_or_action,
            "verdict": "BLOCKED_BY_SANDBOX_VPC_SC",
            "reason": (
                "Internet & 3P tools are OFF by default inside VPC-SC. "
                "Processes inside Agent Sandbox have no direct external network route; "
                "all outbound calls must traverse the Agent Harness -> Agent Gateway Policy Decision Points."
            ),
            "boundary_controls_enforced": ["VPC-SC", "Agent Sandbox Network Namespace", "Default-Deny Egress"],
        }

    if scenario_type == "CROSS_AGENT_MEMORY_BANK_READ":
        allowed = active_agent_id == target_resource_owner_agent_id
        project_id = os.getenv("GCP_PROJECT_ID", "enterprise-agent-prj")
        return {
            "timestamp": now,
            "component": "Agent Context Resources (Memory Bank & Per-Task GCS)",
            "active_agent_id": active_agent_id,
            "requested_gcs_path": f"gs://{project_id}-agent-context/{target_resource_owner_agent_id}/task-8821/memory_bank.json",
            "attempted_action": command_or_action,
            "verdict": "ALLOWED" if allowed else "BLOCKED_BY_HARNESS_CONTEXT_ISOLATION",
            "reason": (
                "Access granted via Agent Harness to own task folder."
                if allowed
                else (
                    f"Cross-agent context access denied: '{active_agent_id}' cannot read Memory Bank or "
                    f"per-task GCS artifacts belonging to '{target_resource_owner_agent_id}'. "
                    "Context resources are isolated per agent with harness-only access (CMEK + IAM scoped)."
                )
            ),
            "boundary_controls_enforced": ["Agent ID Scoping", "Harness-Only Access", "CMEK", "Per-Task GCS Isolation"],
        }

    return {
        "timestamp": now,
        "component": "Agent Sandbox",
        "verdict": "ALLOWED",
        "reason": "Local computation inside ephemeral sandbox succeeded.",
    }
