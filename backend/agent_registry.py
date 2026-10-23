"""
Agent Registry Service
Central hub for 1P (ADK/Gemini) and 3P (Anthropic, Microsoft Copilot) agents,
Skills, and MCP/Connectors (Workspace, M365, Jira, BigQuery).
"""

from __future__ import annotations
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AgentSkill(BaseModel):
    id: str
    name: str
    description: str
    tags: List[str] = Field(default_factory=list)


class AgentCard(BaseModel):
    """A2A Protocol compliant AgentCard (.well-known/agent.json)."""
    name: str
    description: str
    url: str
    provider: str
    version: str = "1.0.0"
    protocol: str = "A2A/1.0"
    capabilities: Dict[str, bool] = Field(
        default_factory=lambda: {
            "streaming": True,
            "pushNotifications": False,
            "stateTransitionHistory": True,
        }
    )
    authentication: Dict[str, Any] = Field(
        default_factory=lambda: {
            "schemes": ["OAuth2-Token-Exchange", "Agent-ID-mTLS"],
            "rawUserCredentialsAllowed": False,
        }
    )
    defaultInputModes: List[str] = Field(default_factory=lambda: ["text/plain", "application/json"])
    defaultOutputModes: List[str] = Field(default_factory=lambda: ["text/plain", "application/json"])
    skills: List[AgentSkill] = Field(default_factory=list)


class RegistryEntry(BaseModel):
    id: str
    agent_id_uri: str
    name: str
    provider: str  # "Google 1P (ADK)", "Anthropic", "Microsoft Copilot Studio", "MCP Server", "Skill"
    category: str  # "1P_AGENT", "3P_AGENT", "MCP_CONNECTOR", "SKILL"
    protocol: str  # "ADK", "A2A", "MCP", "SKILL_MANIFEST"
    endpoint_url: str
    well_known_url: Optional[str] = None
    description: str
    registered_in_registry: bool = True
    gateway_enabled: bool = True
    psc_egress_approved: bool = True
    identity_mode: str = "BOTH"  # "PERSONAL", "COWORKER", "BOTH"
    scopes: List[str] = Field(default_factory=list)
    agent_card: Optional[AgentCard] = None
    registered_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class RegisterExternalAgentRequest(BaseModel):
    id: Optional[str] = None
    name: str
    provider: str
    protocol: str = "A2A"
    endpoint_url: str
    well_known_url: Optional[str] = None
    description: str
    gateway_enabled: bool = True
    psc_egress_approved: bool = True
    skills: List[Dict[str, Any]] = Field(default_factory=list)


class AgentRegistryStore:
    """In-memory + state-resettable Agent Registry store for the live demo."""

    def __init__(self) -> None:
        self.entries: Dict[str, RegistryEntry] = {}
        self.reset_to_defaults()

    def reset_to_defaults(self) -> None:
        now = datetime.now(timezone.utc).isoformat()
        self.entries = {
            # 1P Orchestrator Agent (ADK)
            "adk-enterprise-orchestrator": RegistryEntry(
                id="adk-enterprise-orchestrator",
                agent_id_uri="agent-id://enterprise-agent-prj/sa/adk-orchestrator-agent@enterprise-agent-prj.iam.gserviceaccount.com",
                name="Gemini Enterprise Orchestrator (ADK)",
                provider="Google 1P (ADK / Gemini 2.5)",
                category="1P_AGENT",
                protocol="ADK",
                endpoint_url="internal://agent-harness/adk-orchestrator",
                description="Primary customer-managed ADK agent running in Google Managed Agent Harness with isolated Memory Bank & Agent Sandbox in enterprise-agent-prj.",
                registered_in_registry=True,
                gateway_enabled=True,
                psc_egress_approved=True,
                identity_mode="BOTH",
                scopes=["bigquery.read", "workspace.mcp", "a2a.delegate", "sandbox.exec"],
                registered_at=now,
            ),
            # 3P Agent 1: Anthropic Claude (Pre-populated so user can toggle or re-register live)
            "anthropic-claude-compliance": RegistryEntry(
                id="anthropic-claude-compliance",
                agent_id_uri="agent-id://enterprise-agent-prj.external-3p/anthropic/claude-compliance-v1",
                name="Anthropic Claude Risk & Compliance Agent",
                provider="Anthropic (Claude 3.7 Sonnet via A2A)",
                category="3P_AGENT",
                protocol="A2A",
                endpoint_url="http://127.0.0.1:8080/a2a/anthropic/tasks/send",
                well_known_url="http://127.0.0.1:8080/a2a/anthropic/.well-known/agent.json",
                description="External 3P A2A agent hosted on Anthropic Claude for regulatory contract review, policy auditing, and risk scoring.",
                registered_in_registry=True,
                gateway_enabled=True,
                psc_egress_approved=True,
                identity_mode="BOTH",
                scopes=["a2a.tasks.send", "compliance.review"],
                agent_card=AgentCard(
                    name="Anthropic Claude Risk & Compliance Agent",
                    description="3P A2A Compliance & Financial Risk Reviewer powered by Claude.",
                    url="http://127.0.0.1:8080/a2a/anthropic/tasks/send",
                    provider="Anthropic",
                    version="3.7.0",
                    skills=[
                        AgentSkill(
                            id="regulatory-risk-audit",
                            name="Regulatory & PII Compliance Audit",
                            description="Evaluates enterprise summaries and transactions for regulatory risk.",
                            tags=["compliance", "finance", "anthropic", "a2a"],
                        ),
                        AgentSkill(
                            id="contract-clause-analyzer",
                            name="Contract Clause Analyzer",
                            description="Extracts indemnification and liability risks from vendor contracts.",
                            tags=["legal", "contracts"],
                        ),
                    ],
                ),
                registered_at=now,
            ),
            # 3P Agent 2: Microsoft Copilot Studio (Starts UNREGISTERED or Gateway-Disabled to demo onboarding!)
            "ms-copilot-m365-assistant": RegistryEntry(
                id="ms-copilot-m365-assistant",
                agent_id_uri="agent-id://enterprise-agent-prj.external-3p/microsoft/copilot-m365-it",
                name="Microsoft Copilot Studio (M365 & SharePoint Agent)",
                provider="Microsoft Copilot Studio (A2A Bridge)",
                category="3P_AGENT",
                protocol="A2A",
                endpoint_url="http://127.0.0.1:8080/a2a/copilot/tasks/send",
                well_known_url="http://127.0.0.1:8080/a2a/copilot/.well-known/agent.json",
                description="External 3P Microsoft Copilot agent for M365 Teams/SharePoint knowledge lookup and IT helpdesk automation.",
                registered_in_registry=False,  # Ready for Use Case 1 1-click Registration demo!
                gateway_enabled=False,
                psc_egress_approved=False,
                identity_mode="PERSONAL",
                scopes=["m365.sharepoint.read", "m365.teams.message", "a2a.tasks.send"],
                agent_card=AgentCard(
                    name="Microsoft Copilot Studio — M365 & SharePoint Agent",
                    description="Bridges Microsoft 365 Graph, SharePoint, and ServiceNow IT workflows via A2A protocol.",
                    url="http://127.0.0.1:8080/a2a/copilot/tasks/send",
                    provider="Microsoft Copilot Studio",
                    version="2.4.0",
                    skills=[
                        AgentSkill(
                            id="m365-sharepoint-search",
                            name="M365 SharePoint & Teams Policy Lookup",
                            description="Retrieves enterprise IT policies and SharePoint change advisories.",
                            tags=["m365", "copilot", "sharepoint", "it"],
                        ),
                        AgentSkill(
                            id="it-ticket-dispatch",
                            name="IT Helpdesk Remediation",
                            description="Creates and updates M365 IT incident workflows.",
                            tags=["helpdesk", "m365"],
                        ),
                    ],
                ),
                registered_at=now,
            ),
            # 1P MCP Server: BigQuery & Workspace (Inside VPC-SC)
            "mcp-bigquery-customer-db": RegistryEntry(
                id="mcp-bigquery-customer-db",
                agent_id_uri="agent-id://enterprise-agent-prj.internal/mcp/bigquery-customer-360",
                name="BigQuery Customer 360 MCP Server (VPC-SC)",
                provider="Google Cloud 1P MCP",
                category="MCP_CONNECTOR",
                protocol="MCP",
                endpoint_url="internal://google-apis-vpc-sc/bigquery-mcp",
                description="VPC-SC enforced 1P MCP server providing SQL access to `corp_finance.customer_accounts` (contains SSNs, Credit Cards, VIP tiers).",
                registered_in_registry=True,
                gateway_enabled=True,
                psc_egress_approved=True,
                identity_mode="BOTH",
                scopes=["bigquery.datasets.get", "bigquery.jobs.create"],
                registered_at=now,
            ),
            # 1P MCP Server: Google Workspace (VPC-SC aware)
            "mcp-google-workspace": RegistryEntry(
                id="mcp-google-workspace",
                agent_id_uri="agent-id://gcp-prod.internal/mcp/workspace-drive-gmail",
                name="Google Workspace MCP Connector (VPC-SC Aware)",
                provider="Google Workspace 1P MCP",
                category="MCP_CONNECTOR",
                protocol="MCP",
                endpoint_url="internal://google-apis-vpc-sc/workspace-mcp",
                description="VPC-SC-aware Workspace MCP API for Docs, Drive, and Gmail using delegated end-user OAuth via IAP.",
                registered_in_registry=True,
                gateway_enabled=True,
                psc_egress_approved=True,
                identity_mode="PERSONAL",
                scopes=["drive.readonly", "gmail.send"],
                registered_at=now,
            ),
            # 3P MCP Server: Jira & Confluence Connector
            "mcp-jira-enterprise": RegistryEntry(
                id="mcp-jira-enterprise",
                agent_id_uri="agent-id://gcp-prod.external-3p/mcp/atlassian-jira",
                name="Jira & M365 Incident MCP Server (3P)",
                provider="Atlassian / 3P MCP Server",
                category="MCP_CONNECTOR",
                protocol="MCP",
                endpoint_url="http://127.0.0.1:8080/mcp/jira/invoke",
                description="External 3P MCP server fetching Jira SecOps tickets and vendor bug reports (used to demo Indirect Prompt Injection in tool outputs).",
                registered_in_registry=True,
                gateway_enabled=True,
                psc_egress_approved=True,
                identity_mode="BOTH",
                scopes=["jira.issues.read", "jira.issues.comment"],
                registered_at=now,
            ),
            # Unregistered "Shadow" 3P Agent / MCP (for Flow 8 VPC-SC Default-Deny Egress demo)
            "shadow-unapproved-agent": RegistryEntry(
                id="shadow-unapproved-agent",
                agent_id_uri="agent-id://unverified.external/shadow-scraper-agent",
                name="Unregistered Shadow AI Agent (External Internet)",
                provider="Untrusted External Host",
                category="3P_AGENT",
                protocol="A2A",
                endpoint_url="https://shadow-agent.untrusted-external.io/a2a",
                description="Unapproved external endpoint outside VPC-SC perimeter with no PSC-I route or Agent Registry approval.",
                registered_in_registry=False,
                gateway_enabled=False,
                psc_egress_approved=False,
                identity_mode="BOTH",
                scopes=[],
                registered_at=now,
            ),
        }

    def list_entries(self) -> List[RegistryEntry]:
        return list(self.entries.values())

    def get_entry(self, entry_id: str) -> Optional[RegistryEntry]:
        return self.entries.get(entry_id)

    def register_or_update(self, req: RegisterExternalAgentRequest) -> RegistryEntry:
        entry_id = req.id or req.name.lower().replace(" ", "-").replace("/", "-")
        existing = self.entries.get(entry_id)
        skills = [
            AgentSkill(
                id=s.get("id", f"skill-{idx}"),
                name=s.get("name", "Custom Skill"),
                description=s.get("description", ""),
                tags=s.get("tags", ["a2a", "3p"]),
            )
            for idx, s in enumerate(req.skills)
        ]
        if not skills and existing and existing.agent_card:
            skills = existing.agent_card.skills

        card = AgentCard(
            name=req.name,
            description=req.description,
            url=req.endpoint_url,
            provider=req.provider,
            protocol=f"{req.protocol}/1.0",
            skills=skills,
        )
        entry = RegistryEntry(
            id=entry_id,
            agent_id_uri=(
                existing.agent_id_uri
                if existing
                else f"agent-id://gcp-prod.external-3p/{req.provider.lower().split()[0]}/{entry_id}"
            ),
            name=req.name,
            provider=req.provider,
            category="3P_AGENT" if req.protocol.upper() == "A2A" else "MCP_CONNECTOR",
            protocol=req.protocol.upper(),
            endpoint_url=req.endpoint_url,
            well_known_url=req.well_known_url
            or (existing.well_known_url if existing else None),
            description=req.description,
            registered_in_registry=True,
            gateway_enabled=req.gateway_enabled,
            psc_egress_approved=req.psc_egress_approved,
            identity_mode=existing.identity_mode if existing else "BOTH",
            scopes=existing.scopes if existing else ["a2a.tasks.send"],
            agent_card=card,
            registered_at=datetime.now(timezone.utc).isoformat(),
        )
        self.entries[entry_id] = entry
        return entry

    def update_gateway_flags(
        self,
        entry_id: str,
        registered_in_registry: Optional[bool] = None,
        gateway_enabled: Optional[bool] = None,
        psc_egress_approved: Optional[bool] = None,
    ) -> RegistryEntry:
        if entry_id not in self.entries:
            raise KeyError(f"Agent or MCP '{entry_id}' not found in registry")
        entry = self.entries[entry_id]
        if registered_in_registry is not None:
            entry.registered_in_registry = registered_in_registry
            if not registered_in_registry:
                entry.gateway_enabled = False
        if gateway_enabled is not None:
            entry.gateway_enabled = gateway_enabled
        if psc_egress_approved is not None:
            entry.psc_egress_approved = psc_egress_approved
        return entry


registry_store = AgentRegistryStore()
