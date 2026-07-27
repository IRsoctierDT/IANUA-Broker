# MCP Sentinel — Agent Trust Broker: Agent Suite

## Purpose
This directory defines portfolio-ready agent descriptions for **MCP Sentinel — Agent Trust Broker**. The project positions itself as a secure-by-default AI operations and cybersecurity automation environment for agentic workflows, RAG systems, and MCP tool execution.

These files are written to fit the existing repository posture:

- defensive and authorized lab use only;
- least privilege by default;
- fail-closed behavior for unsafe actions;
- human approval for irreversible or high-impact actions;
- auditability, evidence preservation, and measurable quality gates;
- no plaintext secrets, credentials, legal documents, client data, or PII in logs or source control.

## Recommended agent set

| File | Agent | Primary Function |
|---|---|---|
| [`agent_trust_broker_orchestrator.md`](agent_trust_broker_orchestrator.md) | Agent Trust Broker Orchestrator | Central routing, policy enforcement, risk scoring, approvals |
| [`mcp_tool_risk_assessor.md`](mcp_tool_risk_assessor.md) | MCP Tool Risk Assessor | Scores MCP tools before use and blocks risky calls |
| [`policy_gatekeeper.md`](policy_gatekeeper.md) | Policy Gatekeeper | Enforces project governance, authorization, quality gates |
| [`rag_evidence_curator.md`](rag_evidence_curator.md) | RAG Evidence Curator | Retrieves grounded evidence and prevents unsupported claims |
| [`prompt_injection_defender.md`](prompt_injection_defender.md) | Prompt Injection Defender | Detects malicious instructions in prompts, documents, and tool output |
| [`audit_evidence_recorder.md`](audit_evidence_recorder.md) | Audit Evidence Recorder | Produces tamper-aware logs, decision records, and review packets |
| [`incident_response_triage_agent.md`](incident_response_triage_agent.md) | Incident Response Triage Agent | Handles defensive triage, containment recommendations, and reports |
| [`secrets_supply_chain_sentinel.md`](secrets_supply_chain_sentinel.md) | Secrets & Supply Chain Sentinel | Detects exposed secrets, dependency risk, and CI/CD hygiene issues |
| [`human_approval_liaison.md`](human_approval_liaison.md) | Human Approval Liaison | Manages escalation, consent, approval packets, and operator decisions |

## Repository placement

```text
docs/agents/
  README.md               (this file)
  AGENT_REGISTRY.md       (portfolio-facing inventory)
  agent_trust_broker_orchestrator.md
  mcp_tool_risk_assessor.md
  policy_gatekeeper.md
  rag_evidence_curator.md
  prompt_injection_defender.md
  audit_evidence_recorder.md
  incident_response_triage_agent.md
  secrets_supply_chain_sentinel.md
  human_approval_liaison.md
```

## Operating model

1. A user or agent requests work.
2. The **Agent Trust Broker Orchestrator** classifies the request.
3. The **Policy Gatekeeper** validates whether the request is allowed.
4. The **MCP Tool Risk Assessor** evaluates proposed tool calls.
5. The **Prompt Injection Defender** inspects user input, retrieved documents, and tool output.
6. The **RAG Evidence Curator** retrieves cited evidence where factual grounding is required.
7. The **Human Approval Liaison** pauses high-risk or irreversible actions.
8. The **Audit Evidence Recorder** records the decision path.
9. Specialist agents execute approved work.
10. Quality gates run before merge, release, or publication.

## Portfolio value

This agent suite demonstrates practical knowledge of:

- MCP trust boundaries;
- AI tool governance;
- secure software development lifecycle practices;
- RAG security;
- prompt injection defense;
- audit logging and compliance evidence;
- human-in-the-loop control;
- security testing and CI quality gates;
- SOC-style incident triage.
