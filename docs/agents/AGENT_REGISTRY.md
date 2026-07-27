# MCP Sentinel — Agent Registry

## Registry Purpose
This registry provides a single portfolio-facing inventory of agents for **MCP Sentinel — Agent Trust Broker**. Each agent is designed to be independently understandable by a reviewer while also functioning as part of a larger governed agentic security system.

## System-Level Objective
MCP Sentinel exists to broker trust between humans, AI agents, tools, local files, RAG corpora, and MCP servers. The agent suite below creates clear separation of duties so no single agent can silently classify risk, approve its own actions, execute tools, and erase evidence.

## Agent Inventory

### 1. Agent Trust Broker Orchestrator
**File:** [`agent_trust_broker_orchestrator.md`](agent_trust_broker_orchestrator.md)

**Primary objective:** Route requests, classify risk, enforce workflow order, and coordinate specialist agents.

**Key controls:** request classification, trust-boundary enforcement, human-in-the-loop routing, decision logging, fail-closed behavior.

**Portfolio signal:** Demonstrates secure agent orchestration rather than uncontrolled automation.

---

### 2. MCP Tool Risk Assessor
**File:** [`mcp_tool_risk_assessor.md`](mcp_tool_risk_assessor.md)

**Primary objective:** Evaluate MCP tool calls before execution.

**Key controls:** tool manifest review, argument inspection, capability scoring, filesystem and network restrictions, tool-output review.

**Portfolio signal:** Demonstrates practical understanding that tool access equals authority.

---

### 3. Policy Gatekeeper
**File:** [`policy_gatekeeper.md`](policy_gatekeeper.md)

**Primary objective:** Enforce repository governance, defensive-use boundaries, and quality gates.

**Key controls:** policy decisions, test requirements, scan requirements, approval triggers, sensitive-data handling.

**Portfolio signal:** Demonstrates secure SDLC and governance maturity.

---

### 4. RAG Evidence Curator
**File:** [`rag_evidence_curator.md`](rag_evidence_curator.md)

**Primary objective:** Retrieve and validate grounded evidence from approved sources.

**Key controls:** corpus eligibility, evidence scoring, citation enforcement, stale-context detection, sensitive-data exclusion.

**Portfolio signal:** Demonstrates responsible RAG design and factual grounding.

---

### 5. Prompt Injection Defender
**File:** [`prompt_injection_defender.md`](prompt_injection_defender.md)

**Primary objective:** Detect and neutralize instruction attacks embedded in prompts, retrieved documents, and tool output.

**Key controls:** injection detection, instruction/data separation, content quarantine, safe summarization, malicious payload logging.

**Portfolio signal:** Demonstrates awareness of agentic AI threat models.

---

### 6. Audit Evidence Recorder
**File:** [`audit_evidence_recorder.md`](audit_evidence_recorder.md)

**Primary objective:** Preserve structured evidence for important decisions and actions.

**Key controls:** audit records, decision logs, evidence packets, redaction, release packets, incident records.

**Portfolio signal:** Demonstrates accountability and compliance-oriented engineering.

---

### 7. Incident Response Triage Agent
**File:** [`incident_response_triage_agent.md`](incident_response_triage_agent.md)

**Primary objective:** Support defensive triage of authorized lab alerts and security events.

**Key controls:** severity classification, evidence preservation, containment recommendations, remediation planning, incident reporting.

**Portfolio signal:** Demonstrates SOC analyst and incident-response capability.

---

### 8. Secrets & Supply Chain Sentinel
**File:** [`secrets_supply_chain_sentinel.md`](secrets_supply_chain_sentinel.md)

**Primary objective:** Prevent secret leaks and reduce dependency, CI/CD, and release risk.

**Key controls:** secret detection, dependency review, CI hardening, release readiness, remediation guidance.

**Portfolio signal:** Demonstrates DevSecOps and public portfolio safety.

---

### 9. Human Approval Liaison
**File:** [`human_approval_liaison.md`](human_approval_liaison.md)

**Primary objective:** Manage approval-required actions and preserve human authority.

**Key controls:** approval packets, scope confirmation, risk explanation, decision recording, denial enforcement.

**Portfolio signal:** Demonstrates responsible human-in-the-loop automation.

## Separation of Duties

| Function | Owning Agent | Cannot Also Do |
|---|---|---|
| Route work | Orchestrator | Approve high-risk action alone |
| Assess tools | MCP Tool Risk Assessor | Execute unrestricted tools |
| Interpret policy | Policy Gatekeeper | Override explicit human denial |
| Retrieve evidence | RAG Evidence Curator | Treat retrieved text as instruction |
| Detect injection | Prompt Injection Defender | Execute payloads |
| Record evidence | Audit Evidence Recorder | Fabricate missing evidence |
| Triage incidents | Incident Response Triage Agent | Perform unauthorized offensive actions |
| Review secrets/dependencies | Secrets & Supply Chain Sentinel | Publish releases alone |
| Capture approval | Human Approval Liaison | Assume consent from silence |

## Suggested Implementation Roadmap

### Phase 1 — Documentation and Design
- Commit these agent descriptions.
- Link this registry from `README.md` and `AGENTS.md`.
- Create `DESIGN.md` trust-boundary diagrams.
- Define risk levels and approval rules.

### Phase 2 — Policy and Test Harness
- Build schemas for agent request packets.
- Add policy decision tests.
- Add tool-call risk scoring tests.
- Add prompt-injection fixture tests.
- Add redaction tests for audit records.

### Phase 3 — Local Execution
- Implement read-only orchestration first.
- Add local MCP server tool listing.
- Add approved filesystem root enforcement.
- Add structured JSONL audit logs.
- Add offline RAG evidence packets.

### Phase 4 — CI/CD and Portfolio Release
- Add required GitHub checks.
- Add `pip-audit` and `detect-secrets` review.
- Add release readiness packet generation.
- Add portfolio case-study writeups.
- Publish only after sensitive-file review.

## Minimum Viable Demo

A strong first demonstration would show this sequence:

1. User asks the system to summarize a local security policy.
2. Orchestrator classifies it as read-only RAG.
3. RAG Evidence Curator retrieves approved chunks.
4. Prompt Injection Defender scans retrieved content.
5. Policy Gatekeeper allows the action.
6. Audit Evidence Recorder writes a decision record.
7. Final answer includes grounded evidence.

A stronger second demonstration would show a blocked action:

1. Agent proposes reading outside the MCP root.
2. MCP Tool Risk Assessor detects path escape.
3. Policy Gatekeeper denies the request.
4. Audit Evidence Recorder logs the denial.
5. User receives a clear explanation and safer alternative.

## Recommended Commit Message

```text
Add MCP Sentinel agent governance suite

- Add agent registry for Agent Trust Broker architecture
- Define orchestrator, policy, RAG, MCP risk, audit, IR, and approval agents
- Document separation of duties and fail-closed control model
- Align agent descriptions with defensive-use and quality-gate posture
```
