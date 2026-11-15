# Agent and MCP application boundaries

Use for an authorized target application that consumes untrusted content and can call tools, access resources, store memory or act for users. This playbook assesses that target; it does not grant authority over Codex's own integrations.

## Inventory effective authority

Record which principal the target agent acts for; available tools/resources; per-tool credentials, tenant selection and side effects; user approval points; and inputs from pages, retrieval, attachments, tool results and memory. Distinguish a model's textual claim of tool access from actual callable authority.

Pick one testable invariant: untrusted retrieved text must not authorize an external write; tenant A's retrieval must not expose B's controlled marker; a tool's target argument must remain within the approved user action. Establish the legitimate task first.

## Controlled test

Place a benign unique instruction/marker only in a researcher-controlled input surface within scope. Observe whether the target treats it as content, repeats it, selects a tool, requests authorization or actually performs an unauthorized action. Capture tool invocation/audit evidence or a controlled side effect where available; a response saying 'I sent it' does not prove execution.

For cross-tenant claims use two owned isolated tenants, unique non-sensitive artifacts and verified principals. For an approval bypass, document the intended gate and the actual side effect without that gate. For resource leakage, show the protected marker returned to the wrong principal and exclude public sharing or stale sessions.

Keep tests bounded and reversible. Do not ask the target to expose real credentials, persist access, contact unrelated destinations or execute destructive actions as a substitute for proving the boundary with controlled artifacts.

## Triage and reporting

A jailbreak or changed writing style alone is not a bounty-grade authorization failure. Name the actual authority crossed, attacker input surface, victim task, tool/resource action and observed consequence. Distinguish instruction following, attempted tool action, approved action and completed unauthorized effect. Preserve the relevant conversation/tool trace with secrets removed. Root cause may be an application permission boundary rather than model compliance itself; do not prescribe prompt changes as the sole fix when tool authority is the failure.
