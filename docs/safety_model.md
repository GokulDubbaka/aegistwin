# AegisTwin Safety Model

## Core Principle

AegisTwin is an **authorized** security platform. Every offensive action is bounded by policy
and scope. The platform explicitly rejects any attempt to perform real exploitation, harm,
or unauthorized access.

## Permanently Blocked Actions

The following action types are **hardcoded** in `PolicyEngine._ALWAYS_BLOCKED` and can
never be overridden by any tenant policy, user permission, or engagement rule:

| Action | Reason |
|---|---|
| `exploit_execution` | Real exploitation causes real harm to production |
| `credential_use` | Using stolen or test credentials enables unauthorized access |
| `credential_theft` | Extracting real credentials is illegal and harmful |
| `persistence` | Installing backdoors or persistence is unauthorized modification |
| `c2_communication` | Command and control infrastructure enables ongoing attacks |
| `lateral_movement` | Automated lateral movement causes uncontrolled spread |
| `data_exfiltration` | Real data exfiltration causes real data breaches |
| `stealth` | Anti-detection techniques obstruct incident response |
| `log_deletion` | Log tampering destroys evidence and violates compliance |
| `destructive_payload` | Any payload that destroys, encrypts, or corrupts data |
| `anti_forensics` | Techniques that prevent forensic investigation |
| `hacking_back` | Counter-attacks against attacker infrastructure are illegal |

## Safe Validation Ladder

The offensive agent uses a 7-level validation ladder. Each level must be explicitly authorized
and each step is policy-checked before execution:

| Level | Name | Description | Production? |
|---|---|---|---|
| 1 | Signal Detected | Passive signal observed from open sources | ✅ Read-only |
| 2 | Corroborated | Multiple sources confirm signal | ✅ Read-only |
| 3 | Preconditions Verified | Conditions for exploitability verified passively | ✅ Read-only |
| 4 | Non-Destructive Proof | Safe test that causes no modification | ✅ Non-destructive only |
| 5 | Lab Reproduction | Full reproduction in isolated staging clone | ❌ Staging ONLY |
| 6 | Human-Approved Validation | Production test with explicit human approval | ⚠️ Approval required |
| 7 | Remediated and Retested | Finding remediated, fix verified | ✅ All environments |

## Scope Enforcement

Every action must specify a `target`. The target is checked against the `Engagement.allowed_targets`
list. Any target not in the approved scope list is automatically blocked with `blocked_by: "SCOPE"`.

## Audit Trail

Every agent decision — allowed or blocked — is logged with:
- tenant_id
- engagement_id
- action_type
- target
- decision (allowed/blocked)
- reason
- timestamp

This creates a complete, tamper-evident audit trail for all platform activity.

## Deception Safety

The `DeceptionFabric` generates fake tokens and credentials that:
1. Always contain `AEGISTWIN_FAKE_DO_NOT_USE` in both the value and metadata
2. Are clearly prefixed with `FAKE_`
3. Cannot be used for authentication against real systems
4. Trigger alerts when accessed

## Tool Broker Safety

The `ToolBroker` enforces policy before every tool execution. No tool can execute
without passing the `PolicyEngine.evaluate()` check. Blocked tool executions are
normalized to `status: "blocked"` and the reason is stored as evidence.
