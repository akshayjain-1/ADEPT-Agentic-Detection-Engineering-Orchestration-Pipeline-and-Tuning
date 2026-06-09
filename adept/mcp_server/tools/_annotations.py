"""Shared MCP tool-annotation tiers used to classify every ADEPT tool.

These annotations are the *source of truth* for which tools change state. The
agent derives its human-approval gate from them with a fail-safe default-deny
(see ``adept.agent.approval.derive_guarded_tool_names``): any tool that is not
explicitly read-only — or explicitly a low-risk write — is gated. A newly added
tool is therefore guarded until it is classified here, so the gate fails safe
rather than open.
"""

from __future__ import annotations

from mcp.types import ToolAnnotations

#: Pure reads: no state change anywhere. Never gated.
READ_ONLY = ToolAnnotations(readOnlyHint=True)

#: Writes confined to the local Sigma working tree / feature branches
#: (reversible and isolated by the protected-branch guard). Not gated by default.
LOW_RISK_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False)

#: High-impact, hard-to-reverse actions against live systems (deploying or
#: removing SIEM detections, launching adversary emulation). Always gated.
DESTRUCTIVE = ToolAnnotations(readOnlyHint=False, destructiveHint=True)
