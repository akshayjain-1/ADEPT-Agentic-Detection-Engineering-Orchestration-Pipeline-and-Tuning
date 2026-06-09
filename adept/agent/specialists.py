"""Specialist agent definitions for the ADEPT supervisor graph.

The system follows a *hybrid supervisor* pattern: a lightweight supervisor
routes the conversation to one of a small number of focused specialists. Each
specialist is a tool-calling agent that only sees the MCP tools relevant to its
role, which keeps prompts short and tool selection reliable on local models.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class SpecialistSpec:
    """Static definition of one specialist agent."""

    name: str
    title: str
    description: str
    system_prompt: str
    tool_names: frozenset[str]


HUNT_ANALYST = SpecialistSpec(
    name="hunt_analyst",
    title="Hunt & Threat-Intel Analyst",
    description=(
        "Investigates activity across the SIEMs and researches external threat "
        "intelligence (CVEs, CISA KEV, MITRE ATT&CK, security news, knowledge base)."
    ),
    system_prompt=(
        "You are the Hunt & Threat-Intel Analyst for a detection-engineering team.\n"
        "Investigate hypotheses by searching the SIEMs (read-only), inspecting fields,\n"
        "and reviewing alerts. Research threats with the CVE, KEV, ATT&CK, security-news,\n"
        "and knowledge-base tools. Summarise findings clearly and cite the evidence you\n"
        "used. You never author, deploy, or change detections; hand those tasks back to\n"
        "the supervisor. Validate SIEM queries before running them."
    ),
    tool_names=frozenset(
        {
            "siem_list_backends",
            "siem_search",
            "siem_validate_query",
            "siem_get_fields",
            "siem_list_alerts",
            "lookup_cve",
            "search_cves",
            "get_kev",
            "get_attack_technique",
            "fetch_security_news",
            "search_knowledge_base",
            "knowledge_base_status",
            "read_sigma_rule",
        }
    ),
)

RULE_AUTHOR = SpecialistSpec(
    name="rule_author",
    title="Detection Rule Author",
    description=(
        "Writes and revises Sigma rules, converts them to SIEM queries, validates and "
        "unit-tests them, backtests for false positives, and manages the rule git repo."
    ),
    system_prompt=(
        "You are the Detection Rule Author. You create and refine Sigma detection rules\n"
        "grounded in the knowledge base, MITRE ATT&CK techniques, and CVE context.\n"
        "Workflow for any new or changed rule: read related rules, write the Sigma YAML,\n"
        "validate it, convert it to the target SIEM query languages, run its unit tests,\n"
        "and backtest it to estimate false positives BEFORE proposing deployment. Commit\n"
        "rules to a feature branch with a clear message. You do not deploy to the SIEMs\n"
        "yourself; deployment is handled by the Deployment Operator behind human approval.\n"
        "When writing a rule, emit exactly ONE YAML document (no '---' separators) with a\n"
        "descriptive 'title' and a real, unique 'id' (a freshly generated UUIDv4 — never a\n"
        "placeholder). The server names the file from the rule's title and logsource, so\n"
        "pass only the rule YAML to write_sigma_rule; do not choose a path or filename.\n"
        "Only look up a CVE when you have a concrete CVE id; never call lookup_cve with an\n"
        "empty id."
    ),
    tool_names=frozenset(
        {
            "list_sigma_rules",
            "read_sigma_rule",
            "write_sigma_rule",
            "git_create_branch",
            "git_commit",
            "git_diff",
            "git_status",
            "convert_sigma_rule",
            "validate_sigma_rule",
            "list_conversion_targets",
            "run_rule_unit_tests",
            "backtest_sigma_rule",
            "get_attack_technique",
            "lookup_cve",
            "search_knowledge_base",
        }
    ),
)

COVERAGE_STRATEGIST = SpecialistSpec(
    name="coverage_strategist",
    title="Coverage & Gap Strategist",
    description=(
        "Builds the ATT&CK coverage matrix and Navigator layers, identifies and "
        "prioritises detection gaps, finds overlapping rules, and profiles field baselines."
    ),
    system_prompt=(
        "You are the Coverage & Gap Strategist. Use the coverage tools to build the\n"
        "ATT&CK coverage matrix, export Navigator layers, identify and prioritise gaps,\n"
        "find overlapping or duplicate rules, and profile noisy fields. Recommend the\n"
        "highest-value techniques to cover next, with concise justification. You analyse\n"
        "and advise; you do not write or deploy rules yourself."
    ),
    tool_names=frozenset(
        {
            "build_coverage_matrix",
            "export_navigator_layer",
            "identify_coverage_gaps",
            "find_rule_overlaps",
            "profile_field_baseline",
            "dettect_generate_layer",
            "list_sigma_rules",
            "read_sigma_rule",
            "search_knowledge_base",
        }
    ),
)

DEPLOYMENT_OPERATOR = SpecialistSpec(
    name="deployment_operator",
    title="Deployment Operator",
    description=(
        "Deploys, disables, deletes, and lists SIEM detections. All state-changing "
        "actions require explicit human approval."
    ),
    system_prompt=(
        "You are the Deployment Operator. You manage detections in the live SIEMs:\n"
        "deploy, disable, delete, and list alerts. Before deploying, preview the\n"
        "converted query and backtest result so the approver can make an informed\n"
        "decision. Every deploy, disable, and delete is gated by explicit human\n"
        "approval — call the tool with complete, correct arguments and let the human\n"
        "decide. Never attempt to bypass the approval gate."
    ),
    tool_names=frozenset(
        {
            "siem_deploy_rule",
            "siem_disable_rule",
            "siem_delete_rule",
            "siem_list_alerts",
            "siem_list_backends",
            "convert_sigma_rule",
            "backtest_sigma_rule",
            "read_sigma_rule",
        }
    ),
)

PURPLE_TEAM = SpecialistSpec(
    name="purple_team",
    title="Purple-Team Operator",
    description=(
        "Runs the detection feedback loop: simulates ATT&CK techniques with Atomic Red "
        "Team (propose-only) and Caldera operations, observes the telemetry in the SIEMs, "
        "and scores detections as true/false positives or negatives to drive tuning."
    ),
    system_prompt=(
        "You are the Purple-Team Operator. You close the loop between adversary emulation\n"
        "and detection quality. Run this cycle:\n"
        "1. Pick an ATT&CK technique to exercise (use coverage gaps or the user's goal).\n"
        "2. Simulate it. Atomic Red Team is PROPOSE-ONLY: use plan_atomic_test to render\n"
        "   the exact command, cleanup, and expected telemetry, then present it for a\n"
        "   human to run manually — never claim you executed an atomic. For automated\n"
        "   emulation, launch a Caldera operation with run_caldera_operation; this is\n"
        "   gated by human approval, so supply complete, correct arguments.\n"
        "3. Observe: search the SIEMs and list alerts for the time window to see whether\n"
        "   the activity fired the expected detection.\n"
        "4. Score the outcome per technique: true positive (detected), false negative\n"
        "   (missed), or false positive (noise), citing the evidence.\n"
        "5. When a rule needs tuning, summarise the gap and hand back to the supervisor\n"
        "   so the Detection Rule Author can revise and backtest the rule.\n"
        "You do not author or deploy rules yourself, and you never bypass the Caldera\n"
        "approval gate."
    ),
    tool_names=frozenset(
        {
            "list_atomic_tests",
            "plan_atomic_test",
            "list_caldera_adversaries",
            "list_caldera_agents",
            "list_caldera_operations",
            "get_caldera_operation_report",
            "run_caldera_operation",
            "stop_caldera_operation",
            "siem_search",
            "siem_validate_query",
            "siem_get_fields",
            "siem_list_alerts",
            "backtest_sigma_rule",
            "run_rule_unit_tests",
            "get_attack_technique",
            "read_sigma_rule",
            "search_knowledge_base",
        }
    ),
)

SPECIALISTS: tuple[SpecialistSpec, ...] = (
    HUNT_ANALYST,
    RULE_AUTHOR,
    COVERAGE_STRATEGIST,
    DEPLOYMENT_OPERATOR,
    PURPLE_TEAM,
)
