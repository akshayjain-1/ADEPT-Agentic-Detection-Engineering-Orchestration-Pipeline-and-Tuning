"""MCP resources: reference material the agent can read on demand."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ResourceError

from adept.detection_as_code.targets import SIEM_CONVERTER_TARGETS, SIEM_QUERY_LANGUAGE
from adept.mcp_server.context import AppContext

_ADE_TAXONOMY = """\
# Adversarial Detection Engineering (ADE) Framework — taxonomy

Use this when analysing **false negatives**: for a given detection, walk each
category and ask "could an adversary do this to evade the rule?", then harden.

## ADE1 — Reformatting in Actions
- ADE1.01 Substring Manipulation (insert/quote/escape chars, e.g. `wh""oami`)
- ADE1.02 Normalization Asymmetry (case, path, encoding differences)

## ADE2 — Omit Alternatives
- ADE2.01 Method / Binary (an alternative tool achieves the same effect)
- ADE2.02 Versioning (different version/build of the binary)
- ADE2.03 Locations (binary run from an unexpected path)
- ADE2.04 File Types (alternative extensions / LOLBins)

## ADE3 — Context Development
- ADE3.01 Process Cloning (rename/copy of a flagged binary)
- ADE3.02 Aggregation Hijacking (blend into noisy/expected parents)
- ADE3.03 Timing / Scheduling (delay or schedule to dodge correlation windows)
- ADE3.04 Event Fragmentation (split the behaviour across events/sessions)

## ADE4 — Logic Manipulation
- ADE4.01 Gate Inversion (exploit an inverted/negated condition)
- ADE4.02 Conjunction Inversion (AND/OR confusion in the detection logic)
- ADE4.03 Incorrect Expression (regex/wildcard that doesn't match real data)

Source: adeframework.org (Adversarial Detection Engineering Framework).
"""

_SIGMA_SCHEMA = """\
# Sigma rule quick reference

Required top-level keys: `title`, `logsource`, `detection` (with `condition`).
Recommended: `id` (UUIDv4), `status`, `description`, `references`, `author`,
`date`, `modified`, `tags`, `falsepositives`, `level`.

## logsource
At least one of `category`, `product`, `service`:
```yaml
logsource:
  category: process_creation
  product: windows
```

## detection
One or more named *search identifiers* plus a `condition`:
```yaml
detection:
  selection:
    Image|endswith: '\\\\whoami.exe'
  filter:
    User: 'SYSTEM'
  condition: selection and not filter
```

### Field value modifiers (append with `|`)
`contains`, `startswith`, `endswith`, `all`, `re` (regex), `cased`,
`base64`, `base64offset`, `windash`, `cidr`, `lt`/`lte`/`gt`/`gte`.
Lists under a field are OR; multiple fields in a map are AND.

### condition
`and`, `or`, `not`, parentheses, `1 of selection*`, `all of selection*`,
`1 of them`, `all of them`.

## level
`informational` | `low` | `medium` | `high` | `critical`.

## status
`experimental` | `test` | `stable` | `deprecated` | `unsupported`.
"""


def register_resources(mcp: FastMCP, ctx: AppContext) -> None:
    """Register all read-only reference resources on the server."""

    @mcp.resource(
        "homelab://architecture",
        title="Homelab architecture",
        description="The operator-maintained description of the homelab: hosts, "
        "log sources, network zones, SIEM endpoints, and tooling.",
        mime_type="text/markdown",
    )
    def homelab_architecture() -> str:
        path = ctx.settings.docs_dir / "homelab_architecture.md"
        try:
            return path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ResourceError(
                f"Homelab architecture document not found at {path}. "
                "Create it from the template in docs/."
            ) from exc

    @mcp.resource(
        "ade://taxonomy",
        title="ADE framework taxonomy",
        description="Adversarial Detection Engineering taxonomy for false-negative analysis.",
        mime_type="text/markdown",
    )
    def ade_taxonomy() -> str:
        return _ADE_TAXONOMY

    @mcp.resource(
        "sigma://schema",
        title="Sigma rule reference",
        description="Concise reference for authoring spec-compliant Sigma rules.",
        mime_type="text/markdown",
    )
    def sigma_schema() -> str:
        return _SIGMA_SCHEMA

    @mcp.resource(
        "sigma://pipelines",
        title="Available conversion pipelines",
        description="pySigma processing pipelines available in the rules repository.",
        mime_type="text/markdown",
    )
    def sigma_pipelines() -> str:
        pipelines_dir = ctx.settings.sigma.path / "pipelines"
        lines = ["# Conversion pipelines", ""]
        found = sorted(pipelines_dir.glob("*.yml")) if pipelines_dir.exists() else []
        if found:
            lines.append("## Repository pipelines")
            for path in found:
                lines.append(f"- `{path.name}` (`-p {path}`)")
        else:
            lines.append("_No repository pipelines found._")
        lines += [
            "",
            "## Community pipelines",
            "Installed pySigma pipeline plugins can be referenced by name, e.g. "
            "`-p sysmon`, `-p windows`, `-p splunk_windows`. Run "
            "`sigma list pipelines` to enumerate.",
        ]
        return "\n".join(lines)

    @mcp.resource(
        "siem://targets",
        title="SIEM conversion targets",
        description="Enabled SIEM backends and the pySigma target/query language for each.",
        mime_type="text/markdown",
    )
    def siem_targets() -> str:
        enabled = set(ctx.settings.enabled_siems())
        lines = [
            "# SIEM backends",
            "",
            "| id | enabled | sigma target | query language |",
            "| --- | --- | --- | --- |",
        ]
        for siem_id, target in SIEM_CONVERTER_TARGETS.items():
            mark = "yes" if siem_id in enabled else "no"
            lang = SIEM_QUERY_LANGUAGE.get(siem_id, "?")
            lines.append(f"| {siem_id} | {mark} | `{target}` | {lang} |")
        return "\n".join(lines)
