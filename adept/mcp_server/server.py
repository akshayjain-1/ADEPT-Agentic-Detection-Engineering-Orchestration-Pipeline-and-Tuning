"""ADEPT MCP server construction and entry point."""

from __future__ import annotations

from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

from adept.config.settings import Settings, get_settings
from adept.mcp_server.auth import ADEPT_SCOPE, StaticTokenVerifier
from adept.mcp_server.context import AppContext
from adept.mcp_server.resources import register_resources
from adept.mcp_server.tools.attack_tools import register_attack_tools
from adept.mcp_server.tools.coverage_tools import register_coverage_tools
from adept.mcp_server.tools.dac_tools import register_dac_tools
from adept.mcp_server.tools.intel_tools import register_intel_tools
from adept.mcp_server.tools.kb_tools import register_kb_tools
from adept.mcp_server.tools.siem_tools import register_siem_tools
from adept.mcp_server.tools.sigma_git_tools import register_sigma_git_tools
from adept.shared.errors import ConfigurationError
from adept.shared.logging import configure_logging, get_logger
from adept.shared.observability import setup_observability

log = get_logger(__name__)

INSTRUCTIONS = """\
ADEPT detection-engineering server. Use these tools to hunt through SIEM logs,
read and author Sigma detection rules, convert them to the configured SIEMs,
analyse coverage, and review detections adversarially. Author rules on feature
branches; deployment and adversary emulation are gated behind human approval.
Consult the homelab://architecture, sigma://schema, and ade://taxonomy resources.
"""


def build_server(settings: Settings) -> FastMCP:
    """Construct the FastMCP server with all tools and resources registered."""
    ctx = AppContext.from_settings(settings)
    ctx.sigma_repo.ensure_repo()

    verifier: StaticTokenVerifier | None = None
    auth: AuthSettings | None = None
    if settings.mcp.auth_token:
        verifier = StaticTokenVerifier(settings.mcp.auth_token)
        auth = AuthSettings(
            issuer_url=settings.mcp.public_url,
            resource_server_url=settings.mcp.public_url,
            required_scopes=[ADEPT_SCOPE],
        )
    elif settings.env == "prod":
        # Fail closed: never expose a capability broker unauthenticated in prod.
        raise ConfigurationError(
            "ADEPT_MCP__AUTH_TOKEN is required when ADEPT_ENV=prod; refusing to "
            "start an unauthenticated MCP server in production."
        )
    else:
        log.warning(
            "mcp_auth_disabled",
            hint="set ADEPT_MCP__AUTH_TOKEN to require a bearer token",
        )

    mcp = FastMCP(
        name="adept",
        instructions=INSTRUCTIONS,
        host=settings.mcp.host,
        port=settings.mcp.port,
        streamable_http_path=settings.mcp.path,
        token_verifier=verifier,
        auth=auth,
    )

    register_resources(mcp, ctx)
    register_sigma_git_tools(mcp, ctx)
    register_siem_tools(mcp, ctx)
    register_dac_tools(mcp, ctx)
    register_intel_tools(mcp, ctx)
    register_coverage_tools(mcp, ctx)
    register_kb_tools(mcp, ctx)
    register_attack_tools(mcp, ctx)
    log.info(
        "mcp_server_built",
        tools="sigma_git,siem,dac,intel,coverage,kb,attack",
        siems=sorted(ctx.siem_backends),
        auth=bool(settings.mcp.auth_token),
    )
    return mcp


def main() -> None:
    """Entry point for the ``adept-mcp`` console script."""
    settings = get_settings()
    configure_logging(level=settings.log_level, json_logs=settings.log_json)
    setup_observability(settings.otel)
    settings.ensure_data_dir()
    log.info(
        "starting_mcp_server",
        host=settings.mcp.host,
        port=settings.mcp.port,
        path=settings.mcp.path,
        transport=settings.mcp.transport,
    )
    mcp = build_server(settings)
    mcp.run(transport=settings.mcp.transport)


if __name__ == "__main__":
    main()
