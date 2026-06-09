"""Authentication for the MCP server.

A simple static bearer-token verifier. The token is shared with the agent out
of band (via ``.env``) and the transport is additionally protected by Tailscale.
This integrates with the MCP SDK's native auth: a request without a valid
``Authorization: Bearer <token>`` header is rejected with HTTP 401 before any
tool runs.
"""

from __future__ import annotations

import hmac

from mcp.server.auth.provider import AccessToken, TokenVerifier

#: Scope granted to an authenticated agent and required by the server.
ADEPT_SCOPE = "adept"

#: Stable client id reported for the single trusted agent identity.
ADEPT_CLIENT_ID = "adept-agent"


class StaticTokenVerifier(TokenVerifier):
    """Verify a single pre-shared bearer token in constant time."""

    def __init__(self, token: str, *, scopes: list[str] | None = None) -> None:
        if not token:
            raise ValueError("StaticTokenVerifier requires a non-empty token")
        self._token = token
        self._scopes = scopes or [ADEPT_SCOPE]

    async def verify_token(self, token: str) -> AccessToken | None:
        if hmac.compare_digest(token, self._token):
            return AccessToken(
                token=token,
                client_id=ADEPT_CLIENT_ID,
                scopes=list(self._scopes),
            )
        return None
