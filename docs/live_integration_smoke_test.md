# ADEPT — Live-Integration Smoke Test

> The offline suite (`uv run pytest -q`) proves ADEPT's code runs against
> **mocked** SIEMs, Caldera, intel feeds, and Ollama. It deliberately does **not**
> touch your real homelab. This runbook is the missing half: a staged, manual
> validation that ADEPT talks correctly to **one real backend at a time**.
>
> Run it once after initial setup (see [`SETUP_CHECKLIST.md`](../SETUP_CHECKLIST.md)),
> and again whenever you upgrade a backend, rotate credentials, or change a
> connection setting. Each stage is self-contained — validate only the backends
> you actually run.

**Legend:** `[ ]` = do this and confirm it passes · **[state-changing]** = creates
or modifies data in a real system · **[approval]** = the agent will pause for the
human gate.

---

## Conventions

- Run everything from the ADEPT project root.
- Use `uv run <script>` — no virtualenv activation needed.
- If another project's venv is active in your shell, prefix commands with
  `env -u VIRTUAL_ENV` (e.g. `env -u VIRTUAL_ENV uv run adept-mcp`).
- Validate **one backend at a time**: enable it, run its stage, then move on.
  This keeps a failure unambiguous.
- Safe defaults stay on. `ADEPT_ATTACK__REQUIRE_APPROVAL` and
  `ADEPT_ATTACK__DRY_RUN_DEFAULT` are `true`; leave them that way for the smoke
  test. Use throwaway rule/monitor/saved-search names so cleanup is trivial.
- Every stage that writes to a real system has a matching **Cleanup** step.
  Always run it.

---

## Stage 0 — Preconditions

- [ ] Offline gate is green: `uv run pytest -q` (and, if you have the tooling,
      `uv run ruff check adept tests` + `uv run mypy adept`).
- [ ] `.env` is populated for the backend(s) you intend to test (see
      [`README.md` §7](../README.md#7-configuration-env)).
- [ ] Tailscale (or your chosen transport) is up between the agent host and the
      MCP server host, if they differ.
- [ ] Ollama is reachable: `curl "$ADEPT_OLLAMA__BASE_URL/api/tags"` returns a
      model list (defaults to `http://localhost:11434`).

---

## Stage 1 — MCP server reachability & auth

The MCP server is the broker every agent call flows through; validate it first.

- [ ] Start the server: `uv run adept-mcp` (binds `ADEPT_MCP__HOST:PORT`,
      default `127.0.0.1:8765`, path `/mcp`).
- [ ] From the **agent host**, the MCP URL responds (a `401`/`406` proves
      reachability + auth are active, not a connection refusal):
      `curl -i "$ADEPT_AGENT__MCP_URL"`.
- [ ] Auth tokens match: the agent's `ADEPT_AGENT__MCP_TOKEN` is byte-for-byte
      equal to the server's `ADEPT_MCP__AUTH_TOKEN`. In `prod` the server refuses
      to start without a token.
- [ ] The agent can enumerate enabled SIEMs end-to-end through MCP — ask it to
      call **`siem_list_backends`** (e.g. `uv run adept chat` then
      *"list the enabled SIEM backends"*). The result lists exactly the backends
      you enabled, with their query languages.

> If auth fails, see [`README.md` §15](../README.md#15-troubleshooting--faq)
> (`401`/auth errors). Secrets are stored as `SecretStr`, so they are masked in
> logs and `repr()` — confirm the *plaintext* values in `.env`, not the log
> output.

---

## Stage 2 — ELK / Elasticsearch (primary SIEM)

Prereq: `ADEPT_ELK__ENABLED=true`, `ADEPT_ELK__URL`, and credentials
(`ADEPT_ELK__API_KEY` **or** `ADEPT_ELK__USERNAME`/`ADEPT_ELK__PASSWORD`).

**Read path**

- [ ] `siem_get_fields` against `ADEPT_ELK__DEFAULT_INDEX` returns a non-empty
      field list (proves auth + TLS + index access).
- [ ] `siem_validate_query` accepts a simple Lucene query (e.g.
      `event.code:*`) and rejects an obviously malformed one.
- [ ] `siem_search` returns events from a recent time window.

**Deploy path (Kibana Detection Engine)** — needs `ADEPT_ELK__KIBANA_URL`.

- [ ] **[state-changing]** `siem_deploy_rule` creates a throwaway detection (use
      a unique name like `adept-smoke-test`). Note the returned `deploy_id`.
- [ ] `siem_list_alerts` reads from `ADEPT_ELK__ALERTS_INDEX` without error.
- [ ] **Cleanup:** `siem_disable_rule` then `siem_delete_rule` with the
      `deploy_id` above. Confirm the rule is gone from Kibana.

---

## Stage 3 — OpenSearch / Wazuh Indexer (alerting)

Prereq: `ADEPT_OPENSEARCH__ENABLED=true`, `ADEPT_OPENSEARCH__URL`,
`ADEPT_OPENSEARCH__USERNAME`/`ADEPT_OPENSEARCH__PASSWORD`.

- [ ] `siem_get_fields` against `ADEPT_OPENSEARCH__DEFAULT_INDEX`
      (default `wazuh-alerts-*`) returns fields.
- [ ] `siem_search` returns recent alerts.
- [ ] **[state-changing]** `siem_deploy_rule` creates a throwaway monitor; record
      the `deploy_id`.
- [ ] `siem_list_alerts` returns without error.
- [ ] **Cleanup:** `siem_disable_rule` → `siem_delete_rule` for that `deploy_id`.

---

## Stage 4 — Splunk (saved search)

Prereq: `ADEPT_SPLUNK__ENABLED=true`, host/port (management API, default `8089`),
and either `ADEPT_SPLUNK__TOKEN` or `ADEPT_SPLUNK__USERNAME`/`ADEPT_SPLUNK__PASSWORD`.

- [ ] `siem_get_fields` against `ADEPT_SPLUNK__DEFAULT_INDEX` (default `main`)
      returns fields.
- [ ] `siem_validate_query` accepts a simple SPL search and the output guardrail
      **rejects** a dangerous pipeline (e.g. one piping to `| delete`).
- [ ] `siem_search` returns events for a recent time window.
- [ ] **[state-changing]** `siem_deploy_rule` creates a throwaway saved search;
      record the `deploy_id`.
- [ ] **Cleanup:** `siem_disable_rule` → `siem_delete_rule` for that `deploy_id`.

---

## Stage 5 — Caldera (attack simulation, REST)

Prereq: `ADEPT_ATTACK__CALDERA_ENABLED=true`, `ADEPT_ATTACK__CALDERA_URL`,
`ADEPT_ATTACK__CALDERA_API_KEY` (header per `ADEPT_ATTACK__CALDERA_API_KEY_HEADER`,
default `KEY`). Keep `ADEPT_ATTACK__REQUIRE_APPROVAL=true`.

**Read path (no approval needed)**

- [ ] `list_caldera_adversaries` returns the server's adversary profiles
      (proves base URL + API key + header are correct).
- [ ] `list_caldera_agents` lists deployed agents (deploy at least one sandbox
      agent first if empty).
- [ ] `list_caldera_operations` returns without error.

**Operation path** — only against a sandbox agent you control.

- [ ] **[state-changing] [approval]** `run_caldera_operation` against a sandbox
      group pauses at the human approval gate; approve it and note the
      `operation_id`.
- [ ] `get_caldera_operation_report` returns progress for that operation.
- [ ] **Cleanup:** **[state-changing]** `stop_caldera_operation` with the
      `operation_id`. Confirm it is finished/stopped in the Caldera UI.

> Atomic Red Team is **propose-only** — ADEPT never executes atomics — so
> `list_atomic_tests` / `plan_atomic_test` are safe to exercise but require no
> live cleanup.

---

## Stage 6 — External intel feeds (live fetch)

Prereq: outbound access to the hosts in `ADEPT_INTEL__ALLOWED_DOMAINS`. An
`ADEPT_INTEL__NVD_API_KEY` is optional but raises the NVD rate limit.

- [ ] `lookup_cve` for a known id (e.g. `CVE-2021-44228`) returns details.
- [ ] `get_kev` returns CISA Known-Exploited-Vulnerabilities entries.
- [ ] `get_attack_technique` for a known id (e.g. `T1059.001`) returns the
      technique (first call fetches + caches the ATT&CK STIX bundle).
- [ ] **[optional]** `fetch_security_news` returns items if you configured
      `ADEPT_INTEL__RSS_FEEDS`.

---

## Stage 7 — Agent end-to-end against the live stack

With the MCP server running and at least one SIEM validated above:

- [ ] `uv run adept chat`, then drive a real workflow, e.g.
      *"Search ELK for recent failed logons and summarise what you find."*
      The agent should call live SIEM tools and return grounded results.
- [ ] Trigger the approval gate with a state-changing request (e.g.
      *"deploy this rule"*) and confirm it **pauses** for approval rather than
      acting autonomously.
- [ ] **Cleanup:** delete any detection created during this stage (Stage 2–4
      cleanup steps), and review `uv run adept audit` for the recorded actions.

---

## Sign-off

| Stage | Backend / area              | Validated | Date | Notes |
| ----- | --------------------------- | --------- | ---- | ----- |
| 1     | MCP reachability & auth     |           |      |       |
| 2     | ELK / Elasticsearch         |           |      |       |
| 3     | OpenSearch / Wazuh Indexer  |           |      |       |
| 4     | Splunk                      |           |      |       |
| 5     | Caldera                     |           |      |       |
| 6     | Intel feeds                 |           |      |       |
| 7     | Agent end-to-end            |           |      |       |

> A stage left blank simply means that backend isn't part of your deployment —
> that's expected. Record which backends are in scope for your lab so the next
> run knows what "complete" looks like.
