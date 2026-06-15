# ADEPT — Setup & Go-Live Checklist

> The ADEPT codebase is complete and verified **offline** (lint + strict types +
> the full test suite green). This document is the remaining **operator** work to
> connect it to your homelab and bring it online. Work top to bottom — later steps
> depend on earlier ones.

**Tags:** items are required unless marked **[optional]**. **[VCS]** marks a
version-control decision that is yours to make.

Every command below can be run with `uv run <script>` (no activation needed). A
`Makefile` provides convenience wrappers (`make mcp`, `make agent`, `make eval`,
`make check`); install it with `sudo apt install make` or just use the `uv run`
forms shown here.

> A visual overview of this entire sequence lives in the README under
> [Deployment scenarios](README.md#8-deployment-scenarios).

---

## 0. Plan your topology

ADEPT is split so components can run on different hosts. Decide which layout you want:

- [ ] **MCP server host** — the homelab VM that brokers SIEMs, the Sigma repo, intel, and the KB.
- [ ] **Agent host** — where the LLM agent + chatbot runs (can be the same box as Ollama).
- [ ] **Ollama host** — runs the local models (can be the same as the agent host).
- [ ] Single-box dev option: run all three on one machine to start, split later (the LLM is configured by URL, so inference can move with no code change).

---

## 1. Networking — Tailscale

- [ ] Install Tailscale on the **MCP server host** and the **agent host** and join them to your tailnet.
- [ ] Note the MCP VM's tailnet hostname (e.g. `mcp-vm.your-tailnet.ts.net`) — you'll put it in `ADEPT_MCP__PUBLIC_URL` and `ADEPT_AGENT__MCP_URL`.
- [ ] Keep the MCP port (`8765` by default) **off the public internet** — reachable only over Tailscale.

---

## 2. Install prerequisites

On each host that will run ADEPT components:

- [ ] **Python 3.11 or 3.12** (the project pins 3.12 via `.python-version`).
- [ ] **[uv](https://docs.astral.sh/uv/)** for dependency management.
- [ ] **git** (the Sigma detection-as-code tools operate on a git repo).
- [ ] **[Ollama](https://ollama.com/)** on the Ollama host.
- [ ] **[optional]** `make` (convenience targets only).

---

## 3. Pull local models (Ollama)

On the Ollama host, with the server running:

- [ ] `ollama pull qwen2.5:7b-instruct` — the chat / tool-calling model.
- [ ] `ollama pull nomic-embed-text` — the embedding model (required for the knowledge base).
- [ ] Confirm the server responds: `curl http://localhost:11434/api/tags`.

> If you pick different models, set `ADEPT_OLLAMA__MODEL` / `ADEPT_OLLAMA__EMBED_MODEL` and `ADEPT_KB__EMBED_MODEL` to match.

---

## 4. Get the code & install dependencies

- [ ] Copy/clone the ADEPT project onto each host.
- [ ] Install per host role:
  - MCP server host: `uv sync --extra mcp-server`
  - Agent host: `uv sync --extra agent`
  - Single box / full dev: `uv sync --all-extras --group dev`
  - CI / detection-as-code only: `uv sync --extra dac`

---

## 5. Configure `.env`

- [ ] On each host: `cp .env.example .env` and edit it. `.env.example` is the fully annotated source of truth.

### 5.1 MCP server + shared auth token
- [ ] Generate a strong token: `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
- [ ] **MCP host:** set `ADEPT_MCP__AUTH_TOKEN` to that value.
- [ ] **Agent host:** set `ADEPT_AGENT__MCP_TOKEN` to the **same** value.
- [ ] Set `ADEPT_MCP__PUBLIC_URL` (MCP host) and `ADEPT_AGENT__MCP_URL` (agent host) to the Tailscale URL, e.g. `http://mcp-vm.your-tailnet.ts.net:8765/mcp`.
- [ ] Review `ADEPT_MCP__HOST` / `ADEPT_MCP__PORT` / `ADEPT_MCP__PATH` (defaults `0.0.0.0` / `8765` / `/mcp`).

### 5.2 Ollama
- [ ] `ADEPT_OLLAMA__BASE_URL` -> your Ollama host URL.
- [ ] `ADEPT_OLLAMA__MODEL` / `ADEPT_OLLAMA__EMBED_MODEL` -> the models you pulled.
- [ ] **[optional]** `ADEPT_AGENT__MODEL` to override the chat model just for the agent (blank = reuse `ADEPT_OLLAMA__MODEL`).

### 5.3 SIEMs (at least one)
- [ ] **ELK (primary, enabled by default):** `ADEPT_ELK__URL`, an `ADEPT_ELK__API_KEY` (preferred, least privilege) **or** username/password, `ADEPT_ELK__DEFAULT_INDEX`, and `ADEPT_ELK__VERIFY_CERTS` / `ADEPT_ELK__CA_CERT` for TLS.
- [ ] For deploying detections to the Kibana Detection Engine: set `ADEPT_ELK__KIBANA_URL` and `ADEPT_ELK__ALERTS_INDEX` (leave Kibana URL blank to disable the deploy path).
- [ ] **[optional]** **Wazuh / OpenSearch:** set `ADEPT_OPENSEARCH__ENABLED=true` + URL + credentials + index.
- [ ] **[optional]** **Splunk:** set `ADEPT_SPLUNK__ENABLED=true` + host/port + token (or user/pass) + index.
- [ ] Use **least-privilege** credentials scoped to search and (only if needed) deploy.

### 5.4 Sigma rules repository
- [ ] `ADEPT_SIGMA__PATH` -> the rules repo (default `./sigma_rules`, already bootstrapped in this project).
- [ ] Review `ADEPT_SIGMA__DEFAULT_BRANCH` and `ADEPT_SIGMA__PROTECTED_BRANCHES` (commits to protected branches require approval).
- [ ] **[VCS] [optional]** `ADEPT_SIGMA__REMOTE` if you push rules to Gitea/GitHub.

### 5.5 Threat intelligence
- [ ] **[optional]** `ADEPT_INTEL__NVD_API_KEY` — optional but raises NVD rate limits.
- [ ] Review the **SSRF allowlist** `ADEPT_INTEL__ALLOWED_DOMAINS` — only listed domains can be fetched. Add any extra RSS feed hosts you set in `ADEPT_INTEL__RSS_FEEDS`.

### 5.6 Knowledge base (RAG)
- [ ] `ADEPT_KB__PERSIST_DIR` (default `./data/chroma`) and `ADEPT_KB__EMBED_MODEL` (must be a pulled Ollama model).
- [ ] **[optional]** `ADEPT_KB__SIGMAHQ_PATH` -> a local SigmaHQ clone to also index community rules.

### 5.7 Attack simulation (purple-team) [optional]
- [ ] **Atomic Red Team (propose-only):** clone `redcanaryco/atomic-red-team`, set `ADEPT_ATTACK__ATOMIC_ENABLED=true` and `ADEPT_ATTACK__ATOMIC_PATH`, and curate `ADEPT_ATTACK__ATOMIC_ALLOWED_TESTS` (technique allowlist). ADEPT only *proposes* atomics — a human runs them.
- [ ] **Caldera:** set `ADEPT_ATTACK__CALDERA_ENABLED=true`, `ADEPT_ATTACK__CALDERA_URL`, `ADEPT_ATTACK__CALDERA_API_KEY`, and tune the planner/source/group ids per your server. Operations run only behind the human-approval gate.

### 5.8 Notifications [optional]
- [ ] Set `ADEPT_NOTIFY__BACKEND` (`none` | `ntfy` | `discord` | `slack` | `webhook`) and the matching URL/topic/token to get approval + deploy alerts.

### 5.9 Observability [optional]
- [ ] Install the extra (`uv sync --extra observability`), set `ADEPT_OTEL__ENABLED=true`, and point `ADEPT_OTEL__ENDPOINT` at your OTLP/HTTP collector (spans go to `<endpoint>/v1/traces`). Degrades to a no-op if unset.

---

## 6. Initialize data

- [ ] **[VCS]** **Initialize the Sigma repo as a git repository** (the DaC git tools require it):
  ```bash
  cd sigma_rules && git init && git add -A && git commit -m "Initial detection rules" && cd ..
  ```
- [ ] **Ingest the knowledge base** (Ollama must be running for embeddings):
  ```bash
  uv run adept-kb ingest          # indexes: own_rules, attack, homelab, tuning (+ sigmahq if configured)
  uv run adept-kb info            # verify the collection + document count
  ```
- [ ] The runtime `./data` dir (SQLite history, audit log, Chroma store) is created automatically — ensure the path is writable.

---

## 7. Verify offline

- [ ] Run the gate: `uv run pytest -q` (or `make check` for ruff + mypy + pytest).
- [ ] Run the detection-quality eval: `uv run adept-eval rules` (runs TP/FP unit tests from `sigma_rules/tests/`).

---

## 8. Bring it online — in order

1. [ ] **Ollama** is running and the models respond.
2. [ ] **Start the MCP server** on the homelab VM: `uv run adept-mcp` (or `make mcp`). Confirm it logs `starting_mcp_server` and the registered tool groups.
3. [ ] **Check connectivity** from the agent host over Tailscale (e.g. `curl -sS <ADEPT_AGENT__MCP_URL>` returns a response, not a connection error).
4. [ ] **Start the agent chatbot** on the agent host: `uv run adept chat` (or `make agent`).

---

## 9. First end-to-end test

- [ ] In `adept chat`, run a **read-only** request first, e.g. *"List the available SIEM backends"* or *"Search the last 24h of logs for PowerShell encoded commands"* — confirms MCP auth, SIEM connectivity, and routing.
- [ ] Ask it to **author and validate** a Sigma rule — confirms the rule-author path + detection-as-code conversion.
- [ ] **[optional]** Pin a request to one specialist by starting your message with `@<name>` (e.g. `@coverage_strategist where are my ATT&CK gaps?`) — names: `hunt_analyst`, `rule_author`, `coverage_strategist`, `deployment_operator`, `purple_team`.
- [ ] Trigger a **gated action** (e.g. deploy a test rule) and confirm the **human-approval gate** pauses for your approve/edit/reject decision.
- [ ] Review the trail: `uv run adept audit` (and `uv run adept threads` to see saved conversations).

---

## 10. Ongoing operations [optional]

- [ ] Re-run `uv run adept-kb ingest` after you add rules/docs so retrieval stays current.
- [ ] Use `uv run adept-coverage --help` to refresh the ATT&CK coverage matrix / gap analysis.
- [ ] Periodically review `./data/agent_audit.jsonl` (approvals + executed tools).
- [ ] Rotate `ADEPT_MCP__AUTH_TOKEN` (and the matching agent token) on a schedule.
- [ ] Keep SIEM credentials least-privilege and TLS verification enabled.

---

### Quick reference — console scripts

| Command | Purpose |
| --- | --- |
| `uv run adept chat` | Interactive detection-engineering chatbot (also `threads`, `audit`). |
| `uv run adept-mcp` | Start the MCP server. |
| `uv run adept-dac` | Standalone detection-as-code CLI (convert / validate / test). |
| `uv run adept-kb` | Knowledge-base `ingest` / `search` / `info`. |
| `uv run adept-coverage` | ATT&CK coverage matrix / gaps / overlaps. |
| `uv run adept-eval rules` | Offline TP/FP unit tests for Sigma rules. |

> **Troubleshooting:** if `uv` warns about a `VIRTUAL_ENV` mismatch (e.g. another
> project's venv is active in your shell), prefix the command with
> `unset VIRTUAL_ENV`.
