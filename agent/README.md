# Governance Agent (Snapshot -> Oracle -> Executor)

This agent automates governance operations in a trust-minimized way:

- Watches closed Snapshot proposals in one `space`.
- Verifies proposal payload -> on-chain `executionHash`.
- Computes and submits oracle settlement hashes.
- Proposes validated results on `OracleAdapter`.
- Challenges mismatched settlements.
- Attests results (if the agent wallet is an oracle attester).
- Permissionlessly finalizes and executes passed proposals via `finalizeAndExecuteBundle`.

The agent is non-custodial for governance logic. It cannot bypass contract checks.

## 1) Snapshot payload schema

Each Snapshot proposal should include plugin data under `plugins["governance_agent"]`:

```json
{
  "proposalId": "12",
  "salt": "0x8b5d7f8f7f7a60b86f4d3e1f7c5ab8d8ea4a3f1b7f6f3cb9244e4dfdfc0a2d09",
  "executionHash": "0xa4d6f1c12cce8e4d8fba7f9d3084f1f31f72fe18b38a3d3f9e082be8389dc58e",
  "transactions": [
    {
      "target": "0x1111111111111111111111111111111111111111",
      "value": "0",
      "data": "0x1234abcd"
    }
  ]
}
```

Notes:
- `proposalId` must match `StakeManager` proposal id.
- `salt` and `transactions` must reproduce the executor `executionHash`.
- `transactions` are encoded as `(address target, uint256 value, bytes data)`.

## 2) Configure policy

Copy `agent/policy.example.json` to your runtime policy file and update values.

Policy controls:
- Choice indexes for `for/against/abstain`.
- Which operations the bot can perform.
- Safety limits (`maxTransactionsPerProposal`, max ETH value per bundle).

## 3) Environment variables

Required:
- `GOV_AGENT_RPC_URL`
- `GOV_AGENT_PRIVATE_KEY`
- `GOV_AGENT_ORACLE_ADAPTER`
- `GOV_AGENT_STAKE_MANAGER`
- `GOV_AGENT_PARAMETER_MANAGER`
- `GOV_AGENT_EXECUTOR`

Optional:
- `GOV_AGENT_POLICY_PATH` (default: `agent/policy.example.json`)
- `GOV_AGENT_STATE_PATH` (default: `agent/state/agent-state.json`)
- `GOV_AGENT_POLL_SECONDS` (default: policy value)
- `GOV_AGENT_SNAPSHOT_GRAPHQL` (default: `https://hub.snapshot.org/graphql`)
- `GOV_AGENT_DRY_RUN=1` (simulate decisions, do not send txs)
- `GOV_AGENT_CONSENSUS_ENABLED=1` (send attestations to manager instead of directly sending propose/finalize/execute txs)
- `GOV_AGENT_MANAGER_URL` (required when agent consensus is enabled)
- `GOV_AGENT_CONSENSUS_AGENT_TOKEN` (required when agent consensus is enabled; unique per agent)
- `GOV_AGENT_INSTANCE_ID` (required when agent consensus is enabled)
- `GOV_AGENT_CONSENSUS_ACTIONS` (default `propose,finalize,execute`)

## 4) Run

Single cycle:

```bash
node agent/governance_agent.mjs --once
```

Daemon mode:

```bash
node agent/governance_agent.mjs
```

## 5) Run autonomously (recommended)

### A) Docker (auto-restart + healthcheck)

```bash
cd agent
cp .env.example .env
cp policy.example.json policy.json
docker compose up -d --build
docker compose ps
```

This uses:
- `agent/docker-compose.yml`
- `agent/Dockerfile`
- `agent/healthcheck.mjs`
- `agent/manager_api.mjs`

### B) Linux systemd

```bash
sudo cp agent/governance-agent.service /etc/systemd/system/governance-agent.service
sudo cp agent/governance-agent-manager.service /etc/systemd/system/governance-agent-manager.service
systemctl daemon-reload
systemctl enable --now governance-agent
systemctl enable --now governance-agent-manager
systemctl status governance-agent
systemctl status governance-agent-manager
```

Edit both `.service` files first and replace `/path/to/repo` with your local checkout path.

### C) macOS launchd

```bash
cp agent/com.governance.agent.plist ~/Library/LaunchAgents/com.governance.agent.plist
cp agent/com.governance.agent.manager.plist ~/Library/LaunchAgents/com.governance.agent.manager.plist
launchctl unload ~/Library/LaunchAgents/com.governance.agent.plist 2>/dev/null || true
launchctl unload ~/Library/LaunchAgents/com.governance.agent.manager.plist 2>/dev/null || true
launchctl load ~/Library/LaunchAgents/com.governance.agent.plist
launchctl load ~/Library/LaunchAgents/com.governance.agent.manager.plist
launchctl list | grep com.governance.agent
launchctl list | grep com.governance.agent.manager
```

Edit both `.plist` files first and replace `/path/to/repo` with your local checkout path.

## 6) Agent manager API (add self-hosted agents)

Start manager API:

```bash
node agent/manager_api.mjs
```

Manager settings (`.env`):
- `GOV_AGENT_MANAGER_HOST` (default `127.0.0.1`)
- `GOV_AGENT_MANAGER_PORT` (default `8787`)
- `GOV_AGENT_MANAGER_TOKEN` (required, min 24 chars)
- `GOV_AGENT_MANAGER_ENCRYPTION_KEY` (required, min 24 chars; encrypts stored secrets)
- `GOV_AGENT_MANAGER_ALLOW_REMOTE` (default `0`, local-only API)
- `GOV_AGENT_MANAGER_ALLOWED_ORIGINS` (comma-separated CORS allowlist; empty disables CORS access)
- `GOV_AGENT_MANAGER_DB_PATH`
- `GOV_AGENT_MANAGER_INSTANCES_DIR`
- `GOV_AGENT_MANAGER_DEFAULT_POLICY_PATH`
- `GOV_AGENT_MANAGER_MIN_SUCCESS_CYCLES` (default `20`)
- `GOV_AGENT_MANAGER_MIN_CANDIDATE_UPTIME_SECONDS` (default `3600`)
- `GOV_AGENT_MANAGER_MAX_CANDIDATE_CRASH_COUNT` (default `3`)
- `GOV_AGENT_MANAGER_AUTH_WINDOW_SECONDS` (default `300`)
- `GOV_AGENT_MANAGER_AUTH_MAX_FAILURES` (default `10`)
- `GOV_AGENT_MANAGER_AUTH_BLOCK_SECONDS` (default `900`)
- `GOV_AGENT_MANAGER_CONSENSUS_ENABLED` (default `1`)
- `GOV_AGENT_MANAGER_EXECUTOR_RPC_URL` (required when manager consensus is enabled)
- `GOV_AGENT_MANAGER_EXECUTOR_PRIVATE_KEY` (required when manager consensus is enabled)
- `GOV_AGENT_MANAGER_CONSENSUS_THRESHOLD_PROPOSE` (default `2`)
- `GOV_AGENT_MANAGER_CONSENSUS_THRESHOLD_FINALIZE` (default `2`)
- `GOV_AGENT_MANAGER_CONSENSUS_THRESHOLD_EXECUTE` (default `2`)

Auth:
- Admin endpoints (`/agents*`, `/health`, `/consensus/actions`) require:
  - `Authorization: Bearer <GOV_AGENT_MANAGER_TOKEN>`
- Agent consensus endpoint (`POST /consensus/attest`) requires:
  - `Authorization: Bearer <GOV_AGENT_CONSENSUS_AGENT_TOKEN>` for that specific `agentId`

### Add an agent via API

```bash
curl -X POST http://127.0.0.1:8787/agents \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer replace-with-random-token' \
  -d '{
    "id":"operator_1",
    "autostart":true,
    "env":{
      "GOV_AGENT_RPC_URL":"https://rpc.yourchain.example",
      "GOV_AGENT_PRIVATE_KEY":"0xYOUR_PRIVATE_KEY",
      "GOV_AGENT_ORACLE_ADAPTER":"0xOracleAdapterAddress",
      "GOV_AGENT_STAKE_MANAGER":"0xStakeManagerAddress",
      "GOV_AGENT_PARAMETER_MANAGER":"0xParameterManagerAddress",
      "GOV_AGENT_EXECUTOR":"0xGovernanceExecutorAddress",
      "GOV_AGENT_DRY_RUN":"1"
    }
  }'
```

New agents are created as `permissionLevel: "candidate"` and enforced as `GOV_AGENT_DRY_RUN=1`.
After testing passes, promote to `permissionLevel: "standard"` (same runtime tx permissions as regular operators).

If consensus mode is enabled for an agent (`GOV_AGENT_CONSENSUS_ENABLED=1`), set a unique `GOV_AGENT_CONSENSUS_AGENT_TOKEN` for that agent.

### Promote a tested agent

```bash
curl -X POST http://127.0.0.1:8787/agents/operator_1/promote \
  -H 'authorization: Bearer replace-with-random-token'
```

Promotion requires:
- `estimatedCandidateCycles >= GOV_AGENT_MANAGER_MIN_SUCCESS_CYCLES` (derived from observed candidate uptime and poll interval)
- `candidateObserved.uptimeSeconds >= GOV_AGENT_MANAGER_MIN_CANDIDATE_UPTIME_SECONDS`
- `candidateObserved.crashCount <= GOV_AGENT_MANAGER_MAX_CANDIDATE_CRASH_COUNT`
- agent exists in manager registry

Useful endpoints:
- `GET /agents`
- `GET /agents/:id`
- `PATCH /agents/:id` (update env/policy/autostart, optional `"restart": true`)
- `POST /agents/:id/start`
- `POST /agents/:id/stop`
- `POST /agents/:id/restart`
- `POST /agents/:id/promote` (candidate -> standard after test threshold)
- `DELETE /agents/:id`
- `GET /consensus/actions` (audit queued/executed consensus actions)

## 7) Health monitoring

You can probe liveness directly:

```bash
node agent/healthcheck.mjs
```

Health is based on `lastHeartbeatAt` in the state file.

## 8) Optional AI advisory mode (constrained)

Enable AI advisory with:
- `GOV_AGENT_AI_ENABLED=1`
- `GOV_AGENT_OPENAI_API_KEY=<key>`

Optional:
- `GOV_AGENT_AI_MODEL` (default: `gpt-4o-mini`)
- `GOV_AGENT_AI_BASE_URL` (default: OpenAI Chat Completions URL)

Design constraints enforced in system prompt:
- AI cannot authorize or execute transactions.
- AI output is advisory only.
- Deterministic rule checks remain authoritative.
- Output must be strict JSON:
  - `risk_level`
  - `confidence`
  - `summary`
  - `reasons`
  - `flags`
  - `recommended_action`

The agent stores AI reviews under `lastAiReviews` in state and logs them, but does not let AI bypass safety checks.

## 9) Security recommendations

- Use a dedicated hot wallet with limited funds.
- Use separate wallets for `attester` and `executor` roles when possible.
- Use unique `GOV_AGENT_CONSENSUS_AGENT_TOKEN` values per agent; never reuse manager admin token for agent attestations.
- Start with `GOV_AGENT_DRY_RUN=1`.
- Keep high-impact ops behind existing on-chain timelocks and allowlists.
- Run multiple independent agents (different operators) for redundancy.
- Keep `GOV_AGENT_MANAGER_ALLOW_REMOTE=0` unless you intentionally front with a secure proxy/VPN.
