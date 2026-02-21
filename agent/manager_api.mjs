#!/usr/bin/env node

import { execFileSync, spawn } from "node:child_process";
import { createCipheriv, createDecipheriv, createHash, randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { createServer } from "node:http";
import { createWriteStream, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const AGENT_DIR = dirname(__filename);
const ROOT_DIR = resolve(AGENT_DIR, "..");
const RUNNER_PATH = resolve(AGENT_DIR, "governance_agent.mjs");

const DEFAULT_DB_PATH = resolve(AGENT_DIR, "state", "manager-agents.json");
const DEFAULT_INSTANCES_DIR = resolve(AGENT_DIR, "state", "instances");
const DEFAULT_POLICY_PATH = existsSync(resolve(AGENT_DIR, "policy.json"))
  ? resolve(AGENT_DIR, "policy.json")
  : resolve(AGENT_DIR, "policy.example.json");

const REQUIRED_ENV_KEYS = [
  "GOV_AGENT_RPC_URL",
  "GOV_AGENT_PRIVATE_KEY",
  "GOV_AGENT_ORACLE_ADAPTER",
  "GOV_AGENT_STAKE_MANAGER",
  "GOV_AGENT_PARAMETER_MANAGER",
  "GOV_AGENT_EXECUTOR"
];

const ADDRESS_ENV_KEYS = [
  "GOV_AGENT_ORACLE_ADAPTER",
  "GOV_AGENT_STAKE_MANAGER",
  "GOV_AGENT_PARAMETER_MANAGER",
  "GOV_AGENT_EXECUTOR"
];

const ALLOWED_ENV_KEYS = new Set([
  ...REQUIRED_ENV_KEYS,
  "GOV_AGENT_POLL_SECONDS",
  "GOV_AGENT_SNAPSHOT_GRAPHQL",
  "GOV_AGENT_DRY_RUN",
  "GOV_AGENT_CONSENSUS_ENABLED",
  "GOV_AGENT_MANAGER_URL",
  "GOV_AGENT_MANAGER_TOKEN",
  "GOV_AGENT_CONSENSUS_AGENT_TOKEN",
  "GOV_AGENT_INSTANCE_ID",
  "GOV_AGENT_CONSENSUS_ACTIONS",
  "GOV_AGENT_AI_ENABLED",
  "GOV_AGENT_OPENAI_API_KEY",
  "GOV_AGENT_AI_MODEL",
  "GOV_AGENT_AI_BASE_URL",
  "GOV_AGENT_HEALTH_MAX_AGE_SECONDS"
]);

const PERMISSION_CANDIDATE = "candidate";
const PERMISSION_STANDARD = "standard";
const CONSENSUS_ACTION_TYPES = new Set(["propose", "finalize", "execute"]);
const CONSENSUS_SELECTOR_BY_ACTION = Object.freeze({
  propose: "0xeed7a962",
  finalize: "0x2ec7d5ae",
  execute: "0x70dd9b1e"
});
const ENCRYPTED_PREFIX = "enc:v1:";
const SENSITIVE_ENV_KEYS = new Set([
  "GOV_AGENT_PRIVATE_KEY",
  "GOV_AGENT_OPENAI_API_KEY",
  "GOV_AGENT_MANAGER_TOKEN",
  "GOV_AGENT_CONSENSUS_AGENT_TOKEN"
]);

function normalizePermissionLevel(value) {
  if (value === undefined || value === null || value === "") return PERMISSION_CANDIDATE;
  const level = String(value).toLowerCase();
  if (level !== PERMISSION_CANDIDATE && level !== PERMISSION_STANDARD) {
    throw new Error(`invalid permissionLevel: ${value}`);
  }
  return level;
}

function enforcePermissionEnv(permissionLevel, env) {
  const out = { ...env };
  if (permissionLevel === PERMISSION_CANDIDATE) {
    out.GOV_AGENT_DRY_RUN = "1";
  } else if (!out.GOV_AGENT_DRY_RUN) {
    out.GOV_AGENT_DRY_RUN = "0";
  }
  return out;
}

function deriveKey(secret) {
  return createHash("sha256").update(secret).digest();
}

function encryptSecret(key, plaintext) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${ENCRYPTED_PREFIX}${iv.toString("base64url")}.${tag.toString("base64url")}.${encrypted.toString("base64url")}`;
}

function decryptSecret(key, input) {
  if (typeof input !== "string" || !input.startsWith(ENCRYPTED_PREFIX)) return String(input || "");
  const payload = input.slice(ENCRYPTED_PREFIX.length);
  const parts = payload.split(".");
  if (parts.length !== 3) throw new Error("invalid encrypted payload");

  const iv = Buffer.from(parts[0], "base64url");
  const tag = Buffer.from(parts[1], "base64url");
  const encrypted = Buffer.from(parts[2], "base64url");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString("utf8");
}

function encryptEnvSecrets(env, key) {
  const out = { ...env };
  for (const sensitiveKey of SENSITIVE_ENV_KEYS) {
    const value = out[sensitiveKey];
    if (typeof value !== "string" || value.length === 0) continue;
    if (!value.startsWith(ENCRYPTED_PREFIX)) {
      out[sensitiveKey] = encryptSecret(key, value);
    }
  }
  return out;
}

function decryptEnvSecrets(env, key) {
  const out = { ...env };
  for (const sensitiveKey of SENSITIVE_ENV_KEYS) {
    const value = out[sensitiveKey];
    if (value === undefined) continue;
    out[sensitiveKey] = decryptSecret(key, value);
  }
  return out;
}

function toUintString(value, field) {
  try {
    const v = BigInt(String(value));
    if (v < 0n) throw new Error("negative");
    return v.toString();
  } catch {
    throw new Error(`${field} must be an unsigned integer`);
  }
}

function sendManagedTx(rpcUrl, privateKey, to, data, value) {
  const args = [
    "send",
    to,
    "--data",
    data,
    "--value",
    value,
    "--private-key",
    privateKey,
    "--rpc-url",
    rpcUrl,
    "--async"
  ];
  const out = execFileSync("cast", args, { encoding: "utf8" }).trim();
  const match = out.match(/0x[a-fA-F0-9]{64}/);
  if (!match) throw new Error(`unable to parse cast send tx hash: ${out}`);
  return match[0].toLowerCase();
}

function nowIso() {
  return new Date().toISOString();
}

function log(level, message, meta = undefined) {
  const base = `[${nowIso()}] [manager:${level}] ${message}`;
  if (meta === undefined) {
    console.log(base);
    return;
  }
  console.log(`${base} ${JSON.stringify(meta)}`);
}

function loadJson(path, fallback) {
  if (!existsSync(path)) return fallback;
  const raw = readFileSync(path, "utf8");
  return JSON.parse(raw);
}

function saveJson(path, value) {
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

function isValidAgentId(id) {
  return typeof id === "string" && /^[a-zA-Z0-9_-]{1,64}$/.test(id);
}

function normalizeAddress(value) {
  if (typeof value !== "string") return "";
  const v = value.trim();
  if (!/^0x[a-fA-F0-9]{40}$/.test(v)) return "";
  return v.toLowerCase();
}

function tokenEquals(provided, expected) {
  if (typeof provided !== "string" || typeof expected !== "string") return false;
  const left = Buffer.from(provided);
  const right = Buffer.from(expected);
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

function extractBearerToken(authHeader) {
  if (typeof authHeader !== "string" || !authHeader.startsWith("Bearer ")) return "";
  return authHeader.slice("Bearer ".length);
}

function jsonResponse(res, code, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(code, {
    "content-type": "application/json",
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
    ...extraHeaders
  });
  res.end(body);
}

function isLoopbackAddress(remoteAddress) {
  return (
    remoteAddress === "127.0.0.1"
    || remoteAddress === "::1"
    || remoteAddress === "::ffff:127.0.0.1"
  );
}

function corsHeadersForOrigin(origin, allowedOrigins) {
  if (!origin) return {};
  if (!allowedOrigins.includes(origin)) return {};
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET,POST,PATCH,DELETE,OPTIONS",
    "access-control-allow-headers": "content-type,authorization",
    vary: "Origin"
  };
}

function parseBody(req) {
  return new Promise((resolvePromise, rejectPromise) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 1024 * 1024) {
        rejectPromise(new Error("request body too large"));
      }
    });
    req.on("end", () => {
      if (raw.length === 0) {
        resolvePromise({});
        return;
      }
      try {
        resolvePromise(JSON.parse(raw));
      } catch {
        rejectPromise(new Error("invalid JSON body"));
      }
    });
    req.on("error", rejectPromise);
  });
}

function sanitizeEnv(input) {
  if (!input || typeof input !== "object" || Array.isArray(input)) {
    throw new Error("env must be an object");
  }

  const env = {};
  for (const [key, value] of Object.entries(input)) {
    if (!ALLOWED_ENV_KEYS.has(key)) {
      throw new Error(`env key not allowed: ${key}`);
    }
    env[key] = String(value);
  }

  for (const required of REQUIRED_ENV_KEYS) {
    if (!env[required] || env[required].trim().length === 0) {
      throw new Error(`missing required env key: ${required}`);
    }
  }

  if (!/^0x[a-fA-F0-9]{64}$/.test(env.GOV_AGENT_PRIVATE_KEY)) {
    throw new Error("GOV_AGENT_PRIVATE_KEY must be a 32-byte hex private key");
  }

  for (const key of ADDRESS_ENV_KEYS) {
    if (!/^0x[a-fA-F0-9]{40}$/.test(env[key])) {
      throw new Error(`${key} must be a valid EVM address`);
    }
  }

  if (env.GOV_AGENT_POLL_SECONDS !== undefined) {
    const pollSeconds = Number(env.GOV_AGENT_POLL_SECONDS);
    if (!Number.isFinite(pollSeconds) || pollSeconds <= 0 || pollSeconds > 3600) {
      throw new Error("GOV_AGENT_POLL_SECONDS must be between 1 and 3600");
    }
  }

  if (env.GOV_AGENT_CONSENSUS_ENABLED !== undefined) {
    if (env.GOV_AGENT_CONSENSUS_ENABLED !== "0" && env.GOV_AGENT_CONSENSUS_ENABLED !== "1") {
      throw new Error("GOV_AGENT_CONSENSUS_ENABLED must be '0' or '1'");
    }
    if (env.GOV_AGENT_CONSENSUS_ENABLED === "1") {
      if (!env.GOV_AGENT_MANAGER_URL || !/^https?:\/\//.test(env.GOV_AGENT_MANAGER_URL)) {
        throw new Error("GOV_AGENT_MANAGER_URL must be set to http(s) URL when consensus is enabled");
      }
      if (!env.GOV_AGENT_CONSENSUS_AGENT_TOKEN || env.GOV_AGENT_CONSENSUS_AGENT_TOKEN.length < 24) {
        throw new Error("GOV_AGENT_CONSENSUS_AGENT_TOKEN must be set when consensus is enabled");
      }
      if (!env.GOV_AGENT_INSTANCE_ID || !isValidAgentId(env.GOV_AGENT_INSTANCE_ID)) {
        throw new Error("GOV_AGENT_INSTANCE_ID must be set when consensus is enabled");
      }
    }
  }

  return env;
}

function buildManagerConfig() {
  const host = process.env.GOV_AGENT_MANAGER_HOST || "127.0.0.1";
  const port = Number(process.env.GOV_AGENT_MANAGER_PORT || 8787);
  const token = process.env.GOV_AGENT_MANAGER_TOKEN || "";
  const encryptionKeyInput = process.env.GOV_AGENT_MANAGER_ENCRYPTION_KEY || "";
  const allowRemote = process.env.GOV_AGENT_MANAGER_ALLOW_REMOTE === "1";
  const allowedOrigins = (process.env.GOV_AGENT_MANAGER_ALLOWED_ORIGINS || "")
    .split(",")
    .map((v) => v.trim())
    .filter((v) => v.length > 0);
  const dbPath = process.env.GOV_AGENT_MANAGER_DB_PATH || DEFAULT_DB_PATH;
  const instancesDir = process.env.GOV_AGENT_MANAGER_INSTANCES_DIR || DEFAULT_INSTANCES_DIR;
  const defaultPolicyPath = process.env.GOV_AGENT_MANAGER_DEFAULT_POLICY_PATH || DEFAULT_POLICY_PATH;
  const minSuccessCyclesForPromotion = Number(process.env.GOV_AGENT_MANAGER_MIN_SUCCESS_CYCLES || 20);
  const minCandidateUptimeSeconds = Number(process.env.GOV_AGENT_MANAGER_MIN_CANDIDATE_UPTIME_SECONDS || 3600);
  const maxCandidateCrashCount = Number(process.env.GOV_AGENT_MANAGER_MAX_CANDIDATE_CRASH_COUNT || 3);
  const consensusEnabled = process.env.GOV_AGENT_MANAGER_CONSENSUS_ENABLED !== "0";
  const consensusExecutorRpcUrl = process.env.GOV_AGENT_MANAGER_EXECUTOR_RPC_URL || "";
  const consensusExecutorPrivateKey = process.env.GOV_AGENT_MANAGER_EXECUTOR_PRIVATE_KEY || "";
  const consensusThresholdPropose = Number(process.env.GOV_AGENT_MANAGER_CONSENSUS_THRESHOLD_PROPOSE || 2);
  const consensusThresholdFinalize = Number(process.env.GOV_AGENT_MANAGER_CONSENSUS_THRESHOLD_FINALIZE || 2);
  const consensusThresholdExecute = Number(process.env.GOV_AGENT_MANAGER_CONSENSUS_THRESHOLD_EXECUTE || 2);
  const authWindowSeconds = Number(process.env.GOV_AGENT_MANAGER_AUTH_WINDOW_SECONDS || 300);
  const authMaxFailures = Number(process.env.GOV_AGENT_MANAGER_AUTH_MAX_FAILURES || 10);
  const authBlockSeconds = Number(process.env.GOV_AGENT_MANAGER_AUTH_BLOCK_SECONDS || 900);

  if (!Number.isFinite(port) || port <= 0 || port > 65535) {
    throw new Error("GOV_AGENT_MANAGER_PORT must be a valid TCP port");
  }
  if (!token || token.length < 24) {
    throw new Error("GOV_AGENT_MANAGER_TOKEN must be set and at least 24 characters");
  }
  if (token.includes("replace-with-")) {
    throw new Error("GOV_AGENT_MANAGER_TOKEN must not use the example placeholder value");
  }
  if (!encryptionKeyInput || encryptionKeyInput.length < 24) {
    throw new Error("GOV_AGENT_MANAGER_ENCRYPTION_KEY must be set and at least 24 characters");
  }
  if (encryptionKeyInput.includes("replace-with-")) {
    throw new Error("GOV_AGENT_MANAGER_ENCRYPTION_KEY must not use the example placeholder value");
  }
  if (!Number.isFinite(minSuccessCyclesForPromotion) || minSuccessCyclesForPromotion < 1) {
    throw new Error("GOV_AGENT_MANAGER_MIN_SUCCESS_CYCLES must be >= 1");
  }
  if (!Number.isFinite(minCandidateUptimeSeconds) || minCandidateUptimeSeconds < 1) {
    throw new Error("GOV_AGENT_MANAGER_MIN_CANDIDATE_UPTIME_SECONDS must be >= 1");
  }
  if (!Number.isFinite(maxCandidateCrashCount) || maxCandidateCrashCount < 0) {
    throw new Error("GOV_AGENT_MANAGER_MAX_CANDIDATE_CRASH_COUNT must be >= 0");
  }
  for (const [name, value] of [
    ["GOV_AGENT_MANAGER_CONSENSUS_THRESHOLD_PROPOSE", consensusThresholdPropose],
    ["GOV_AGENT_MANAGER_CONSENSUS_THRESHOLD_FINALIZE", consensusThresholdFinalize],
    ["GOV_AGENT_MANAGER_CONSENSUS_THRESHOLD_EXECUTE", consensusThresholdExecute]
  ]) {
    if (!Number.isFinite(value) || value < 1) {
      throw new Error(`${name} must be >= 1`);
    }
  }
  if (consensusEnabled) {
    if (!consensusExecutorRpcUrl || !/^https?:\/\//.test(consensusExecutorRpcUrl)) {
      throw new Error("GOV_AGENT_MANAGER_EXECUTOR_RPC_URL must be set when consensus is enabled");
    }
    if (!/^0x[a-fA-F0-9]{64}$/.test(consensusExecutorPrivateKey)) {
      throw new Error("GOV_AGENT_MANAGER_EXECUTOR_PRIVATE_KEY must be a 32-byte hex key");
    }
  }
  if (!Number.isFinite(authWindowSeconds) || authWindowSeconds < 1) {
    throw new Error("GOV_AGENT_MANAGER_AUTH_WINDOW_SECONDS must be >= 1");
  }
  if (!Number.isFinite(authMaxFailures) || authMaxFailures < 1) {
    throw new Error("GOV_AGENT_MANAGER_AUTH_MAX_FAILURES must be >= 1");
  }
  if (!Number.isFinite(authBlockSeconds) || authBlockSeconds < 1) {
    throw new Error("GOV_AGENT_MANAGER_AUTH_BLOCK_SECONDS must be >= 1");
  }

  return {
    host,
    port,
    token,
    encryptionKey: deriveKey(encryptionKeyInput),
    allowRemote,
    allowedOrigins,
    dbPath,
    instancesDir,
    defaultPolicyPath,
    minSuccessCyclesForPromotion,
    minCandidateUptimeSeconds,
    maxCandidateCrashCount,
    consensusEnabled,
    consensusExecutorRpcUrl,
    consensusExecutorPrivateKey,
    consensusThresholds: {
      propose: consensusThresholdPropose,
      finalize: consensusThresholdFinalize,
      execute: consensusThresholdExecute
    },
    authWindowSeconds,
    authMaxFailures,
    authBlockSeconds
  };
}

function ensureManagerDb(config) {
  const db = loadJson(config.dbPath, null);
  if (db && typeof db === "object" && db.agents && typeof db.agents === "object") {
    if (!db.consensusActions || typeof db.consensusActions !== "object") {
      db.consensusActions = {};
    }
    return db;
  }
  return { agents: {}, consensusActions: {} };
}

function makeInstancePaths(config, id) {
  const dir = resolve(config.instancesDir, id);
  return {
    dir,
    policyPath: resolve(dir, "policy.json"),
    statePath: resolve(dir, "agent-state.json"),
    stdoutPath: resolve(dir, "agent.stdout.log"),
    stderrPath: resolve(dir, "agent.stderr.log")
  };
}

function writePolicyFile(policyPath, policyInput, defaultPolicyPath) {
  mkdirSync(dirname(policyPath), { recursive: true, mode: 0o700 });

  if (policyInput === undefined) {
    if (!existsSync(defaultPolicyPath)) {
      throw new Error(`default policy file not found: ${defaultPolicyPath}`);
    }
    const raw = readFileSync(defaultPolicyPath, "utf8");
    writeFileSync(policyPath, raw, { encoding: "utf8", mode: 0o600 });
    return;
  }

  if (!policyInput || typeof policyInput !== "object" || Array.isArray(policyInput)) {
    throw new Error("policy must be an object when provided");
  }
  writeFileSync(policyPath, `${JSON.stringify(policyInput, null, 2)}\n`, { encoding: "utf8", mode: 0o600 });
}

class AgentManager {
  constructor(config) {
    this.config = config;
    this.db = ensureManagerDb(config);
    this.processes = new Map();
    this._migrateAgents();
  }

  _migrateAgents() {
    let changed = false;
    for (const agent of Object.values(this.db.agents)) {
      if (!agent.permissionLevel) {
        agent.permissionLevel = PERMISSION_CANDIDATE;
        changed = true;
      }
      if (agent.permissionLevel === PERMISSION_CANDIDATE && !agent.candidateStats) {
        agent.candidateStats = {
          phaseStartedAt: nowIso(),
          uptimeSeconds: 0,
          crashCount: 0,
          currentStartAt: null
        };
        changed = true;
      }

      const decrypted = decryptEnvSecrets(agent.env || {}, this.config.encryptionKey);
      const enforcedEnv = enforcePermissionEnv(agent.permissionLevel, decrypted);
      const encrypted = encryptEnvSecrets(enforcedEnv, this.config.encryptionKey);
      if (JSON.stringify(encrypted) !== JSON.stringify(agent.env || {})) {
        agent.env = encrypted;
        changed = true;
      }
    }
    if (changed) this.save();
  }

  save() {
    saveJson(this.config.dbPath, this.db);
  }

  listAgents() {
    return Object.values(this.db.agents).map((agent) => this._view(agent));
  }

  getAgent(id) {
    const agent = this.db.agents[id];
    if (!agent) return null;
    return this._view(agent);
  }

  _readStateMetrics(agent) {
    const state = loadJson(agent.statePath, {});
    return {
      totalCycles: Number(state?.totalCycles || 0),
      successfulCycles: Number(state?.successfulCycles || 0),
      failedCycles: Number(state?.failedCycles || 0),
      lastHeartbeatAt: state?.lastHeartbeatAt || null,
      lastSuccessAt: state?.lastSuccessAt || null,
      lastErrorAt: state?.lastErrorAt || null
    };
  }

  _candidateObserved(agent) {
    const stats = agent.candidateStats || {
      phaseStartedAt: nowIso(),
      uptimeSeconds: 0,
      crashCount: 0,
      currentStartAt: null
    };
    let uptimeSeconds = Number(stats.uptimeSeconds || 0);
    if (agent.permissionLevel === PERMISSION_CANDIDATE && typeof stats.currentStartAt === "string") {
      const startedMs = Date.parse(stats.currentStartAt);
      if (!Number.isNaN(startedMs)) {
        const delta = Math.floor((Date.now() - startedMs) / 1000);
        if (delta > 0) uptimeSeconds += delta;
      }
    }
    return {
      phaseStartedAt: stats.phaseStartedAt || null,
      uptimeSeconds,
      crashCount: Number(stats.crashCount || 0)
    };
  }

  _estimatedCandidateCycles(agent) {
    const observed = this._candidateObserved(agent);
    const decrypted = decryptEnvSecrets(agent.env || {}, this.config.encryptionKey);
    const pollSeconds = Math.max(1, Number(decrypted.GOV_AGENT_POLL_SECONDS || 30));
    return Math.floor(observed.uptimeSeconds / pollSeconds);
  }

  addAgent(payload) {
    const id = payload?.id;
    if (!isValidAgentId(id)) throw new Error("id must match /^[a-zA-Z0-9_-]{1,64}$/");
    if (this.db.agents[id]) throw new Error("agent already exists");

    const permissionLevel = normalizePermissionLevel(payload?.permissionLevel);
    if (permissionLevel === PERMISSION_STANDARD) {
      throw new Error("new agents must start as candidate; use /promote after testing");
    }
    const env = enforcePermissionEnv(permissionLevel, sanitizeEnv(payload.env));
    const envEncrypted = encryptEnvSecrets(env, this.config.encryptionKey);
    const paths = makeInstancePaths(this.config, id);
    writePolicyFile(paths.policyPath, payload.policy, this.config.defaultPolicyPath);

    const now = nowIso();
    const agent = {
      id,
      createdAt: now,
      updatedAt: now,
      autostart: payload.autostart !== false,
      permissionLevel,
      env: envEncrypted,
      candidateStats: {
        phaseStartedAt: now,
        uptimeSeconds: 0,
        crashCount: 0,
        currentStartAt: null
      },
      policyPath: paths.policyPath,
      statePath: paths.statePath,
      stdoutPath: paths.stdoutPath,
      stderrPath: paths.stderrPath,
      lastExitCode: null,
      lastExitSignal: null
    };

    this.db.agents[id] = agent;
    this.save();

    if (agent.autostart) {
      this.startAgent(id);
    }

    return this._view(agent);
  }

  updateAgent(id, payload) {
    const agent = this.db.agents[id];
    if (!agent) throw new Error("agent not found");

    if (payload.env !== undefined) {
      const env = enforcePermissionEnv(agent.permissionLevel, sanitizeEnv(payload.env));
      agent.env = encryptEnvSecrets(env, this.config.encryptionKey);
    }

    if (payload.policy !== undefined) {
      writePolicyFile(agent.policyPath, payload.policy, this.config.defaultPolicyPath);
    }

    if (payload.autostart !== undefined) {
      agent.autostart = Boolean(payload.autostart);
    }

    agent.updatedAt = nowIso();
    this.save();

    if (payload.restart === true) {
      this.restartAgent(id);
    }

    return this._view(agent);
  }

  promoteAgent(id) {
    const agent = this.db.agents[id];
    if (!agent) throw new Error("agent not found");
    if (agent.permissionLevel === PERMISSION_STANDARD) return this._view(agent);

    const observed = this._candidateObserved(agent);
    const estimatedCycles = this._estimatedCandidateCycles(agent);
    const minCycles = this.config.minSuccessCyclesForPromotion;
    if (estimatedCycles < minCycles) {
      throw new Error(
        `agent has not passed testing threshold: estimatedCycles=${estimatedCycles}, required=${minCycles}`
      );
    }
    if (observed.uptimeSeconds < this.config.minCandidateUptimeSeconds) {
      throw new Error(
        `agent candidate uptime too low: uptimeSeconds=${observed.uptimeSeconds}, required=${this.config.minCandidateUptimeSeconds}`
      );
    }
    if (observed.crashCount > this.config.maxCandidateCrashCount) {
      throw new Error(
        `agent crash count too high: crashCount=${observed.crashCount}, max=${this.config.maxCandidateCrashCount}`
      );
    }

    agent.permissionLevel = PERMISSION_STANDARD;
    const decrypted = decryptEnvSecrets(agent.env, this.config.encryptionKey);
    agent.env = encryptEnvSecrets(enforcePermissionEnv(agent.permissionLevel, decrypted), this.config.encryptionKey);
    agent.candidateStats = null;
    agent.updatedAt = nowIso();
    this.save();

    return this.restartAgent(id);
  }

  _consensusKey(actionType, proposalId, to, value, data) {
    const hash = createHash("sha256")
      .update(`${actionType}|${proposalId}|${to.toLowerCase()}|${value}|${data.toLowerCase()}`)
      .digest("hex");
    return `v1:${hash}`;
  }

  _viewConsensusAction(action) {
    return {
      id: action.id,
      actionType: action.actionType,
      proposalId: action.proposalId,
      to: action.to,
      value: action.value,
      dataHash: createHash("sha256").update(action.data).digest("hex"),
      threshold: action.threshold,
      attestorCount: Object.keys(action.attestors || {}).length,
      attestors: Object.keys(action.attestors || {}),
      executed: Boolean(action.executedAt),
      txHash: action.txHash || null,
      createdAt: action.createdAt,
      updatedAt: action.updatedAt,
      executedAt: action.executedAt || null
    };
  }

  listConsensusActions() {
    return Object.values(this.db.consensusActions || {}).map((a) => this._viewConsensusAction(a));
  }

  verifyConsensusAttestor(agentId, bearerToken) {
    if (!isValidAgentId(agentId)) return false;
    const agent = this.db.agents[agentId];
    if (!agent || agent.permissionLevel !== PERMISSION_STANDARD) return false;
    const decryptedEnv = decryptEnvSecrets(agent.env || {}, this.config.encryptionKey);
    const expected = String(decryptedEnv.GOV_AGENT_CONSENSUS_AGENT_TOKEN || "");
    if (expected.length < 24) return false;
    return tokenEquals(bearerToken, expected);
  }

  _validateConsensusActionForAgent(agent, actionType, proposalId, to, data) {
    if (!/^0x[a-fA-F0-9]+$/.test(data) || data.length < 10 || data.length % 2 !== 0) {
      throw new Error("data must be non-empty hex calldata");
    }

    const selector = data.slice(0, 10).toLowerCase();
    const expectedSelector = CONSENSUS_SELECTOR_BY_ACTION[actionType];
    if (selector !== expectedSelector) {
      throw new Error(`calldata selector mismatch for action type ${actionType}`);
    }

    if (data.length < 74) {
      throw new Error("calldata too short to extract proposalId");
    }

    let encodedProposalId;
    try {
      encodedProposalId = BigInt(`0x${data.slice(10, 74)}`).toString();
    } catch {
      throw new Error("calldata proposalId decode failed");
    }
    if (encodedProposalId !== proposalId) {
      throw new Error("proposalId mismatch between request and calldata");
    }

    const env = decryptEnvSecrets(agent.env || {}, this.config.encryptionKey);
    const expectedTarget = actionType === "execute"
      ? normalizeAddress(env.GOV_AGENT_EXECUTOR || "")
      : normalizeAddress(env.GOV_AGENT_ORACLE_ADAPTER || "");
    if (!expectedTarget) {
      throw new Error("agent is missing expected on-chain target for consensus action");
    }
    if (to !== expectedTarget) {
      throw new Error(`target mismatch for action type ${actionType}`);
    }
  }

  recordConsensusAttestation(payload) {
    if (!this.config.consensusEnabled) {
      throw new Error("manager consensus execution is disabled");
    }

    const agentId = payload?.agentId;
    if (!isValidAgentId(agentId)) throw new Error("agentId is invalid");
    const agent = this.db.agents[agentId];
    if (!agent) throw new Error("agent not found");
    if (agent.permissionLevel !== PERMISSION_STANDARD) {
      throw new Error("only standard agents may submit consensus attestations");
    }

    const actionType = String(payload?.actionType || "").toLowerCase();
    if (!CONSENSUS_ACTION_TYPES.has(actionType)) {
      throw new Error("actionType must be one of: propose, finalize, execute");
    }

    const proposalId = toUintString(payload?.proposalId, "proposalId");
    const to = String(payload?.to || "").toLowerCase();
    const data = String(payload?.data || "");
    const value = toUintString(payload?.value ?? "0", "value");
    if (!/^0x[a-fA-F0-9]{40}$/.test(to)) throw new Error("to must be a valid EVM address");
    if (!/^0x[a-fA-F0-9]*$/.test(data)) throw new Error("data must be hex calldata");
    this._validateConsensusActionForAgent(agent, actionType, proposalId, to, data);

    const threshold = Number(this.config.consensusThresholds[actionType] || 0);
    if (threshold < 1) throw new Error("invalid consensus threshold");

    const key = this._consensusKey(actionType, proposalId, to, value, data);
    const now = nowIso();
    const current = this.db.consensusActions[key] || {
      id: key,
      actionType,
      proposalId,
      to,
      value,
      data,
      threshold,
      attestors: {},
      createdAt: now,
      updatedAt: now,
      executedAt: null,
      txHash: null
    };

    if (
      current.actionType !== actionType
      || current.proposalId !== proposalId
      || current.to !== to
      || current.value !== value
      || current.data !== data
    ) {
      throw new Error("consensus action payload mismatch");
    }

    current.threshold = threshold;
    current.attestors[agentId] = now;
    current.updatedAt = now;

    if (!current.executedAt && Object.keys(current.attestors).length >= threshold) {
      const txHash = sendManagedTx(
        this.config.consensusExecutorRpcUrl,
        this.config.consensusExecutorPrivateKey,
        current.to,
        current.data,
        current.value
      );
      current.executedAt = nowIso();
      current.txHash = txHash;
    }

    this.db.consensusActions[key] = current;
    this.save();
    return this._viewConsensusAction(current);
  }

  removeAgent(id) {
    const agent = this.db.agents[id];
    if (!agent) throw new Error("agent not found");

    this.stopAgent(id);

    delete this.db.agents[id];
    this.save();

    const instanceDir = makeInstancePaths(this.config, id).dir;
    rmSync(instanceDir, { recursive: true, force: true });

    return { id, removed: true };
  }

  startAgent(id) {
    const agent = this.db.agents[id];
    if (!agent) throw new Error("agent not found");

    if (this.processes.has(id)) {
      return this._view(agent);
    }

    mkdirSync(dirname(agent.stdoutPath), { recursive: true, mode: 0o700 });
    const stdout = createWriteStream(agent.stdoutPath, { flags: "a", mode: 0o600 });
    const stderr = createWriteStream(agent.stderrPath, { flags: "a", mode: 0o600 });

    const decryptedEnv = decryptEnvSecrets(agent.env, this.config.encryptionKey);
    const effectiveEnv = enforcePermissionEnv(agent.permissionLevel, decryptedEnv);

    const env = {
      ...process.env,
      ...effectiveEnv,
      GOV_AGENT_POLICY_PATH: agent.policyPath,
      GOV_AGENT_STATE_PATH: agent.statePath
    };

    const runtimeId = randomUUID();
    const child = spawn("node", [RUNNER_PATH], {
      cwd: ROOT_DIR,
      env,
      stdio: ["ignore", "pipe", "pipe"]
    });

    child.stdout.pipe(stdout);
    child.stderr.pipe(stderr);

    if (agent.permissionLevel === PERMISSION_CANDIDATE) {
      agent.candidateStats = agent.candidateStats || {
        phaseStartedAt: nowIso(),
        uptimeSeconds: 0,
        crashCount: 0,
        currentStartAt: null
      };
      agent.candidateStats.currentStartAt = nowIso();
    }

    child.on("exit", (code, signal) => {
      const current = this.processes.get(id);
      if (!current || current.runtimeId !== runtimeId) {
        stdout.end();
        stderr.end();
        return;
      }

      agent.lastExitCode = code;
      agent.lastExitSignal = signal;
      agent.updatedAt = nowIso();

      if (agent.permissionLevel === PERMISSION_CANDIDATE && agent.candidateStats) {
        if (typeof agent.candidateStats.currentStartAt === "string") {
          const startedMs = Date.parse(agent.candidateStats.currentStartAt);
          if (!Number.isNaN(startedMs)) {
            const deltaSeconds = Math.max(0, Math.floor((Date.now() - startedMs) / 1000));
            agent.candidateStats.uptimeSeconds = Number(agent.candidateStats.uptimeSeconds || 0) + deltaSeconds;
          }
        }
        agent.candidateStats.currentStartAt = null;
        if (code !== 0 || signal !== null) {
          agent.candidateStats.crashCount = Number(agent.candidateStats.crashCount || 0) + 1;
        }
      }

      this.save();

      this.processes.delete(id);
      stdout.end();
      stderr.end();
      log("warn", "agent process exited", { id, code, signal });

      if (agent.autostart) {
        setTimeout(() => {
          try {
            if (!this.processes.has(id) && this.db.agents[id]) {
              this.startAgent(id);
            }
          } catch (error) {
            log("error", "agent auto-restart failed", { id, error: String(error.message || error) });
          }
        }, 3000);
      }
    });

    this.processes.set(id, { child, startedAt: nowIso(), runtimeId });
    agent.updatedAt = nowIso();
    this.save();

    log("info", "agent started", { id, pid: child.pid });
    return this._view(agent);
  }

  stopAgent(id) {
    const runtime = this.processes.get(id);
    if (!runtime) return;

    runtime.child.kill("SIGTERM");
    setTimeout(() => {
      const current = this.processes.get(id);
      if (current && current.runtimeId === runtime.runtimeId) {
        runtime.child.kill("SIGKILL");
      }
    }, 8000);
    log("info", "agent stop requested", { id });
  }

  restartAgent(id) {
    const runtime = this.processes.get(id);
    if (runtime) {
      runtime.child.kill("SIGTERM");
      setTimeout(() => {
        const current = this.processes.get(id);
        if (current && current.runtimeId === runtime.runtimeId) {
          runtime.child.kill("SIGKILL");
        }
      }, 8000);
      this.processes.delete(id);
    }
    return this.startAgent(id);
  }

  startAutostartAgents() {
    for (const agent of Object.values(this.db.agents)) {
      if (agent.autostart) {
        try {
          this.startAgent(agent.id);
        } catch (error) {
          log("error", "failed to autostart agent", { id: agent.id, error: String(error.message || error) });
        }
      }
    }
  }

  _view(agent) {
    const runtime = this.processes.get(agent.id);
    const metrics = this._readStateMetrics(agent);
    const observed = this._candidateObserved(agent);
    const estimatedCycles = this._estimatedCandidateCycles(agent);
    const promotionEligible =
      agent.permissionLevel === PERMISSION_CANDIDATE
      && estimatedCycles >= this.config.minSuccessCyclesForPromotion
      && observed.uptimeSeconds >= this.config.minCandidateUptimeSeconds
      && observed.crashCount <= this.config.maxCandidateCrashCount;
    return {
      id: agent.id,
      createdAt: agent.createdAt,
      updatedAt: agent.updatedAt,
      autostart: agent.autostart,
      permissionLevel: agent.permissionLevel,
      promotionEligible,
      running: Boolean(runtime),
      pid: runtime?.child?.pid || null,
      startedAt: runtime?.startedAt || null,
      policyPath: agent.policyPath,
      statePath: agent.statePath,
      stdoutPath: agent.stdoutPath,
      stderrPath: agent.stderrPath,
      lastExitCode: agent.lastExitCode,
      lastExitSignal: agent.lastExitSignal,
      metrics,
      candidateObserved: observed,
      estimatedCandidateCycles: estimatedCycles,
      env: {
        GOV_AGENT_RPC_URL: agent.env.GOV_AGENT_RPC_URL,
        GOV_AGENT_ORACLE_ADAPTER: agent.env.GOV_AGENT_ORACLE_ADAPTER,
        GOV_AGENT_STAKE_MANAGER: agent.env.GOV_AGENT_STAKE_MANAGER,
        GOV_AGENT_PARAMETER_MANAGER: agent.env.GOV_AGENT_PARAMETER_MANAGER,
        GOV_AGENT_EXECUTOR: agent.env.GOV_AGENT_EXECUTOR,
        GOV_AGENT_DRY_RUN: agent.permissionLevel === PERMISSION_CANDIDATE ? "1" : "0"
      }
    };
  }
}

function requireAuth(req, token) {
  if (!token) return false;
  const provided = extractBearerToken(req.headers.authorization);
  return tokenEquals(provided, token);
}

async function main() {
  const config = buildManagerConfig();
  const manager = new AgentManager(config);
  const authFailures = new Map();

  manager.startAutostartAgents();

  const server = createServer(async (req, res) => {
    const remoteAddress = req.socket?.remoteAddress || "unknown";
    const origin = typeof req.headers.origin === "string" ? req.headers.origin : "";
    const corsHeaders = corsHeadersForOrigin(origin, config.allowedOrigins);
    const respond = (code, payload, headers = {}) => jsonResponse(res, code, payload, { ...corsHeaders, ...headers });
    const url = new URL(req.url || "/", `http://${req.headers.host || "localhost"}`);
    const path = url.pathname;
    const isConsensusAttest = req.method === "POST" && path === "/consensus/attest";

    if (!config.allowRemote && !isLoopbackAddress(remoteAddress)) {
      respond(403, { error: "forbidden_remote_address" });
      return;
    }

    if (req.method === "OPTIONS") {
      if (Object.keys(corsHeaders).length === 0) {
        respond(403, { error: "cors_origin_not_allowed" });
        return;
      }
      res.writeHead(204, corsHeaders);
      res.end("");
      return;
    }

    const nowMs = Date.now();
    const state = authFailures.get(remoteAddress);
    if (state && state.blockedUntilMs > nowMs) {
      respond(429, { error: "too_many_auth_failures" });
      return;
    }

    const registerAuthFailure = () => {
      const existing = authFailures.get(remoteAddress) || {
        windowStartMs: nowMs,
        failures: 0,
        blockedUntilMs: 0
      };
      if (nowMs - existing.windowStartMs > config.authWindowSeconds * 1000) {
        existing.windowStartMs = nowMs;
        existing.failures = 0;
        existing.blockedUntilMs = 0;
      }
      existing.failures += 1;
      if (existing.failures >= config.authMaxFailures) {
        existing.blockedUntilMs = nowMs + config.authBlockSeconds * 1000;
      }
      authFailures.set(remoteAddress, existing);
      return existing.blockedUntilMs > nowMs ? 429 : 401;
    };

    if (isConsensusAttest) {
      try {
        const body = await parseBody(req);
        const provided = extractBearerToken(req.headers.authorization);
        if (!manager.verifyConsensusAttestor(body?.agentId, provided)) {
          respond(registerAuthFailure(), { error: "unauthorized" });
          return;
        }
        authFailures.delete(remoteAddress);
        const action = manager.recordConsensusAttestation(body);
        respond(200, { action });
      } catch (error) {
        respond(400, { error: String(error.message || error) });
      }
      return;
    }

    if (!requireAuth(req, config.token)) {
      respond(registerAuthFailure(), { error: "unauthorized" });
      return;
    }
    authFailures.delete(remoteAddress);

    try {
      if (req.method === "GET" && path === "/health") {
        respond(200, {
          ok: true,
          time: nowIso(),
          count: manager.listAgents().length,
          minSuccessCyclesForPromotion: config.minSuccessCyclesForPromotion,
          minCandidateUptimeSeconds: config.minCandidateUptimeSeconds,
          maxCandidateCrashCount: config.maxCandidateCrashCount
        });
        return;
      }

      if (req.method === "GET" && path === "/agents") {
        respond(200, { agents: manager.listAgents() });
        return;
      }

      if (req.method === "GET" && path === "/consensus/actions") {
        respond(200, { actions: manager.listConsensusActions() });
        return;
      }

      if (req.method === "POST" && path === "/agents") {
        const body = await parseBody(req);
        const created = manager.addAgent(body);
        respond(201, { agent: created });
        return;
      }

      const match = path.match(/^\/agents\/([a-zA-Z0-9_-]{1,64})(?:\/(start|stop|restart|promote))?$/);
      if (match) {
        const id = match[1];
        const action = match[2] || "";

        if (req.method === "GET" && action === "") {
          const agent = manager.getAgent(id);
          if (!agent) {
            respond(404, { error: "agent not found" });
            return;
          }
          respond(200, { agent });
          return;
        }

        if (req.method === "PATCH" && action === "") {
          const body = await parseBody(req);
          const updated = manager.updateAgent(id, body);
          respond(200, { agent: updated });
          return;
        }

        if (req.method === "DELETE" && action === "") {
          const removed = manager.removeAgent(id);
          respond(200, removed);
          return;
        }

        if (req.method === "POST" && action === "start") {
          const view = manager.startAgent(id);
          respond(200, { agent: view });
          return;
        }

        if (req.method === "POST" && action === "stop") {
          manager.stopAgent(id);
          respond(200, { id, stopped: true });
          return;
        }

        if (req.method === "POST" && action === "restart") {
          const view = manager.restartAgent(id);
          respond(200, { agent: view });
          return;
        }

        if (req.method === "POST" && action === "promote") {
          const view = manager.promoteAgent(id);
          respond(200, { agent: view });
          return;
        }
      }

      respond(404, { error: "not found" });
    } catch (error) {
      respond(400, { error: String(error.message || error) });
    }
  });

  server.listen(config.port, config.host, () => {
    log("info", "manager API listening", {
      host: config.host,
      port: config.port,
      allowRemote: config.allowRemote,
      allowedOrigins: config.allowedOrigins,
      tokenRequired: Boolean(config.token),
      dbPath: config.dbPath,
      minSuccessCyclesForPromotion: config.minSuccessCyclesForPromotion,
      minCandidateUptimeSeconds: config.minCandidateUptimeSeconds,
      maxCandidateCrashCount: config.maxCandidateCrashCount,
      consensusEnabled: config.consensusEnabled,
      consensusThresholds: config.consensusThresholds,
      authWindowSeconds: config.authWindowSeconds,
      authMaxFailures: config.authMaxFailures,
      authBlockSeconds: config.authBlockSeconds
    });
  });
}

main().catch((error) => {
  log("fatal", String(error.message || error));
  process.exit(1);
});
