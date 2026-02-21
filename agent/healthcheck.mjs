#!/usr/bin/env node

import { existsSync, readFileSync } from "node:fs";

function fail(message) {
  console.error(message);
  process.exit(1);
}

const statePath = process.env.GOV_AGENT_STATE_PATH || "./agent/state/agent-state.json";
const maxAgeSeconds = Number(process.env.GOV_AGENT_HEALTH_MAX_AGE_SECONDS || 180);

if (!existsSync(statePath)) {
  fail(`state file does not exist: ${statePath}`);
}

let state;
try {
  state = JSON.parse(readFileSync(statePath, "utf8"));
} catch (error) {
  fail(`failed to parse state file: ${String(error.message || error)}`);
}

const heartbeat = state?.lastHeartbeatAt;
if (typeof heartbeat !== "string" || heartbeat.length === 0) {
  fail("state file missing lastHeartbeatAt");
}

const heartbeatMs = Date.parse(heartbeat);
if (Number.isNaN(heartbeatMs)) {
  fail("invalid heartbeat timestamp in state file");
}

const ageSeconds = Math.floor((Date.now() - heartbeatMs) / 1000);
if (ageSeconds > maxAgeSeconds) {
  fail(`agent heartbeat too old: ${ageSeconds}s > ${maxAgeSeconds}s`);
}

console.log(`ok heartbeat_age_seconds=${ageSeconds}`);
