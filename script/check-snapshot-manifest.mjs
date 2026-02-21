#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

function fail(message) {
  console.error(`[fail] ${message}`);
  process.exit(1);
}

function normalizeAddress(value) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  if (!/^0x[a-fA-F0-9]{40}$/.test(trimmed)) return "";
  return trimmed.toLowerCase();
}

function normalizeBytes32(value) {
  if (typeof value !== "string") return "";
  const trimmed = value.trim();
  if (!/^0x[a-fA-F0-9]{64}$/.test(trimmed)) return "";
  return trimmed.toLowerCase();
}

function runCast(args) {
  try {
    return execFileSync("cast", args, { encoding: "utf8" }).trim();
  } catch (error) {
    const stderr = error && typeof error.stderr === "string" ? error.stderr.trim() : "";
    const stdout = error && typeof error.stdout === "string" ? error.stdout.trim() : "";
    throw new Error(`cast ${args.join(" ")} failed: ${stderr || stdout || String(error)}`);
  }
}

function castCall(rpcUrl, target, signature, args = []) {
  return runCast(["call", target, signature, ...args.map((v) => String(v)), "--rpc-url", rpcUrl]).trim();
}

function castUintCall(rpcUrl, target, signature) {
  const raw = castCall(rpcUrl, target, signature);
  try {
    return BigInt(raw);
  } catch {
    throw new Error(`unable to parse uint from call ${signature}: ${raw}`);
  }
}

function castAddressCall(rpcUrl, target, signature) {
  const raw = castCall(rpcUrl, target, signature);
  const addr = normalizeAddress(raw);
  if (!addr) throw new Error(`unable to parse address from call ${signature}: ${raw}`);
  return addr;
}

function castBytes32Call(rpcUrl, target, signature) {
  const raw = castCall(rpcUrl, target, signature);
  const value = normalizeBytes32(raw);
  if (!value) throw new Error(`unable to parse bytes32 from call ${signature}: ${raw}`);
  return value;
}

function expectEq(checks, label, got, expected) {
  const ok = got === expected;
  checks.push({ ok, label, got, expected });
}

function requiredPath(obj, path) {
  let cur = obj;
  for (const part of path) {
    if (!cur || typeof cur !== "object" || !(part in cur)) {
      throw new Error(`missing required field: ${path.join(".")}`);
    }
    cur = cur[part];
  }
  return cur;
}

function parseArgs(argv) {
  let manifestPath = "snapshot/governance.manifest.json";
  let rpcUrl = process.env.RPC_URL || process.env.GOV_AGENT_RPC_URL || "";

  const args = [...argv];
  while (args.length > 0) {
    const arg = args.shift();
    if (!arg) continue;
    if (arg === "--rpc-url") {
      const value = args.shift();
      if (!value) fail("missing value for --rpc-url");
      rpcUrl = value;
      continue;
    }
    if (arg.startsWith("--rpc-url=")) {
      rpcUrl = arg.slice("--rpc-url=".length);
      continue;
    }
    if (arg.startsWith("-")) {
      fail(`unknown flag: ${arg}`);
    }
    manifestPath = arg;
  }

  return { manifestPath, rpcUrl };
}

function readManifest(path) {
  const absolute = resolve(process.cwd(), path);
  if (!existsSync(absolute)) fail(`manifest file not found: ${absolute}`);

  let manifest;
  try {
    manifest = JSON.parse(readFileSync(absolute, "utf8"));
  } catch (error) {
    fail(`failed to parse manifest JSON: ${String(error.message || error)}`);
  }

  return { manifest, absolute };
}

function validateLocalManifest(manifest) {
  requiredPath(manifest, ["version"]);
  requiredPath(manifest, ["chainId"]);
  requiredPath(manifest, ["snapshot", "space"]);
  requiredPath(manifest, ["snapshot", "spaceHash"]);
  requiredPath(manifest, ["snapshot", "configHash"]);
  requiredPath(manifest, ["snapshot", "strategy", "name"]);
  requiredPath(manifest, ["snapshot", "strategy", "contract"]);
  requiredPath(manifest, ["snapshot", "strategy", "method"]);
  requiredPath(manifest, ["snapshot", "strategy", "quorumMethod"]);
  requiredPath(manifest, ["snapshot", "strategy", "argsTemplate"]);
  requiredPath(manifest, ["snapshot", "proposalValidation", "pluginKey"]);
  requiredPath(manifest, ["snapshot", "proposalValidation", "requiredFields"]);
  requiredPath(manifest, ["contracts", "parameterManager"]);
  requiredPath(manifest, ["contracts", "stakeManager"]);
  requiredPath(manifest, ["contracts", "oracleAdapter"]);
  requiredPath(manifest, ["contracts", "governanceExecutor"]);
  requiredPath(manifest, ["governance", "proposalThresholdBps"]);
  requiredPath(manifest, ["governance", "quorumBps"]);
  requiredPath(manifest, ["governance", "majorityBps"]);
  requiredPath(manifest, ["governance", "superMajorityBps"]);
  requiredPath(manifest, ["governance", "slashingQuorumBps"]);
  requiredPath(manifest, ["governance", "maxSlashingBps"]);
  requiredPath(manifest, ["governance", "oracleChallengeWindow"]);
  requiredPath(manifest, ["governance", "timelockDuration"]);
  requiredPath(manifest, ["governance", "slashingExecutionCooldown"]);
  requiredPath(manifest, ["governance", "proposalBond"]);
  requiredPath(manifest, ["oracle", "attesterThreshold"]);
  requiredPath(manifest, ["oracle", "fallbackFinalizationDelay"]);

  if (manifest.version !== 1) {
    fail(`manifest version must be 1, got ${String(manifest.version)}`);
  }
  if (!Number.isInteger(manifest.chainId) || manifest.chainId <= 0) {
    fail(`chainId must be a positive integer, got ${String(manifest.chainId)}`);
  }

  const strategy = manifest.snapshot.strategy;
  if (strategy.name !== "contract-call") fail("snapshot.strategy.name must be 'contract-call'");
  if (strategy.method !== "votingPowerAt(address,uint256)") {
    fail("snapshot.strategy.method must be votingPowerAt(address,uint256)");
  }
  if (strategy.quorumMethod !== "totalStakedAt(uint256)") {
    fail("snapshot.strategy.quorumMethod must be totalStakedAt(uint256)");
  }

  if (!Array.isArray(strategy.argsTemplate) || strategy.argsTemplate.length !== 2) {
    fail("snapshot.strategy.argsTemplate must have exactly two items");
  }
  const args = strategy.argsTemplate.map((x) => String(x));
  if (args[0] !== "{address}" || args[1] !== "{snapshot}") {
    fail("snapshot.strategy.argsTemplate must be ['{address}','{snapshot}']");
  }

  const requiredPluginFields = new Set(
    (manifest.snapshot.proposalValidation.requiredFields || []).map((x) => String(x))
  );
  for (const field of ["proposalId", "salt", "transactions", "executionHash"]) {
    if (!requiredPluginFields.has(field)) {
      fail(`snapshot.proposalValidation.requiredFields missing '${field}'`);
    }
  }

  const addresses = {
    parameterManager: normalizeAddress(manifest.contracts.parameterManager),
    stakeManager: normalizeAddress(manifest.contracts.stakeManager),
    oracleAdapter: normalizeAddress(manifest.contracts.oracleAdapter),
    governanceExecutor: normalizeAddress(manifest.contracts.governanceExecutor),
    strategyContract: normalizeAddress(manifest.snapshot.strategy.contract)
  };
  for (const [name, value] of Object.entries(addresses)) {
    if (!value) fail(`invalid address for ${name}`);
  }

  const spaceHash = normalizeBytes32(manifest.snapshot.spaceHash);
  if (!spaceHash) fail("invalid snapshot.spaceHash");
  const configHash = normalizeBytes32(manifest.snapshot.configHash);
  if (!configHash) fail("invalid snapshot.configHash");

  return {
    addresses,
    space: String(manifest.snapshot.space),
    spaceHash,
    configHash,
    governance: manifest.governance,
    oracle: manifest.oracle,
    snapshot: manifest.snapshot
  };
}

function computeManifestConfigHash(snapshot) {
  const strategy = snapshot.strategy;
  const proposalValidation = snapshot.proposalValidation;
  const fieldDigest = runCast(["keccak", (proposalValidation.requiredFields || []).map((x) => String(x)).join(",")]);
  const encoded = runCast([
    "abi-encode",
    "f(bytes32,address,bytes32,bytes32,bytes32,bytes32)",
    String(snapshot.spaceHash),
    String(strategy.contract),
    runCast(["keccak", String(strategy.method)]),
    runCast(["keccak", String(strategy.quorumMethod)]),
    runCast(["keccak", String(proposalValidation.pluginKey)]),
    fieldDigest
  ]);
  const digest = normalizeBytes32(runCast(["keccak", encoded]));
  if (!digest) fail("failed to compute manifest config hash");
  return digest;
}

function localChecks(manifest, local) {
  const checks = [];

  const computedSpaceHash = normalizeBytes32(runCast(["keccak", local.space]));
  if (!computedSpaceHash) fail("failed to compute keccak for snapshot.space");
  expectEq(checks, "snapshot.spaceHash == keccak(snapshot.space)", local.spaceHash, computedSpaceHash);

  expectEq(
    checks,
    "snapshot.strategy.contract == contracts.stakeManager",
    local.addresses.strategyContract,
    local.addresses.stakeManager
  );
  const computedConfigHash = computeManifestConfigHash(local.snapshot);
  expectEq(checks, "snapshot.configHash == hash(manifest snapshot config)", local.configHash, computedConfigHash);

  return checks;
}

function onchainChecks(rpcUrl, manifest, local) {
  const checks = [];
  const contracts = local.addresses;

  const chainId = Number(runCast(["chain-id", "--rpc-url", rpcUrl]));
  expectEq(checks, "chainId (manifest vs RPC)", String(manifest.chainId), String(chainId));

  const pmSpaceHash = castBytes32Call(rpcUrl, contracts.parameterManager, "snapshotSpaceHash()(bytes32)");
  expectEq(checks, "ParameterManager.snapshotSpaceHash()", pmSpaceHash, local.spaceHash);
  const pmConfigHash = castBytes32Call(rpcUrl, contracts.parameterManager, "snapshotConfigHash()(bytes32)");
  expectEq(checks, "ParameterManager.snapshotConfigHash()", pmConfigHash, local.configHash);

  const pmExecutor = castAddressCall(rpcUrl, contracts.parameterManager, "governanceExecutor()(address)");
  expectEq(checks, "ParameterManager.governanceExecutor()", pmExecutor, contracts.governanceExecutor);

  const smParams = castAddressCall(rpcUrl, contracts.stakeManager, "parameterManager()(address)");
  expectEq(checks, "StakeManager.parameterManager()", smParams, contracts.parameterManager);
  const smOracle = castAddressCall(rpcUrl, contracts.stakeManager, "oracleAdapter()(address)");
  expectEq(checks, "StakeManager.oracleAdapter()", smOracle, contracts.oracleAdapter);
  const smExecutor = castAddressCall(rpcUrl, contracts.stakeManager, "governanceExecutor()(address)");
  expectEq(checks, "StakeManager.governanceExecutor()", smExecutor, contracts.governanceExecutor);

  const oaStake = castAddressCall(rpcUrl, contracts.oracleAdapter, "stakeManager()(address)");
  expectEq(checks, "OracleAdapter.stakeManager()", oaStake, contracts.stakeManager);
  const oaParams = castAddressCall(rpcUrl, contracts.oracleAdapter, "parameterManager()(address)");
  expectEq(checks, "OracleAdapter.parameterManager()", oaParams, contracts.parameterManager);

  const geOracle = castAddressCall(rpcUrl, contracts.governanceExecutor, "oracleAdapter()(address)");
  expectEq(checks, "GovernanceExecutor.oracleAdapter()", geOracle, contracts.oracleAdapter);
  const geParams = castAddressCall(rpcUrl, contracts.governanceExecutor, "parameterManager()(address)");
  expectEq(checks, "GovernanceExecutor.parameterManager()", geParams, contracts.parameterManager);

  const g = manifest.governance;
  expectEq(
    checks,
    "ParameterManager.proposalThresholdBps()",
    castUintCall(rpcUrl, contracts.parameterManager, "proposalThresholdBps()(uint16)").toString(),
    String(g.proposalThresholdBps)
  );
  expectEq(
    checks,
    "ParameterManager.quorumBps()",
    castUintCall(rpcUrl, contracts.parameterManager, "quorumBps()(uint16)").toString(),
    String(g.quorumBps)
  );
  expectEq(
    checks,
    "ParameterManager.majorityBps()",
    castUintCall(rpcUrl, contracts.parameterManager, "majorityBps()(uint16)").toString(),
    String(g.majorityBps)
  );
  expectEq(
    checks,
    "ParameterManager.superMajorityBps()",
    castUintCall(rpcUrl, contracts.parameterManager, "superMajorityBps()(uint16)").toString(),
    String(g.superMajorityBps)
  );
  expectEq(
    checks,
    "ParameterManager.slashingQuorumBps()",
    castUintCall(rpcUrl, contracts.parameterManager, "slashingQuorumBps()(uint16)").toString(),
    String(g.slashingQuorumBps)
  );
  expectEq(
    checks,
    "ParameterManager.maxSlashingBps()",
    castUintCall(rpcUrl, contracts.parameterManager, "maxSlashingBps()(uint16)").toString(),
    String(g.maxSlashingBps)
  );
  expectEq(
    checks,
    "ParameterManager.oracleChallengeWindow()",
    castUintCall(rpcUrl, contracts.parameterManager, "oracleChallengeWindow()(uint64)").toString(),
    String(g.oracleChallengeWindow)
  );
  expectEq(
    checks,
    "ParameterManager.timelockDuration()",
    castUintCall(rpcUrl, contracts.parameterManager, "timelockDuration()(uint64)").toString(),
    String(g.timelockDuration)
  );
  expectEq(
    checks,
    "ParameterManager.slashingExecutionCooldown()",
    castUintCall(rpcUrl, contracts.parameterManager, "slashingExecutionCooldown()(uint64)").toString(),
    String(g.slashingExecutionCooldown)
  );
  expectEq(
    checks,
    "ParameterManager.proposalBond()",
    castUintCall(rpcUrl, contracts.parameterManager, "proposalBond()(uint256)").toString(),
    String(g.proposalBond)
  );

  const o = manifest.oracle;
  expectEq(
    checks,
    "OracleAdapter.attesterThreshold()",
    castUintCall(rpcUrl, contracts.oracleAdapter, "attesterThreshold()(uint8)").toString(),
    String(o.attesterThreshold)
  );
  expectEq(
    checks,
    "OracleAdapter.fallbackFinalizationDelay()",
    castUintCall(rpcUrl, contracts.oracleAdapter, "fallbackFinalizationDelay()(uint64)").toString(),
    String(o.fallbackFinalizationDelay)
  );

  return checks;
}

function printChecks(checks) {
  let failures = 0;
  for (const check of checks) {
    if (check.ok) {
      console.log(`[ok] ${check.label}`);
    } else {
      failures += 1;
      console.error(`[fail] ${check.label}`);
      console.error(`       expected: ${check.expected}`);
      console.error(`       got     : ${check.got}`);
    }
  }
  return failures;
}

function main() {
  const { manifestPath, rpcUrl } = parseArgs(process.argv.slice(2));
  const { manifest, absolute } = readManifest(manifestPath);
  const local = validateLocalManifest(manifest);

  console.log(`[info] loaded manifest: ${absolute}`);
  const localResults = localChecks(manifest, local);
  let failures = printChecks(localResults);

  if (rpcUrl) {
    console.log(`[info] running on-chain checks via RPC: ${rpcUrl}`);
    const chainResults = onchainChecks(rpcUrl, manifest, local);
    failures += printChecks(chainResults);
  } else {
    console.log("[warn] --rpc-url not provided; skipping on-chain checks");
  }

  if (failures > 0) {
    console.error(`[result] FAILED with ${failures} check(s)`);
    process.exit(1);
  }
  console.log("[result] PASS");
}

main();
