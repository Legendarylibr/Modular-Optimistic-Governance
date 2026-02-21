#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

function fail(message) {
  console.error(`[fail] ${message}`);
  process.exit(1);
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

function normalizeAddress(value) {
  if (typeof value !== "string") return "";
  const v = value.trim();
  if (!/^0x[a-fA-F0-9]{40}$/.test(v)) return "";
  return v.toLowerCase();
}

function normalizeBytes32(value) {
  if (typeof value !== "string") return "";
  const v = value.trim();
  if (!/^0x[a-fA-F0-9]{64}$/.test(v)) return "";
  return v.toLowerCase();
}

function parseArgs(argv) {
  let manifestPath = "snapshot/governance.manifest.json";
  const args = [...argv];
  while (args.length > 0) {
    const arg = args.shift();
    if (!arg) continue;
    if (arg.startsWith("-")) fail(`unknown flag: ${arg}`);
    manifestPath = arg;
  }
  return { manifestPath };
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

function computeConfigHash(snapshot) {
  const spaceHash = normalizeBytes32(String(snapshot.spaceHash || ""));
  if (!spaceHash) fail("snapshot.spaceHash must be bytes32");
  const strategyContract = normalizeAddress(String(snapshot.strategy?.contract || ""));
  if (!strategyContract) fail("snapshot.strategy.contract must be an address");

  const requiredFields = Array.isArray(snapshot.proposalValidation?.requiredFields)
    ? snapshot.proposalValidation.requiredFields.map((x) => String(x))
    : [];
  if (requiredFields.length === 0) fail("snapshot.proposalValidation.requiredFields must be non-empty");

  const fieldDigest = runCast(["keccak", requiredFields.join(",")]);
  const encoded = runCast([
    "abi-encode",
    "f(bytes32,address,bytes32,bytes32,bytes32,bytes32)",
    spaceHash,
    strategyContract,
    runCast(["keccak", String(snapshot.strategy.method || "")]),
    runCast(["keccak", String(snapshot.strategy.quorumMethod || "")]),
    runCast(["keccak", String(snapshot.proposalValidation.pluginKey || "")]),
    fieldDigest
  ]);
  const digest = normalizeBytes32(runCast(["keccak", encoded]));
  if (!digest) fail("failed to compute digest");
  return digest;
}

function main() {
  const { manifestPath } = parseArgs(process.argv.slice(2));
  const { manifest, absolute } = readManifest(manifestPath);

  requiredPath(manifest, ["snapshot"]);
  requiredPath(manifest, ["contracts", "parameterManager"]);

  const parameterManager = normalizeAddress(String(manifest.contracts.parameterManager || ""));
  if (!parameterManager) fail("contracts.parameterManager must be an address");

  const computedConfigHash = computeConfigHash(manifest.snapshot);
  const manifestConfigHash = normalizeBytes32(String(manifest.snapshot.configHash || ""));
  if (!manifestConfigHash) fail("snapshot.configHash must be bytes32");
  if (manifestConfigHash !== computedConfigHash) {
    fail(
      `snapshot.configHash mismatch; manifest=${manifestConfigHash}, computed=${computedConfigHash}. `
      + "Update manifest first."
    );
  }

  const calldata = runCast(["calldata", "setSnapshotConfigHash(bytes32)", computedConfigHash]).trim();

  const tx = {
    target: parameterManager,
    value: "0",
    data: calldata
  };

  console.log(`[info] manifest: ${absolute}`);
  console.log(`[info] snapshot.configHash: ${computedConfigHash}`);
  console.log("[info] governance call:");
  console.log(`target: ${parameterManager}`);
  console.log("value : 0");
  console.log(`data  : ${calldata}`);
  console.log("[info] tx JSON for governance bundle:");
  console.log(JSON.stringify(tx, null, 2));
}

main();
