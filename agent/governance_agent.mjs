#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";

const ZERO_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000";
const BPS_DENOMINATOR = 10_000n;
const UINT128_MAX = (1n << 128n) - 1n;

function nowIso() {
  return new Date().toISOString();
}

function log(level, message, meta = undefined) {
  const base = `[${nowIso()}] [${level}] ${message}`;
  if (meta === undefined) {
    console.log(base);
    return;
  }
  console.log(`${base} ${JSON.stringify(meta)}`);
}

function fatal(message) {
  log("fatal", message);
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

function toUint(value, field) {
  try {
    const bigint = BigInt(String(value));
    if (bigint < 0n) throw new Error("negative value");
    return bigint;
  } catch {
    throw new Error(`invalid unsigned integer for ${field}`);
  }
}

function decimalToScaledBigInt(raw, decimals) {
  const text = String(raw).trim();
  if (text.length === 0) throw new Error("empty decimal");

  let normalized = text;
  if (/e/i.test(normalized)) {
    const asNumber = Number(normalized);
    if (!Number.isFinite(asNumber)) throw new Error("non-finite decimal");
    normalized = asNumber.toLocaleString("fullwide", { useGrouping: false, maximumFractionDigits: 24 });
  }

  const negative = normalized.startsWith("-");
  if (negative) throw new Error("negative decimal not supported");

  const [wholePart, fracPart = ""] = normalized.split(".");
  if (!/^\d+$/.test(wholePart) || !/^\d*$/.test(fracPart)) {
    throw new Error(`invalid decimal string: ${text}`);
  }

  const scale = 10n ** BigInt(decimals);
  const whole = BigInt(wholePart) * scale;

  if (fracPart.length === 0) return whole;

  const trimmedFrac = fracPart.slice(0, decimals).padEnd(decimals, "0");
  return whole + BigInt(trimmedFrac || "0");
}

function loadJson(path, fallback) {
  if (!existsSync(path)) return fallback;
  const raw = readFileSync(path, "utf8");
  return JSON.parse(raw);
}

function saveJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function rpc(url, method, params) {
  const body = { jsonrpc: "2.0", id: Date.now(), method, params };
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error(`rpc ${method} http ${response.status}`);

  const json = await response.json();
  if (json.error) {
    const message = json.error?.message || JSON.stringify(json.error);
    throw new Error(`rpc ${method} error: ${message}`);
  }
  return json.result;
}

async function ethCallHex(rpcUrl, to, data, from = undefined) {
  const tx = from ? { to, data, from } : { to, data };
  return rpc(rpcUrl, "eth_call", [tx, "latest"]);
}

function castCalldata(signature, args) {
  return runCast(["calldata", signature, ...args.map((arg) => String(arg))]);
}

function castAbiEncode(signature, args) {
  return runCast(["abi-encode", signature, ...args.map((arg) => String(arg))]);
}

function castAbiDecode(signature, hexData) {
  const out = runCast(["abi-decode", signature, hexData, "--json"]);
  return JSON.parse(out);
}

function castKeccak(data) {
  return runCast(["keccak", data]).toLowerCase();
}

function walletAddress(privateKey) {
  return runCast(["wallet", "address", "--private-key", privateKey]).trim().toLowerCase();
}

async function readSingle(rpcUrl, contract, callSig, decodeSig, args, from = undefined) {
  const data = castCalldata(callSig, args);
  const raw = await ethCallHex(rpcUrl, contract, data, from);
  const decoded = castAbiDecode(decodeSig, raw);
  return decoded[0];
}

function formatTxTupleArray(transactions) {
  return `[${transactions
    .map((tx) => `(${normalizeAddress(tx.target)},${toUint(tx.value, "tx.value")},${tx.data})`)
    .join(",")}]`;
}

function formatSnapshotResultTuple(result) {
  return `(${result.proposalId},${result.executionHash},${result.snapshotProposalHash},${result.snapshotSpaceHash},${result.snapshotConfigHash},${result.snapshotBlock},${result.forVotes},${result.againstVotes},${result.abstainVotes},${result.totalStakedAtSnapshot},${result.passed},${result.metadataHash})`;
}

async function sendTx(rpcUrl, privateKey, to, data, dryRun, reason) {
  if (dryRun) {
    log("dry-run", `skip tx: ${reason}`, { to, data });
    return { txHash: null, dryRun: true };
  }

  const args = [
    "send",
    to,
    "--data",
    data,
    "--private-key",
    privateKey,
    "--rpc-url",
    rpcUrl,
    "--async"
  ];

  const out = runCast(args);
  const match = out.match(/0x[a-fA-F0-9]{64}/);
  if (!match) throw new Error(`could not parse tx hash from cast output: ${out}`);

  return { txHash: match[0].toLowerCase(), dryRun: false };
}

function parseConsensusActions(raw) {
  const source = String(raw || "propose,finalize,execute");
  const set = new Set(
    source
      .split(",")
      .map((x) => x.trim().toLowerCase())
      .filter((x) => x.length > 0)
  );
  return set;
}

function shouldUseConsensus(config, actionType) {
  return Boolean(config.consensus.enabled && config.consensus.actions.has(actionType));
}

async function attestConsensusAction(config, actionType, proposalId, to, data, value = "0") {
  const body = {
    agentId: config.consensus.agentId,
    actionType,
    proposalId: String(proposalId),
    to,
    data,
    value: String(value)
  };

  const response = await fetch(`${config.consensus.managerUrl}/consensus/attest`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${config.consensus.agentToken}`
    },
    body: JSON.stringify(body)
  });

  if (!response.ok) {
    const text = await response.text();
    throw new Error(`consensus attestation failed http=${response.status} body=${text}`);
  }

  const payload = await response.json();
  return payload?.action || null;
}

async function canCall(rpcUrl, from, to, data) {
  try {
    await ethCallHex(rpcUrl, to, data, from);
    return true;
  } catch {
    return false;
  }
}

async function fetchSnapshotClosedProposals(graphqlUrl, space, first) {
  const query = `
    query Proposals($space: String!, $first: Int!) {
      proposals(
        first: $first,
        skip: 0,
        where: { space_in: [$space], state: "closed" }
        orderBy: "end"
        orderDirection: desc
      ) {
        id
        title
        end
        snapshot
        choices
        scores
        scores_total
        quorum
        plugins
        space { id }
      }
    }
  `;

  const response = await fetch(graphqlUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query, variables: { space, first } })
  });

  if (!response.ok) throw new Error(`snapshot graphql http ${response.status}`);
  const body = await response.json();
  if (body.errors && body.errors.length > 0) {
    throw new Error(`snapshot graphql error: ${body.errors[0].message}`);
  }

  const proposals = body?.data?.proposals;
  if (!Array.isArray(proposals)) return [];
  return proposals;
}

function parseOnchainPayload(snapshotProposal, pluginKey) {
  const plugins = snapshotProposal?.plugins;
  if (!plugins || typeof plugins !== "object") return null;

  const payload = plugins[pluginKey];
  if (!payload || typeof payload !== "object") return null;

  const proposalId = toUint(payload.proposalId, "plugin.proposalId");
  const salt = normalizeBytes32(payload.salt);
  if (!salt) throw new Error("plugin.salt must be bytes32");

  if (!Array.isArray(payload.transactions) || payload.transactions.length === 0) {
    throw new Error("plugin.transactions must be a non-empty array");
  }

  const transactions = payload.transactions.map((tx, index) => {
    const target = normalizeAddress(tx.target);
    if (!target) throw new Error(`plugin.transactions[${index}].target invalid address`);

    const value = toUint(tx.value ?? "0", `plugin.transactions[${index}].value`);
    const data = typeof tx.data === "string" ? tx.data.trim() : "";
    if (!/^0x[a-fA-F0-9]*$/.test(data)) {
      throw new Error(`plugin.transactions[${index}].data invalid hex`);
    }

    return { target, value, data };
  });

  const executionHash = normalizeBytes32(payload.executionHash || "");

  return { proposalId, salt, transactions, executionHash };
}

function buildChallengeEvidence(snapshotProposalId, expectedResultHash, submittedHash) {
  const text = `snapshot:${snapshotProposalId}|expected:${expectedResultHash}|submitted:${submittedHash}`;
  return castKeccak(text);
}

async function buildContext(config) {
  const agentAddress = walletAddress(config.privateKey);

  const snapshotSpaceHash = String(
    await readSingle(
      config.rpcUrl,
      config.parameterManager,
      "snapshotSpaceHash()",
      "f()(bytes32)",
      [],
      agentAddress
    )
  ).toLowerCase();
  const snapshotConfigHash = String(
    await readSingle(
      config.rpcUrl,
      config.parameterManager,
      "snapshotConfigHash()",
      "f()(bytes32)",
      [],
      agentAddress
    )
  ).toLowerCase();

  const isAttester = Boolean(
    await readSingle(
      config.rpcUrl,
      config.oracleAdapter,
      "isAttester(address)",
      "f()(bool)",
      [agentAddress],
      agentAddress
    )
  );

  return { agentAddress, snapshotSpaceHash, snapshotConfigHash, isAttester };
}

async function readProposal(config, proposalId, from) {
  const tuple = await readSingle(
    config.rpcUrl,
    config.stakeManager,
    "getProposal(uint256)",
    "f()((address,bytes32,uint64,uint64,uint64,uint8,address,uint16,bool))",
    [proposalId],
    from
  );

  return {
    proposer: String(tuple[0]).toLowerCase(),
    executionHash: String(tuple[1]).toLowerCase(),
    voteStart: toUint(tuple[2], "proposal.voteStart"),
    voteEnd: toUint(tuple[3], "proposal.voteEnd"),
    snapshotBlock: toUint(tuple[4], "proposal.snapshotBlock"),
    proposalType: Number(tuple[5]),
    accused: String(tuple[6]).toLowerCase(),
    maxSlashBps: Number(tuple[7]),
    exists: Boolean(tuple[8])
  };
}

async function readSettlement(config, proposalId, from) {
  const tuple = await readSingle(
    config.rpcUrl,
    config.oracleAdapter,
    "getSettlement(uint256)",
    "f()((bytes32,bytes32,bool,bool,bool,uint32,uint64,uint64,uint8))",
    [proposalId],
    from
  );

  return {
    submittedHash: String(tuple[0]).toLowerCase(),
    executionHash: String(tuple[1]).toLowerCase(),
    passed: Boolean(tuple[2]),
    challenged: Boolean(tuple[3]),
    finalized: Boolean(tuple[4]),
    attestationCount: Number(tuple[5]),
    proposedAt: toUint(tuple[6], "settlement.proposedAt"),
    finalizedAt: toUint(tuple[7], "settlement.finalizedAt"),
    proposalType: Number(tuple[8])
  };
}

async function readParams(config, from) {
  const [quorumBps, majorityBps, superMajorityBps, slashingQuorumBps, challengeWindow] = await Promise.all([
    readSingle(config.rpcUrl, config.parameterManager, "quorumBps()", "f()(uint16)", [], from),
    readSingle(config.rpcUrl, config.parameterManager, "majorityBps()", "f()(uint16)", [], from),
    readSingle(config.rpcUrl, config.parameterManager, "superMajorityBps()", "f()(uint16)", [], from),
    readSingle(config.rpcUrl, config.parameterManager, "slashingQuorumBps()", "f()(uint16)", [], from),
    readSingle(config.rpcUrl, config.parameterManager, "oracleChallengeWindow()", "f()(uint64)", [], from)
  ]);

  return {
    quorumBps: BigInt(quorumBps),
    majorityBps: BigInt(majorityBps),
    superMajorityBps: BigInt(superMajorityBps),
    slashingQuorumBps: BigInt(slashingQuorumBps),
    challengeWindow: BigInt(challengeWindow)
  };
}

function computePassed(proposalType, tally, totalStakedAtSnapshot, params) {
  if (totalStakedAtSnapshot === 0n) return false;

  const quorumTarget = proposalType === 2 ? params.slashingQuorumBps : params.quorumBps;
  const majorityTarget = proposalType === 2 ? params.superMajorityBps : params.majorityBps;

  const votesCast = tally.forVotes + tally.againstVotes + tally.abstainVotes;
  if (votesCast * BPS_DENOMINATOR < totalStakedAtSnapshot * quorumTarget) return false;

  const decisive = tally.forVotes + tally.againstVotes;
  if (decisive === 0n) return false;

  return tally.forVotes * BPS_DENOMINATOR >= decisive * majorityTarget;
}

function parseScoreAt(scores, indexOneBased, decimals) {
  const idx = indexOneBased - 1;
  if (!Array.isArray(scores) || idx < 0 || idx >= scores.length) return 0n;
  return decimalToScaledBigInt(scores[idx], decimals);
}

async function requestAiAdvisory(config, advisoryInput) {
  if (!config.ai.enabled) return null;

  const systemPrompt = [
    "You are a DAO governance risk analyst.",
    "Hard constraints:",
    "1) You cannot authorize or execute transactions.",
    "2) You only provide advisory output.",
    "3) Deterministic rule checks remain authoritative.",
    "4) If uncertain, set risk_level=high and confidence<0.5.",
    "Output strict JSON only with keys:",
    "risk_level (low|medium|high), confidence (0..1), summary, reasons (string[]), flags (string[]), recommended_action (monitor|review|pause)."
  ].join(" ");

  const payload = {
    model: config.ai.model,
    temperature: 0,
    response_format: { type: "json_object" },
    messages: [
      { role: "system", content: systemPrompt },
      { role: "user", content: JSON.stringify(advisoryInput) }
    ]
  };

  const response = await fetch(config.ai.baseUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${config.ai.apiKey}`
    },
    body: JSON.stringify(payload)
  });
  if (!response.ok) throw new Error(`ai advisory http ${response.status}`);

  const body = await response.json();
  const content = body?.choices?.[0]?.message?.content;
  if (typeof content !== "string" || content.length === 0) throw new Error("ai advisory empty response");

  const parsed = JSON.parse(content);
  const riskLevel = typeof parsed.risk_level === "string" ? parsed.risk_level : "high";
  const confidenceRaw = Number(parsed.confidence);

  return {
    risk_level: ["low", "medium", "high"].includes(riskLevel) ? riskLevel : "high",
    confidence: Number.isFinite(confidenceRaw) ? Math.max(0, Math.min(1, confidenceRaw)) : 0,
    summary: typeof parsed.summary === "string" ? parsed.summary : "",
    reasons: Array.isArray(parsed.reasons) ? parsed.reasons.map((x) => String(x)) : [],
    flags: Array.isArray(parsed.flags) ? parsed.flags.map((x) => String(x)) : [],
    recommended_action:
      parsed.recommended_action === "monitor" || parsed.recommended_action === "review" || parsed.recommended_action === "pause"
        ? parsed.recommended_action
        : "review"
  };
}

async function handleProposal(config, runtime, snapshotProposal, state) {
  const proposalIdentifier = snapshotProposal?.id || "unknown";

  let payload;
  try {
    payload = parseOnchainPayload(snapshotProposal, config.policy.snapshotPluginKey);
  } catch (error) {
    log("warn", "skip proposal with invalid plugin payload", {
      snapshotProposalId: proposalIdentifier,
      error: String(error.message || error)
    });
    return;
  }

  if (!payload) return;

  const proposalId = payload.proposalId;
  const snapshotBlock = toUint(snapshotProposal.snapshot, "snapshot.snapshot");

  const onchainProposal = await readProposal(config, proposalId, runtime.agentAddress);
  if (!onchainProposal.exists) {
    log("warn", "on-chain proposal does not exist", { snapshotProposalId: proposalIdentifier, proposalId: String(proposalId) });
    return;
  }

  if (onchainProposal.snapshotBlock !== snapshotBlock) {
    log("warn", "snapshot block mismatch", {
      snapshotProposalId: proposalIdentifier,
      proposalId: String(proposalId),
      snapshotBlock: String(snapshotBlock),
      onchainSnapshotBlock: String(onchainProposal.snapshotBlock)
    });
    return;
  }

  if (payload.transactions.length > config.policy.safety.maxTransactionsPerProposal) {
    log("warn", "proposal exceeds maxTransactionsPerProposal", {
      snapshotProposalId: proposalIdentifier,
      proposalId: String(proposalId),
      txCount: payload.transactions.length
    });
    return;
  }

  const totalEthValue = payload.transactions.reduce((acc, tx) => acc + tx.value, 0n);
  if (totalEthValue > BigInt(config.policy.safety.maxBundleEthValueWei)) {
    log("warn", "proposal exceeds maxBundleEthValueWei", {
      snapshotProposalId: proposalIdentifier,
      proposalId: String(proposalId),
      totalEthValue: totalEthValue.toString()
    });
    return;
  }

  const txArg = formatTxTupleArray(payload.transactions);
  const computedExecutionHash = String(
    await readSingle(
      config.rpcUrl,
      config.executor,
      "computeExecutionHash(uint256,bytes32,(address,uint256,bytes)[])",
      "f()(bytes32)",
      [proposalId, payload.salt, txArg],
      runtime.agentAddress
    )
  ).toLowerCase();

  if (computedExecutionHash !== onchainProposal.executionHash) {
    log("warn", "computed execution hash mismatch", {
      snapshotProposalId: proposalIdentifier,
      proposalId: String(proposalId),
      computedExecutionHash,
      onchainExecutionHash: onchainProposal.executionHash
    });
    return;
  }

  if (payload.executionHash && payload.executionHash !== computedExecutionHash) {
    log("warn", "plugin execution hash mismatch", {
      snapshotProposalId: proposalIdentifier,
      proposalId: String(proposalId),
      pluginExecutionHash: payload.executionHash,
      computedExecutionHash
    });
    if (config.policy.safety.requireExecutionHashMatch) return;
  }

  const forVotes = parseScoreAt(snapshotProposal.scores, config.policy.choices.for, config.policy.snapshotScoreDecimals);
  const againstVotes = parseScoreAt(snapshotProposal.scores, config.policy.choices.against, config.policy.snapshotScoreDecimals);
  const abstainVotes = parseScoreAt(snapshotProposal.scores, config.policy.choices.abstain, config.policy.snapshotScoreDecimals);

  const totalStakedAtSnapshot = BigInt(
    await readSingle(
      config.rpcUrl,
      config.stakeManager,
      "totalStakedAt(uint256)",
      "f()(uint256)",
      [snapshotBlock],
      runtime.agentAddress
    )
  );

  if (forVotes > UINT128_MAX || againstVotes > UINT128_MAX || abstainVotes > UINT128_MAX || totalStakedAtSnapshot > UINT128_MAX) {
    log("warn", "proposal tally does not fit uint128", {
      snapshotProposalId: proposalIdentifier,
      proposalId: String(proposalId)
    });
    return;
  }

  const params = await readParams(config, runtime.agentAddress);
  const passed = computePassed(
    onchainProposal.proposalType,
    { forVotes, againstVotes, abstainVotes },
    totalStakedAtSnapshot,
    params
  );

  const snapshotProposalHash = castKeccak(snapshotProposal.id);
  const metadataEncoded = castAbiEncode("f(bytes32,bytes32,uint256,uint64,bytes32)", [
    snapshotProposalHash,
    runtime.snapshotSpaceHash,
    proposalId,
    snapshotBlock,
    computedExecutionHash
  ]);
  const metadataHash = castKeccak(metadataEncoded);

  const result = {
    proposalId,
    executionHash: computedExecutionHash,
    snapshotProposalHash,
    snapshotSpaceHash: runtime.snapshotSpaceHash,
    snapshotConfigHash: runtime.snapshotConfigHash,
    snapshotBlock,
    forVotes,
    againstVotes,
    abstainVotes,
    totalStakedAtSnapshot,
    passed,
    metadataHash
  };

  const resultTuple = formatSnapshotResultTuple(result);
  const resultHash = String(
    await readSingle(
      config.rpcUrl,
      config.oracleAdapter,
      "hashSnapshotResult((uint256,bytes32,bytes32,bytes32,bytes32,uint64,uint128,uint128,uint128,uint128,bool,bytes32))",
      "f()(bytes32)",
      [resultTuple],
      runtime.agentAddress
    )
  ).toLowerCase();

  const settlement = await readSettlement(config, proposalId, runtime.agentAddress);

  const record = {
    snapshotProposalId: proposalIdentifier,
    proposalId: String(proposalId),
    resultHash,
    settlement
  };

  if (config.ai.enabled) {
    try {
      const aiReview = await requestAiAdvisory(config, {
        snapshotProposalId: proposalIdentifier,
        proposalId: String(proposalId),
        title: snapshotProposal?.title || "",
        proposalType: onchainProposal.proposalType,
        tally: {
          forVotes: forVotes.toString(),
          againstVotes: againstVotes.toString(),
          abstainVotes: abstainVotes.toString(),
          totalStakedAtSnapshot: totalStakedAtSnapshot.toString(),
          passed
        },
        txCount: payload.transactions.length,
        totalEthValueWei: totalEthValue.toString(),
        challenged: settlement.challenged,
        finalized: settlement.finalized
      });

      state.lastAiReviews = state.lastAiReviews || {};
      state.lastAiReviews[String(proposalId)] = { at: nowIso(), review: aiReview };
      log("ai", "advisory review", { proposalId: String(proposalId), review: aiReview });
    } catch (error) {
      log("warn", "ai advisory failed", { proposalId: String(proposalId), error: String(error.message || error) });
    }
  }

  if (!settlement.finalized && settlement.proposedAt > 0n && settlement.submittedHash !== resultHash) {
    if (config.policy.operations.challenge && !settlement.challenged) {
      const evidenceHash = buildChallengeEvidence(proposalIdentifier, resultHash, settlement.submittedHash);
      const challengeData = castCalldata("challengeResult(uint256,bytes32)", [proposalId, evidenceHash]);
      if (await canCall(config.rpcUrl, runtime.agentAddress, config.oracleAdapter, challengeData)) {
        const tx = await sendTx(
          config.rpcUrl,
          config.privateKey,
          config.oracleAdapter,
          challengeData,
          config.dryRun,
          "challenge settlement hash mismatch"
        );
        log("action", "challenged mismatched settlement", { ...record, txHash: tx.txHash, evidenceHash });
        state.lastActions[`${proposalId}:challenge`] = { at: nowIso(), txHash: tx.txHash };
      }
    }
    return;
  }

  if (settlement.submittedHash === ZERO_HASH && config.policy.operations.submitResultHash) {
    const submitData = castCalldata("submitResultHash(uint256,bytes32)", [proposalId, resultHash]);
    if (await canCall(config.rpcUrl, runtime.agentAddress, config.oracleAdapter, submitData)) {
      const tx = await sendTx(
        config.rpcUrl,
        config.privateKey,
        config.oracleAdapter,
        submitData,
        config.dryRun,
        "submit snapshot result hash"
      );
      log("action", "submitted result hash", { ...record, txHash: tx.txHash });
      state.lastActions[`${proposalId}:submit`] = { at: nowIso(), txHash: tx.txHash };
    }
    return;
  }

  if (settlement.proposedAt === 0n && config.policy.operations.proposeResult) {
    if (settlement.submittedHash !== resultHash) {
      log("warn", "submitted hash does not match local verification", {
        ...record,
        expectedSubmittedHash: resultHash
      });
      return;
    }

    const proposeData = castCalldata(
      "proposeResult((uint256,bytes32,bytes32,bytes32,bytes32,uint64,uint128,uint128,uint128,uint128,bool,bytes32))",
      [resultTuple]
    );

    if (await canCall(config.rpcUrl, runtime.agentAddress, config.oracleAdapter, proposeData)) {
      if (shouldUseConsensus(config, "propose")) {
        const consensus = await attestConsensusAction(
          config,
          "propose",
          proposalId,
          config.oracleAdapter,
          proposeData,
          "0"
        );
        log("action", "submitted propose attestation to consensus manager", { ...record, consensus });
        state.lastActions[`${proposalId}:propose_consensus`] = { at: nowIso(), consensus };
      } else {
        const tx = await sendTx(
          config.rpcUrl,
          config.privateKey,
          config.oracleAdapter,
          proposeData,
          config.dryRun,
          "propose verified snapshot result"
        );
        log("action", "proposed snapshot result", { ...record, txHash: tx.txHash, passed });
        state.lastActions[`${proposalId}:propose`] = { at: nowIso(), txHash: tx.txHash };
      }
    }
    return;
  }

  if (!settlement.finalized && !settlement.challenged && runtime.isAttester && config.policy.operations.attest) {
    const hasAttested = Boolean(
      await readSingle(
        config.rpcUrl,
        config.oracleAdapter,
        "hasAttested(uint256,address)",
        "f()(bool)",
        [proposalId, runtime.agentAddress],
        runtime.agentAddress
      )
    );

    if (!hasAttested) {
      const attestData = castCalldata("attestResult(uint256)", [proposalId]);
      if (await canCall(config.rpcUrl, runtime.agentAddress, config.oracleAdapter, attestData)) {
        const tx = await sendTx(
          config.rpcUrl,
          config.privateKey,
          config.oracleAdapter,
          attestData,
          config.dryRun,
          "attest snapshot result"
        );
        log("action", "attested snapshot result", { ...record, txHash: tx.txHash });
        state.lastActions[`${proposalId}:attest`] = { at: nowIso(), txHash: tx.txHash };
      }
      return;
    }
  }

  if (config.policy.operations.execute && passed) {
    const executed = Boolean(
      await readSingle(
        config.rpcUrl,
        config.executor,
        "proposalExecuted(uint256)",
        "f()(bool)",
        [proposalId],
        runtime.agentAddress
      )
    );

    if (!executed) {
      const finalizeAndExecuteData = castCalldata(
        "finalizeAndExecuteBundle(uint256,bytes32,(address,uint256,bytes)[])",
        [proposalId, payload.salt, txArg]
      );

      if (await canCall(config.rpcUrl, runtime.agentAddress, config.executor, finalizeAndExecuteData)) {
        if (shouldUseConsensus(config, "execute")) {
          const consensus = await attestConsensusAction(
            config,
            "execute",
            proposalId,
            config.executor,
            finalizeAndExecuteData,
            "0"
          );
          log("action", "submitted execute attestation to consensus manager", { ...record, consensus });
          state.lastActions[`${proposalId}:execute_consensus`] = { at: nowIso(), consensus };
        } else {
          const tx = await sendTx(
            config.rpcUrl,
            config.privateKey,
            config.executor,
            finalizeAndExecuteData,
            config.dryRun,
            "finalize and execute passed bundle"
          );
          log("action", "finalized and executed bundle", { ...record, txHash: tx.txHash });
          state.lastActions[`${proposalId}:execute`] = { at: nowIso(), txHash: tx.txHash };
        }
      }
      return;
    }
  }

  if (!settlement.finalized && config.policy.operations.finalize && !settlement.challenged) {
    const finalizeData = castCalldata("finalizeResult(uint256)", [proposalId]);
    if (await canCall(config.rpcUrl, runtime.agentAddress, config.oracleAdapter, finalizeData)) {
      if (shouldUseConsensus(config, "finalize")) {
        const consensus = await attestConsensusAction(
          config,
          "finalize",
          proposalId,
          config.oracleAdapter,
          finalizeData,
          "0"
        );
        log("action", "submitted finalize attestation to consensus manager", { ...record, consensus });
        state.lastActions[`${proposalId}:finalize_consensus`] = { at: nowIso(), consensus };
      } else {
        const tx = await sendTx(
          config.rpcUrl,
          config.privateKey,
          config.oracleAdapter,
          finalizeData,
          config.dryRun,
          "finalize oracle settlement"
        );
        log("action", "finalized oracle settlement", { ...record, txHash: tx.txHash });
        state.lastActions[`${proposalId}:finalize`] = { at: nowIso(), txHash: tx.txHash };
      }
    }
  }
}

function loadConfig(rootDir) {
  const policyPath = process.env.GOV_AGENT_POLICY_PATH || resolve(rootDir, "agent", "policy.example.json");
  const statePath = process.env.GOV_AGENT_STATE_PATH || resolve(rootDir, "agent", "state", "agent-state.json");

  const policy = loadJson(policyPath, null);
  if (!policy || typeof policy !== "object") fatal(`unable to load policy file: ${policyPath}`);

  const rpcUrl = process.env.GOV_AGENT_RPC_URL || "";
  const privateKey = process.env.GOV_AGENT_PRIVATE_KEY || "";
  const oracleAdapter = normalizeAddress(process.env.GOV_AGENT_ORACLE_ADAPTER || "");
  const stakeManager = normalizeAddress(process.env.GOV_AGENT_STAKE_MANAGER || "");
  const parameterManager = normalizeAddress(process.env.GOV_AGENT_PARAMETER_MANAGER || "");
  const executor = normalizeAddress(process.env.GOV_AGENT_EXECUTOR || "");

  if (!rpcUrl) fatal("GOV_AGENT_RPC_URL is required");
  if (!privateKey) fatal("GOV_AGENT_PRIVATE_KEY is required");
  if (!oracleAdapter || !stakeManager || !parameterManager || !executor) {
    fatal("GOV_AGENT_ORACLE_ADAPTER, GOV_AGENT_STAKE_MANAGER, GOV_AGENT_PARAMETER_MANAGER, GOV_AGENT_EXECUTOR are required");
  }

  const pollIntervalSeconds = Number(process.env.GOV_AGENT_POLL_SECONDS || policy.pollIntervalSeconds || 30);
  const graphqlUrl = process.env.GOV_AGENT_SNAPSHOT_GRAPHQL || "https://hub.snapshot.org/graphql";
  const dryRun = process.env.GOV_AGENT_DRY_RUN === "1";
  const aiEnabled = process.env.GOV_AGENT_AI_ENABLED === "1" || policy.ai?.enabled === true;
  const aiApiKey = process.env.GOV_AGENT_OPENAI_API_KEY || "";
  const aiModel = process.env.GOV_AGENT_AI_MODEL || policy.ai?.model || "gpt-4o-mini";
  const aiBaseUrl =
    process.env.GOV_AGENT_AI_BASE_URL
    || policy.ai?.baseUrl
    || "https://api.openai.com/v1/chat/completions";
  const consensusEnabled = process.env.GOV_AGENT_CONSENSUS_ENABLED === "1";
  const consensusManagerUrl = process.env.GOV_AGENT_MANAGER_URL || "";
  const consensusAgentToken = process.env.GOV_AGENT_CONSENSUS_AGENT_TOKEN || "";
  const consensusAgentId = process.env.GOV_AGENT_INSTANCE_ID || "";
  const consensusActions = parseConsensusActions(process.env.GOV_AGENT_CONSENSUS_ACTIONS || "propose,finalize,execute");
  if (aiEnabled && !aiApiKey) fatal("GOV_AGENT_OPENAI_API_KEY is required when AI advisory is enabled");
  if (consensusEnabled) {
    if (!/^https?:\/\//.test(consensusManagerUrl)) {
      fatal("GOV_AGENT_MANAGER_URL must be set to http(s) URL when consensus is enabled");
    }
    if (consensusAgentToken.length < 24) {
      fatal("GOV_AGENT_CONSENSUS_AGENT_TOKEN must be set when consensus is enabled");
    }
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(consensusAgentId)) {
      fatal("GOV_AGENT_INSTANCE_ID must be set when consensus is enabled");
    }
  }

  if (typeof policy.space !== "string" || policy.space.length === 0) fatal("policy.space must be set");

  const mergedPolicy = {
    space: policy.space,
    snapshotPluginKey: policy.snapshotPluginKey || "governance_agent",
    snapshotScoreDecimals: Number(policy.snapshotScoreDecimals || 18),
    closedProposalLookback: Number(policy.closedProposalLookback || 20),
    choices: {
      for: Number(policy.choices?.for || 1),
      against: Number(policy.choices?.against || 2),
      abstain: Number(policy.choices?.abstain || 3)
    },
    operations: {
      submitResultHash: policy.operations?.submitResultHash !== false,
      proposeResult: policy.operations?.proposeResult !== false,
      attest: policy.operations?.attest !== false,
      challenge: policy.operations?.challenge !== false,
      finalize: policy.operations?.finalize !== false,
      execute: policy.operations?.execute !== false
    },
    safety: {
      maxTransactionsPerProposal: Number(policy.safety?.maxTransactionsPerProposal || 20),
      maxBundleEthValueWei: String(policy.safety?.maxBundleEthValueWei || "100000000000000000000"),
      requireExecutionHashMatch: policy.safety?.requireExecutionHashMatch !== false
    },
    ai: {
      enabled: policy.ai?.enabled === true,
      model: policy.ai?.model || "gpt-4o-mini"
    }
  };

  return {
    rpcUrl,
    privateKey,
    oracleAdapter,
    stakeManager,
    parameterManager,
    executor,
    graphqlUrl,
    dryRun,
    pollIntervalSeconds,
    statePath,
    policy: mergedPolicy,
    ai: {
      enabled: aiEnabled,
      apiKey: aiApiKey,
      model: aiModel,
      baseUrl: aiBaseUrl
    },
    consensus: {
      enabled: consensusEnabled,
      managerUrl: consensusManagerUrl,
      agentToken: consensusAgentToken,
      agentId: consensusAgentId,
      actions: consensusActions
    }
  };
}

async function runOnce(config, state) {
  const runtime = await buildContext(config);

  if (runtime.snapshotSpaceHash === ZERO_HASH) {
    log("warn", "snapshotSpaceHash is zero on ParameterManager");
  }
  if (runtime.snapshotConfigHash === ZERO_HASH) {
    log("warn", "snapshotConfigHash is zero on ParameterManager");
  }

  const localSpaceHash = castKeccak(config.policy.space);
  if (runtime.snapshotSpaceHash !== localSpaceHash) {
    log("warn", "configured Snapshot space hash differs from on-chain hash", {
      policySpace: config.policy.space,
      localSpaceHash,
      onchainSpaceHash: runtime.snapshotSpaceHash
    });
  }

  const proposals = await fetchSnapshotClosedProposals(
    config.graphqlUrl,
    config.policy.space,
    config.policy.closedProposalLookback
  );

  for (const snapshotProposal of proposals) {
    try {
      await handleProposal(config, runtime, snapshotProposal, state);
    } catch (error) {
      log("error", "proposal handling failed", {
        snapshotProposalId: snapshotProposal?.id,
        error: String(error.message || error)
      });
    }
  }
}

async function main() {
  const rootDir = process.cwd();
  const config = loadConfig(rootDir);
  const state = loadJson(config.statePath, { lastActions: {} });

  log("info", "starting governance agent", {
    space: config.policy.space,
    dryRun: config.dryRun,
    pollIntervalSeconds: config.pollIntervalSeconds,
    aiEnabled: config.ai.enabled,
    consensusEnabled: config.consensus.enabled,
    consensusAgentId: config.consensus.agentId || null
  });

  const runLoop = async () => {
    state.lastHeartbeatAt = nowIso();
    state.totalCycles = Number(state.totalCycles || 0) + 1;
    try {
      await runOnce(config, state);
      state.successfulCycles = Number(state.successfulCycles || 0) + 1;
      state.lastSuccessAt = nowIso();
      saveJson(config.statePath, state);
    } catch (error) {
      state.failedCycles = Number(state.failedCycles || 0) + 1;
      state.lastErrorAt = nowIso();
      state.lastErrorMessage = String(error.message || error);
      saveJson(config.statePath, state);
      log("error", "agent cycle failed", { error: String(error.message || error) });
    }
  };

  const once = process.argv.includes("--once");
  await runLoop();
  if (once) return;

  setInterval(runLoop, config.pollIntervalSeconds * 1000);
}

main().catch((error) => {
  fatal(String(error.message || error));
});
