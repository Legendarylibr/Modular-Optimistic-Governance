# Modular DAO Governance (Snapshot + Optimistic Oracle + Executor)

This repository implements a modular governance stack with off-chain Snapshot voting and on-chain optimistic settlement.

## 1) Contract Architecture Overview

### Components
- `StakeManager`
  - Custodies governance tokens.
  - Enforces stake requirements for proposal submission, delegation eligibility, voting power access, freezing, and slashing.
  - Records proposal metadata (`executionHash`, vote window, proposal type, accused account for slashing flows).
  - Enforces proposal bond economics (bond lock on submit, refund on pass, slash to treasury on fail).

- `OracleAdapter`
  - Optimistic oracle-style settlement for Snapshot outcomes.
  - Flow: submit hash -> propose result -> challenge window -> finalize.
  - Validates outcome thresholds by proposal type and checks hash integrity with domain separation.
  - Uses attester threshold finalization with fallback delay for censorship-resilient liveness.

- `GovernanceExecutor`
  - Executes only finalized, passed oracle outcomes.
  - Verifies bundle hash, enforces timelock and slashing cooldown, blocks replay/double execution.
  - Supports emergency pause (guardian, bounded duration, auto-expiry) and high-impact timelock extension.
  - Enforces target allowlist (from `ParameterManager`) and supports governance-only self-updates.

- `ParameterManager`
  - Stores governance configuration and allowlisted execution targets.
  - Runtime parameter changes are only callable by `GovernanceExecutor`.
  - One-time bootstrap owner sets initial governance executor and bootstrap target allowlist.

### Treasury / Safe integration
- Treasury assets are intended to remain in a Safe multisig.
- `GovernanceExecutor` is designed to be authorized as a Safe module.
- Governance payloads can include calls to Safe contracts only if those contracts are allowlisted in `ParameterManager`.

## 2) Solidity Contracts
- `/Users/libr/Downloads/Slashing dao structure/src/GovernanceExecutor.sol`
- `/Users/libr/Downloads/Slashing dao structure/src/StakeManager.sol`
- `/Users/libr/Downloads/Slashing dao structure/src/OracleAdapter.sol`
- `/Users/libr/Downloads/Slashing dao structure/src/ParameterManager.sol`

## 3) Interface Definitions
- `/Users/libr/Downloads/Slashing dao structure/src/interfaces/IGovernanceExecutor.sol`
- `/Users/libr/Downloads/Slashing dao structure/src/interfaces/IStakeManager.sol`
- `/Users/libr/Downloads/Slashing dao structure/src/interfaces/IOracleAdapter.sol`
- `/Users/libr/Downloads/Slashing dao structure/src/interfaces/IParameterManager.sol`
- `/Users/libr/Downloads/Slashing dao structure/src/interfaces/IERC20.sol`

## 4) Storage Layout Design

### `ParameterManager`
- `governanceExecutor`: runtime governance authority (executor contract).
- Treasury routing: `treasury`, `compensationPool`, `burnAddress`.
- Governance thresholds:
  - `proposalThresholdBps`
  - `quorumBps`
  - `majorityBps`
  - `superMajorityBps`
  - `slashingQuorumBps`
  - `maxSlashingBps`
- Timing controls:
  - `oracleChallengeWindow`
  - `timelockDuration`
  - `slashingExecutionCooldown`
- `_approvedTargets[target] => bool` execution allowlist.

### `StakeManager`
- Token + config refs: `token`, `params`, `governanceExecutor`.
- Stake state:
  - `totalStaked`
  - `_stakeOf[account]`
  - `_lockedUntil[account]`
  - `globalVoteLockUntil`
  - `_delegateOf[account]`
  - `_isFrozen[account]`
  - `_frozenAt[account]`
- Proposal registry:
  - `proposalCount`
  - `_proposals[proposalId]` with proposer, `executionHash`, vote window, type, accused, `maxSlashBps`.

### `OracleAdapter`
- Refs: `stakeMgr`, `params`.
- `_settlements[proposalId]`:
  - Submitted hash, execution hash, pass/final flags, challenged state.
  - Timestamps (`submittedAt`, `proposedAt`, `finalizedAt`) and actors (`submitter`, `proposer`, `challenger`).
  - `proposalType` and challenge evidence hash.

### `GovernanceExecutor`
- Contract refs: `oracleAdapter`, `parameterManager`.
- Replay/double-execution protection:
  - `executionHashExecuted[hash]`
  - `proposalExecuted[proposalId]`

## 5) Event Definitions

Each contract emits state transition events:
- `ParameterManager`
  - `GovernanceExecutorSet`
  - `GovernanceParamsUpdated`
  - `TargetApprovalSet`
  - `TreasurySet`, `CompensationPoolSet`, `BurnAddressSet`
- `StakeManager`
  - `Staked`, `Unstaked`, `DelegateSet`
  - `StakeLockUpdated`, `GlobalVoteLockUpdated`
  - `ProposalRegistered`
  - `StakeFrozen`, `StakeUnfrozen`, `StakeSlashed`
- `OracleAdapter`
  - `ResultHashSubmitted`
  - `ResultProposed`
  - `ResultChallenged`
  - `ResultFinalized`
- `GovernanceExecutor`
  - `TransactionExecuted`
  - `BundleExecuted`
  - `OracleAdapterUpdated`, `ParameterManagerUpdated`

## 6) Execution Flow Explanation

### Standard governance flow
1. Proposer stakes governance tokens.
2. Proposer registers proposal in `StakeManager` with `executionHash` and Snapshot voting window.
3. Snapshot runs off-chain vote (token-weighted by staked balances via strategy).
4. After vote end, anyone submits result hash to `OracleAdapter`.
5. Anyone proposes full result data matching submitted hash.
6. Challenge window opens (`oracleChallengeWindow`).
7. If unchallenged, result finalizes.
8. After timelock (`timelockDuration`), anyone calls `GovernanceExecutor.executeBundle`.
9. Executor validates oracle outcome, hash match, replay status, and target allowlist, then executes bundle.

### Snapshot.org compatibility flow
1. Create proposal off-chain on Snapshot with a fixed `snapshot` block number.
2. Register on-chain proposal with the same block via `registerProposalWithSnapshot(...)`.
3. Snapshot strategy reads voting power from `StakeManager.votingPowerAt(voter, snapshotBlock)`.
4. Snapshot quorum reference can use `StakeManager.totalStakedAt(snapshotBlock)`.
5. Oracle settlement submits `snapshotProposalHash`, `snapshotSpaceHash`, and `snapshotBlock` in `SnapshotResult`.
6. `OracleAdapter` verifies:
   - snapshot block matches registered proposal,
   - `totalStakedAtSnapshot` equals on-chain historical total at that block,
   - vote totals do not exceed snapshot supply,
   - snapshot space hash matches configured governance space,
   - metadata hash follows deterministic schema.

### 2-phase slashing flow
1. **Phase 1: Notice proposal (`SlashNotice`)**
   - Snapshot vote passes with standard majority + standard quorum.
   - Finalized bundle executes `StakeManager.freezeStake(accused, proposalId)`.
2. **Phase 2: Slashing proposal (`SlashExecution`)**
   - Requires accused already frozen.
   - Snapshot vote must satisfy supermajority + slashing quorum.
   - Finalized bundle executes `StakeManager.slashStake(...)` with per-proposal cap and global max cap checks.
   - Tokens route to treasury, burn address, or compensation pool.
3. **Optional Appeal (`Appeal`)**
   - Separate proposal may execute `unfreezeStake` if governance overturns slash/freeze decision.

## 7) Threat Model Analysis

### Covered controls
- Reentrancy: `ReentrancyGuard` in execution and token transfer paths.
- Access control:
  - Governance runtime writes limited to `GovernanceExecutor`.
  - Bootstrap owner restricted to one-time initialization.
- Replay prevention:
  - Execution hash binds contract + chain + proposal + salt + tx bundle.
  - `executionHashExecuted` and `proposalExecuted` prevent replays/double execution.
- Oracle integrity:
  - Result hash is domain-separated and recomputed on propose.
  - Proposal execution hash must match registered hash in `StakeManager`.
  - Challenge window blocks immediate finalization.
- Slashing abuse limits:
  - Separate notice and slash phases.
  - Supermajority + higher quorum for slash outcomes.
  - Configurable max slashing cap and execution cooldown.
  - Frozen stake has zero voting power.

### Residual risks / operational assumptions
- Snapshot strategy must source voting power from `StakeManager.votingPowerAt(...)` to enforce frozen-vote exclusion at the Snapshot block.
- Governance capture remains economically possible if token distribution is highly centralized; mitigation is policy-level (higher quorums, slower timelocks, appeal path, social layer).
- Proposal ID prediction is used when payload references proposal IDs directly; governance ops should avoid parallel ID races during proposal registration.

## 8) Gas Optimization Notes
- Uses packed small types where practical (`uint16`, `uint64`, `uint8`) for config/state.
- Storage writes only at transition points; heavy computation remains off-chain.
- Bundle hash uses per-tx keccak and one final hash for replay safety.
- Stateless view validations in oracle/executor avoid redundant persistent fields.
- `immutable` contract references reduce runtime SLOADs for core dependencies.

## 9) Unit Test Plan Outline

Implemented tests (`/Users/libr/Downloads/Slashing dao structure/test/GovernanceSystem.t.sol`):
- `testStandardProposalExecution`
- `testReplayAndDoubleExecutionPrevention`
- `testRejectsUnapprovedTargets`
- `testChallengeBlocksFinalization`
- `testTwoPhaseSlashingFlow`
- `testOracleUpdateRequiresGovernanceExecution`

Additional recommended tests:
- Boundary checks for all parameter bps and timing values.
- Fuzz tests for quorum/majority edge conditions.
- Negative tests for malformed oracle results and hash mismatch permutations.
- Multi-tx bundle atomicity and ETH value accounting tests.
- Safe module integration tests on a forked environment.

## 10) Upgrade Strategy

Current implementation is non-upgradeable (recommended default for governance minimization).

If upgradeability is required:
- Use transparent proxy or UUPS with immutable governance constraints.
- Restrict upgrade authority to `GovernanceExecutor` only.
- Route upgrade calls through Snapshot->Oracle->Executor flow with timelock.
- Add explicit upgrade cooldown and versioned implementation registry.
- Preserve storage slots exactly; include storage-gap policy and upgrade tests.

## Build & Test

- Build: `forge build`
- Test (offline mode to avoid external signature lookups): `forge test --offline`

## Deployment Script

Script: `/Users/libr/Downloads/Slashing dao structure/script/DeployGovernance.s.sol`

Required environment variables:
- `DEPLOYER_PRIVATE_KEY`
- `GOV_TOKEN`
- `TREASURY`
- `COMPENSATION_POOL`
- `BURN_ADDRESS`
- `SNAPSHOT_SPACE_HASH`
- `PROPOSAL_THRESHOLD_BPS`
- `QUORUM_BPS`
- `MAJORITY_BPS`
- `SUPER_MAJORITY_BPS`
- `SLASHING_QUORUM_BPS`
- `MAX_SLASHING_BPS`
- `ORACLE_CHALLENGE_WINDOW`
- `TIMELOCK_DURATION`
- `SLASHING_EXECUTION_COOLDOWN`
- `HIGH_IMPACT_TIMELOCK_DURATION`
- `EMERGENCY_PAUSE_MAX_DURATION`
- `PROPOSAL_BOND`
- `ORACLE_ATTESTER_1`
- `ORACLE_ATTESTER_THRESHOLD`
- `ORACLE_FALLBACK_FINALIZATION_DELAY`
- `EMERGENCY_GUARDIAN`

Example:

```bash
forge script script/DeployGovernance.s.sol:DeployGovernance \
  --rpc-url $RPC_URL \
  --broadcast
```

## Safe Fork Harness

Fork harness test: `/Users/libr/Downloads/Slashing dao structure/test/fork/SafeModuleFork.t.sol`

Required environment variables:
- `FORK_RPC_URL`
- `SAFE_ADDRESS`
- `SAFE_OWNER_PK`

Behavior:
- If env vars are absent, the test exits early (no failure).
- If env vars are present, the test validates:
  - enabling `GovernanceExecutor` as a Safe module via signed Safe transaction,
  - proposal settlement through `OracleAdapter`,
  - governance execution calling `Safe.execTransactionFromModule(...)`.

Run:

```bash
forge test --match-path test/fork/SafeModuleFork.t.sol
```
