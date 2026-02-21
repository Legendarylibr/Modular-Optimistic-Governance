// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IOracleAdapter} from "./interfaces/IOracleAdapter.sol";
import {IParameterManager} from "./interfaces/IParameterManager.sol";
import {IStakeManager} from "./interfaces/IStakeManager.sol";

contract OracleAdapter is IOracleAdapter {
    error ZeroAddress();
    error NotGovernanceExecutor();
    error NotAttester();
    error InvalidHash();
    error InvalidThreshold();
    error ResultAlreadySubmitted();
    error ResultNotSubmitted();
    error ResultAlreadyProposed();
    error ProposalVoteNotEnded();
    error InvalidExecutionHash();
    error InvalidOutcome();
    error InvalidSnapshotSpace();
    error InvalidSnapshotConfig();
    error InvalidMetadataSchema();
    error ChallengeWindowExpired();
    error ChallengeWindowOpen();
    error AlreadyChallenged();
    error AlreadyFinalized();
    error ChallengedResult();
    error NotChallenged();
    error SlashProposalRequiresFrozenAccount();
    error InvalidSnapshotBlock();
    error SnapshotSupplyMismatch();
    error InvalidVoteTotals();
    error SlashAccountNotFrozenAtSnapshot();
    error AlreadyAttested();
    error AttestationThresholdNotReached();

    uint16 internal constant BPS_DENOMINATOR = 10_000;

    bytes32 internal constant SNAPSHOT_RESULT_TYPEHASH =
        keccak256("SnapshotResultV2(address oracle,uint256 chainId,bytes32 payloadHash)");

    IStakeManager public immutable stakeMgr;
    IParameterManager public immutable params;

    struct Settlement {
        bytes32 submittedHash;
        bytes32 executionHash;
        bool passed;
        bool challenged;
        bool finalized;
        uint64 submittedAt;
        uint64 proposedAt;
        uint64 finalizedAt;
        uint32 attestationCount;
        uint8 proposalType;
        address submitter;
        address proposer;
        address challenger;
        bytes32 challengeEvidenceHash;
    }

    mapping(uint256 => Settlement) private _settlements;
    mapping(uint256 => mapping(address => bool)) private _hasAttested;
    mapping(address => bool) private _attesters;
    uint256 private _attesterCount;

    uint8 public override attesterThreshold;
    uint64 public override fallbackFinalizationDelay;

    event ResultHashSubmitted(uint256 indexed proposalId, bytes32 indexed resultHash, address indexed submitter);
    event ResultProposed(
        uint256 indexed proposalId,
        bytes32 indexed resultHash,
        address indexed proposer,
        bool passed,
        uint128 forVotes,
        uint128 againstVotes,
        uint128 abstainVotes,
        uint128 totalStakedAtSnapshot
    );
    event ResultChallenged(uint256 indexed proposalId, address indexed challenger, bytes32 indexed counterEvidenceHash);
    event ResultFinalized(uint256 indexed proposalId, bytes32 indexed executionHash, bool passed, uint64 finalizedAt);
    event ChallengedResultResolved(uint256 indexed proposalId, bool passed, uint64 finalizedAt);
    event ResultAttested(uint256 indexed proposalId, address indexed attester, uint32 attestationCount);
    event AttesterSet(address indexed account, bool enabled);
    event AttesterThresholdSet(uint8 threshold);
    event FallbackFinalizationDelaySet(uint64 delay);

    modifier onlyGovernanceExecutor() {
        if (msg.sender != params.governanceExecutor()) revert NotGovernanceExecutor();
        _;
    }

    modifier onlyAttester() {
        if (!_attesters[msg.sender]) revert NotAttester();
        _;
    }

    constructor(
        address stakeManager_,
        address parameterManager_,
        address[] memory initialAttesters,
        uint8 initialThreshold,
        uint64 initialFallbackFinalizationDelay
    ) {
        if (stakeManager_ == address(0) || parameterManager_ == address(0)) revert ZeroAddress();
        stakeMgr = IStakeManager(stakeManager_);
        params = IParameterManager(parameterManager_);
        fallbackFinalizationDelay = initialFallbackFinalizationDelay;

        uint256 length = initialAttesters.length;
        for (uint256 i = 0; i < length; ++i) {
            address attester = initialAttesters[i];
            if (attester == address(0)) revert ZeroAddress();
            if (!_attesters[attester]) {
                _attesters[attester] = true;
                ++_attesterCount;
                emit AttesterSet(attester, true);
            }
        }

        if (initialThreshold == 0 || initialThreshold > _attesterCount) revert InvalidThreshold();
        attesterThreshold = initialThreshold;
        emit AttesterThresholdSet(initialThreshold);
        emit FallbackFinalizationDelaySet(initialFallbackFinalizationDelay);
    }

    function stakeManager() external view override returns (address) {
        return address(stakeMgr);
    }

    function parameterManager() external view override returns (address) {
        return address(params);
    }

    function isAttester(address account) external view override returns (bool) {
        return _attesters[account];
    }

    function hasAttested(uint256 proposalId, address account) external view override returns (bool) {
        return _hasAttested[proposalId][account];
    }

    function setAttester(address account, bool enabled) external override onlyGovernanceExecutor {
        if (account == address(0)) revert ZeroAddress();
        bool current = _attesters[account];
        if (current == enabled) return;

        _attesters[account] = enabled;
        if (enabled) {
            ++_attesterCount;
        } else {
            --_attesterCount;
            if (attesterThreshold > _attesterCount) revert InvalidThreshold();
        }

        emit AttesterSet(account, enabled);
    }

    function setAttesterThreshold(uint8 newThreshold) external override onlyGovernanceExecutor {
        if (newThreshold == 0 || newThreshold > _attesterCount) revert InvalidThreshold();
        attesterThreshold = newThreshold;
        emit AttesterThresholdSet(newThreshold);
    }

    function setFallbackFinalizationDelay(uint64 newDelay) external override onlyGovernanceExecutor {
        fallbackFinalizationDelay = newDelay;
        emit FallbackFinalizationDelaySet(newDelay);
    }

    function hashSnapshotResult(SnapshotResult calldata result) public view override returns (bytes32) {
        bytes32 payloadHash = _hashSnapshotPayload(result);
        return keccak256(abi.encode(SNAPSHOT_RESULT_TYPEHASH, address(this), block.chainid, payloadHash));
    }

    function submitResultHash(uint256 proposalId, bytes32 resultHash) external override {
        if (resultHash == bytes32(0)) revert InvalidHash();

        Settlement storage settlement = _settlements[proposalId];
        if (settlement.submittedHash != bytes32(0)) revert ResultAlreadySubmitted();

        IStakeManager.ProposalView memory proposal = stakeMgr.getProposal(proposalId);
        if (block.timestamp < proposal.voteEnd) revert ProposalVoteNotEnded();

        settlement.submittedHash = resultHash;
        settlement.submittedAt = uint64(block.timestamp);
        settlement.submitter = msg.sender;

        emit ResultHashSubmitted(proposalId, resultHash, msg.sender);
    }

    function proposeResult(SnapshotResult calldata result) external override {
        Settlement storage settlement = _settlements[result.proposalId];
        if (settlement.submittedHash == bytes32(0)) revert ResultNotSubmitted();
        if (settlement.proposedAt != 0) revert ResultAlreadyProposed();

        bytes32 computedHash = hashSnapshotResult(result);
        if (computedHash != settlement.submittedHash) revert InvalidHash();

        IStakeManager.ProposalView memory proposal = stakeMgr.getProposal(result.proposalId);
        if (block.timestamp < proposal.voteEnd) revert ProposalVoteNotEnded();
        _validateSnapshotResultBinding(result, proposal);

        bool computedPassed = _computePassed(proposal.proposalType, result);
        if (computedPassed != result.passed) revert InvalidOutcome();

        settlement.executionHash = result.executionHash;
        settlement.passed = result.passed;
        settlement.proposedAt = uint64(block.timestamp);
        settlement.proposalType = uint8(proposal.proposalType);
        settlement.proposer = msg.sender;

        emit ResultProposed(
            result.proposalId,
            settlement.submittedHash,
            msg.sender,
            result.passed,
            result.forVotes,
            result.againstVotes,
            result.abstainVotes,
            result.totalStakedAtSnapshot
        );
    }

    function _validateSnapshotResultBinding(SnapshotResult calldata result, IStakeManager.ProposalView memory proposal)
        internal
        view
    {
        if (result.executionHash != proposal.executionHash) revert InvalidExecutionHash();
        if (result.snapshotBlock != proposal.snapshotBlock) revert InvalidSnapshotBlock();
        if (result.snapshotProposalHash == bytes32(0)) revert InvalidMetadataSchema();
        if (result.snapshotSpaceHash != params.snapshotSpaceHash()) revert InvalidSnapshotSpace();
        if (result.snapshotConfigHash != params.snapshotConfigHash()) revert InvalidSnapshotConfig();

        bytes32 expectedMetadataHash = keccak256(
            abi.encode(
                result.snapshotProposalHash,
                result.snapshotSpaceHash,
                result.proposalId,
                result.snapshotBlock,
                result.executionHash
            )
        );
        if (result.metadataHash != expectedMetadataHash) revert InvalidMetadataSchema();

        uint256 recordedTotalStaked = stakeMgr.totalStakedAt(result.snapshotBlock);
        if (recordedTotalStaked != result.totalStakedAtSnapshot) revert SnapshotSupplyMismatch();

        uint256 votesCast = uint256(result.forVotes) + uint256(result.againstVotes) + uint256(result.abstainVotes);
        if (votesCast > result.totalStakedAtSnapshot) revert InvalidVoteTotals();

        if (proposal.proposalType == IStakeManager.ProposalType.SlashExecution && !stakeMgr.isFrozen(proposal.accused)) {
            revert SlashProposalRequiresFrozenAccount();
        }
        if (proposal.proposalType == IStakeManager.ProposalType.SlashExecution) {
            if (!stakeMgr.isFrozenAt(proposal.accused, result.snapshotBlock)) revert SlashAccountNotFrozenAtSnapshot();
        }
    }

    function attestResult(uint256 proposalId) external override onlyAttester {
        Settlement storage settlement = _settlements[proposalId];
        if (settlement.proposedAt == 0) revert ResultNotSubmitted();
        if (settlement.finalized) revert AlreadyFinalized();
        if (settlement.challenged) revert ChallengedResult();
        if (_hasAttested[proposalId][msg.sender]) revert AlreadyAttested();

        _hasAttested[proposalId][msg.sender] = true;
        settlement.attestationCount += 1;

        emit ResultAttested(proposalId, msg.sender, settlement.attestationCount);
    }

    function challengeResult(uint256 proposalId, bytes32 counterEvidenceHash) external override {
        Settlement storage settlement = _settlements[proposalId];
        if (settlement.proposedAt == 0) revert ResultNotSubmitted();
        if (settlement.finalized) revert AlreadyFinalized();
        if (settlement.challenged) revert AlreadyChallenged();

        uint64 challengeWindow = params.oracleChallengeWindow();
        if (block.timestamp >= uint256(settlement.proposedAt) + challengeWindow) revert ChallengeWindowExpired();

        settlement.challenged = true;
        settlement.challenger = msg.sender;
        settlement.challengeEvidenceHash = counterEvidenceHash;

        emit ResultChallenged(proposalId, msg.sender, counterEvidenceHash);
    }

    function resolveChallengedResult(uint256 proposalId, bool passed) external override onlyGovernanceExecutor {
        Settlement storage settlement = _settlements[proposalId];
        if (settlement.proposedAt == 0) revert ResultNotSubmitted();
        if (settlement.finalized) revert AlreadyFinalized();
        if (!settlement.challenged) revert NotChallenged();

        settlement.passed = passed;
        settlement.challenged = false;
        settlement.finalized = true;
        settlement.finalizedAt = uint64(block.timestamp);
        stakeMgr.settleProposalBond(proposalId, passed);

        emit ChallengedResultResolved(proposalId, passed, uint64(block.timestamp));
    }

    function finalizeResult(uint256 proposalId) external override {
        Settlement storage settlement = _settlements[proposalId];
        if (settlement.proposedAt == 0) revert ResultNotSubmitted();
        if (settlement.finalized) revert AlreadyFinalized();
        if (settlement.challenged) revert ChallengedResult();

        uint64 challengeWindow = params.oracleChallengeWindow();
        uint256 challengeEnd = uint256(settlement.proposedAt) + challengeWindow;
        if (block.timestamp < challengeEnd) revert ChallengeWindowOpen();

        bool thresholdMet = settlement.attestationCount >= attesterThreshold;
        uint256 finalizedAt = challengeEnd;
        if (!thresholdMet) {
            uint256 fallbackFinalizationTime = challengeEnd + fallbackFinalizationDelay;
            if (block.timestamp < fallbackFinalizationTime) revert AttestationThresholdNotReached();
            finalizedAt = fallbackFinalizationTime;
        }

        settlement.finalized = true;
        settlement.finalizedAt = uint64(finalizedAt);
        stakeMgr.settleProposalBond(proposalId, settlement.passed);

        emit ResultFinalized(proposalId, settlement.executionHash, settlement.passed, uint64(finalizedAt));
    }

    function getSettlement(uint256 proposalId) external view override returns (SettlementView memory) {
        Settlement memory settlement = _settlements[proposalId];
        return SettlementView({
            submittedHash: settlement.submittedHash,
            executionHash: settlement.executionHash,
            passed: settlement.passed,
            challenged: settlement.challenged,
            finalized: settlement.finalized,
            attestationCount: settlement.attestationCount,
            proposedAt: settlement.proposedAt,
            finalizedAt: settlement.finalizedAt,
            proposalType: settlement.proposalType
        });
    }

    function _computePassed(IStakeManager.ProposalType proposalType, SnapshotResult calldata result)
        internal
        view
        returns (bool)
    {
        if (result.totalStakedAtSnapshot == 0) return false;

        uint16 quorumTarget = proposalType == IStakeManager.ProposalType.SlashExecution
            ? params.slashingQuorumBps()
            : params.quorumBps();

        uint16 majorityTarget = proposalType == IStakeManager.ProposalType.SlashExecution
            ? params.superMajorityBps()
            : params.majorityBps();

        uint256 votesCast = uint256(result.forVotes) + uint256(result.againstVotes) + uint256(result.abstainVotes);
        bool quorumReached = (votesCast * BPS_DENOMINATOR) >= (uint256(result.totalStakedAtSnapshot) * quorumTarget);
        if (!quorumReached) return false;

        uint256 decisiveVotes = uint256(result.forVotes) + uint256(result.againstVotes);
        if (decisiveVotes == 0) return false;

        bool supportReached = (uint256(result.forVotes) * BPS_DENOMINATOR) >= (decisiveVotes * majorityTarget);
        return supportReached;
    }

    function _hashSnapshotPayload(SnapshotResult calldata result) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                result.proposalId,
                result.executionHash,
                result.snapshotProposalHash,
                result.snapshotSpaceHash,
                result.snapshotConfigHash,
                result.snapshotBlock,
                result.forVotes,
                result.againstVotes,
                result.abstainVotes,
                result.totalStakedAtSnapshot,
                result.passed,
                result.metadataHash
            )
        );
    }
}
