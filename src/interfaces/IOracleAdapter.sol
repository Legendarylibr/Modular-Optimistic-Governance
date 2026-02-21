// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IOracleAdapter {
    struct SnapshotResult {
        uint256 proposalId;
        bytes32 executionHash;
        bytes32 snapshotProposalHash;
        bytes32 snapshotSpaceHash;
        bytes32 snapshotConfigHash;
        uint64 snapshotBlock;
        uint128 forVotes;
        uint128 againstVotes;
        uint128 abstainVotes;
        uint128 totalStakedAtSnapshot;
        bool passed;
        bytes32 metadataHash;
    }

    struct SettlementView {
        bytes32 submittedHash;
        bytes32 executionHash;
        bool passed;
        bool challenged;
        bool finalized;
        uint32 attestationCount;
        uint64 proposedAt;
        uint64 finalizedAt;
        uint8 proposalType;
    }

    function stakeManager() external view returns (address);
    function parameterManager() external view returns (address);
    function attesterThreshold() external view returns (uint8);
    function fallbackFinalizationDelay() external view returns (uint64);
    function isAttester(address account) external view returns (bool);
    function hasAttested(uint256 proposalId, address account) external view returns (bool);

    function hashSnapshotResult(SnapshotResult calldata result) external view returns (bytes32);

    function setAttester(address account, bool enabled) external;
    function setAttesterThreshold(uint8 newThreshold) external;
    function setFallbackFinalizationDelay(uint64 newDelay) external;

    function submitResultHash(uint256 proposalId, bytes32 resultHash) external;
    function proposeResult(SnapshotResult calldata result) external;
    function attestResult(uint256 proposalId) external;
    function challengeResult(uint256 proposalId, bytes32 counterEvidenceHash) external;
    function resolveChallengedResult(uint256 proposalId, bool passed) external;
    function finalizeResult(uint256 proposalId) external;
    function getSettlement(uint256 proposalId) external view returns (SettlementView memory);
}
