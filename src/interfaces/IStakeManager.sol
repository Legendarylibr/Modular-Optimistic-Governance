// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IStakeManager {
    enum ProposalType {
        Standard,
        SlashNotice,
        SlashExecution,
        Appeal
    }

    enum SlashingDestination {
        Treasury,
        Burn,
        CompensationPool
    }

    struct ProposalView {
        address proposer;
        bytes32 executionHash;
        uint64 voteStart;
        uint64 voteEnd;
        uint64 snapshotBlock;
        ProposalType proposalType;
        address accused;
        uint16 maxSlashBps;
        bool exists;
    }

    function governanceToken() external view returns (address);
    function parameterManager() external view returns (address);
    function governanceExecutor() external view returns (address);
    function oracleAdapter() external view returns (address);

    function totalStaked() external view returns (uint256);
    function globalVoteLockUntil() external view returns (uint64);
    function proposalCount() external view returns (uint256);
    function stakeOf(address account) external view returns (uint256);
    function stakeAt(address account, uint256 blockNumber) external view returns (uint256);
    function totalStakedAt(uint256 blockNumber) external view returns (uint256);
    function lockedUntil(address account) external view returns (uint64);
    function delegateOf(address account) external view returns (address);
    function isFrozen(address account) external view returns (bool);
    function isFrozenAt(address account, uint256 blockNumber) external view returns (bool);
    function frozenAt(address account) external view returns (uint64);
    function votingPower(address account) external view returns (uint256);
    function votingPowerAt(address account, uint256 blockNumber) external view returns (uint256);
    function clock() external view returns (uint48);
    function CLOCK_MODE() external view returns (string memory);

    function getProposal(uint256 proposalId) external view returns (ProposalView memory);

    function setGovernanceExecutor(address executor) external;
    function setOracleAdapter(address adapter) external;
    function stake(uint256 amount) external;
    function unstake(uint256 amount) external;
    function delegate(address delegatee) external;
    function registerProposal(
        bytes32 executionHash,
        uint64 voteStart,
        uint64 voteEnd,
        ProposalType proposalType,
        address accused,
        uint16 maxSlashBps
    ) external returns (uint256 proposalId);
    function registerProposalWithSnapshot(
        bytes32 executionHash,
        uint64 voteStart,
        uint64 voteEnd,
        uint64 snapshotBlock,
        ProposalType proposalType,
        address accused,
        uint16 maxSlashBps
    ) external returns (uint256 proposalId);

    function freezeStake(address account, uint256 proposalId) external;
    function unfreezeStake(address account, uint256 proposalId) external;
    function slashStake(
        address account,
        uint16 slashBps,
        SlashingDestination destination,
        address destinationOverride,
        uint256 proposalId
    ) external returns (uint256 slashedAmount);
    function settleProposalBond(uint256 proposalId, bool passed) external;
}
