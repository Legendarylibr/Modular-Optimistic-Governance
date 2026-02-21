// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IParameterManager {
    struct GovernanceParams {
        uint16 proposalThresholdBps;
        uint16 quorumBps;
        uint16 majorityBps;
        uint16 superMajorityBps;
        uint16 slashingQuorumBps;
        uint16 maxSlashingBps;
        uint64 oracleChallengeWindow;
        uint64 timelockDuration;
        uint64 slashingExecutionCooldown;
        uint64 highImpactTimelockDuration;
        uint64 emergencyPauseMaxDuration;
        uint256 proposalBond;
    }

    function governanceExecutor() external view returns (address);
    function treasury() external view returns (address);
    function compensationPool() external view returns (address);
    function burnAddress() external view returns (address);

    function proposalThresholdBps() external view returns (uint16);
    function quorumBps() external view returns (uint16);
    function majorityBps() external view returns (uint16);
    function superMajorityBps() external view returns (uint16);
    function slashingQuorumBps() external view returns (uint16);
    function maxSlashingBps() external view returns (uint16);
    function oracleChallengeWindow() external view returns (uint64);
    function timelockDuration() external view returns (uint64);
    function slashingExecutionCooldown() external view returns (uint64);
    function highImpactTimelockDuration() external view returns (uint64);
    function emergencyPauseMaxDuration() external view returns (uint64);
    function proposalBond() external view returns (uint256);
    function snapshotSpaceHash() external view returns (bytes32);
    function snapshotConfigHash() external view returns (bytes32);

    function isTargetApproved(address target) external view returns (bool);
    function isHighImpactTarget(address target) external view returns (bool);

    function setGovernanceExecutor(address executor) external;
    function updateGovernanceParams(GovernanceParams calldata newParams) external;
    function setTargetApproval(address target, bool approved) external;
    function setHighImpactTarget(address target, bool highImpact) external;
    function setTreasury(address newTreasury) external;
    function setCompensationPool(address newCompensationPool) external;
    function setBurnAddress(address newBurnAddress) external;
    function setSnapshotSpaceHash(bytes32 newSnapshotSpaceHash) external;
    function setSnapshotConfigHash(bytes32 newSnapshotConfigHash) external;
}
