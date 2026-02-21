// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IParameterManager} from "./interfaces/IParameterManager.sol";
import {OwnableBootstrap} from "./utils/OwnableBootstrap.sol";

contract ParameterManager is IParameterManager, OwnableBootstrap {
    error NotGovernanceExecutor();
    error GovernanceExecutorAlreadySet();
    error GovernanceAlreadyInitialized();
    error InvalidThresholds();
    error InvalidSnapshotSpaceHash();

    uint16 internal constant BPS_DENOMINATOR = 10_000;
    uint16 internal constant CONSTITUTION_MIN_QUORUM_BPS = 1_500;
    uint16 internal constant CONSTITUTION_MIN_SUPER_MAJORITY_BPS = 6_700;
    uint16 internal constant CONSTITUTION_MAX_SLASHING_BPS = 5_000;
    uint64 internal constant CONSTITUTION_MIN_TIMELOCK = 1 hours;

    address public override governanceExecutor;
    address public override treasury;
    address public override compensationPool;
    address public override burnAddress;

    uint16 public override proposalThresholdBps;
    uint16 public override quorumBps;
    uint16 public override majorityBps;
    uint16 public override superMajorityBps;
    uint16 public override slashingQuorumBps;
    uint16 public override maxSlashingBps;

    uint64 public override oracleChallengeWindow;
    uint64 public override timelockDuration;
    uint64 public override slashingExecutionCooldown;
    uint64 public override highImpactTimelockDuration;
    uint64 public override emergencyPauseMaxDuration;
    uint256 public override proposalBond;
    bytes32 public override snapshotSpaceHash;

    mapping(address => bool) private _approvedTargets;
    mapping(address => bool) private _highImpactTargets;

    event GovernanceExecutorSet(address indexed executor);
    event GovernanceParamsUpdated(
        uint16 proposalThresholdBps,
        uint16 quorumBps,
        uint16 majorityBps,
        uint16 superMajorityBps,
        uint16 slashingQuorumBps,
        uint16 maxSlashingBps,
        uint64 oracleChallengeWindow,
        uint64 timelockDuration,
        uint64 slashingExecutionCooldown,
        uint64 highImpactTimelockDuration,
        uint64 emergencyPauseMaxDuration,
        uint256 proposalBond
    );
    event TargetApprovalSet(address indexed target, bool approved);
    event HighImpactTargetSet(address indexed target, bool highImpact);
    event TreasurySet(address indexed treasury);
    event CompensationPoolSet(address indexed compensationPool);
    event BurnAddressSet(address indexed burnAddress);
    event SnapshotSpaceHashSet(bytes32 indexed snapshotSpaceHash);

    modifier onlyGovernanceExecutor() {
        if (msg.sender != governanceExecutor) revert NotGovernanceExecutor();
        _;
    }

    constructor(
        address initialBootstrapOwner,
        GovernanceParams memory initialParams,
        address initialTreasury,
        address initialCompensationPool,
        address initialBurnAddress,
        bytes32 initialSnapshotSpaceHash
    ) OwnableBootstrap(initialBootstrapOwner) {
        if (initialTreasury == address(0) || initialBurnAddress == address(0)) revert ZeroAddress();
        if (initialSnapshotSpaceHash == bytes32(0)) revert InvalidSnapshotSpaceHash();

        _validateParams(initialParams);

        treasury = initialTreasury;
        compensationPool = initialCompensationPool;
        burnAddress = initialBurnAddress;
        snapshotSpaceHash = initialSnapshotSpaceHash;

        _setParams(initialParams);
        emit SnapshotSpaceHashSet(initialSnapshotSpaceHash);
    }

    function isTargetApproved(address target) external view override returns (bool) {
        return _approvedTargets[target];
    }

    function isHighImpactTarget(address target) external view override returns (bool) {
        return _highImpactTargets[target];
    }

    function setGovernanceExecutor(address executor) external override onlyBootstrapOwner {
        if (executor == address(0)) revert ZeroAddress();
        if (governanceExecutor != address(0)) revert GovernanceExecutorAlreadySet();

        governanceExecutor = executor;
        emit GovernanceExecutorSet(executor);
    }

    function bootstrapSetTargetApproval(address target, bool approved) external onlyBootstrapOwner {
        if (governanceExecutor != address(0)) revert GovernanceAlreadyInitialized();
        if (target == address(0)) revert ZeroAddress();
        _approvedTargets[target] = approved;
        emit TargetApprovalSet(target, approved);
    }

    function bootstrapSetHighImpactTarget(address target, bool highImpact) external onlyBootstrapOwner {
        if (governanceExecutor != address(0)) revert GovernanceAlreadyInitialized();
        if (target == address(0)) revert ZeroAddress();
        _highImpactTargets[target] = highImpact;
        emit HighImpactTargetSet(target, highImpact);
    }

    function updateGovernanceParams(GovernanceParams calldata newParams) external override onlyGovernanceExecutor {
        _validateParams(newParams);
        _setParams(newParams);
    }

    function setTargetApproval(address target, bool approved) external override onlyGovernanceExecutor {
        if (target == address(0)) revert ZeroAddress();
        _approvedTargets[target] = approved;
        emit TargetApprovalSet(target, approved);
    }

    function setHighImpactTarget(address target, bool highImpact) external override onlyGovernanceExecutor {
        if (target == address(0)) revert ZeroAddress();
        _highImpactTargets[target] = highImpact;
        emit HighImpactTargetSet(target, highImpact);
    }

    function setTreasury(address newTreasury) external override onlyGovernanceExecutor {
        if (newTreasury == address(0)) revert ZeroAddress();
        treasury = newTreasury;
        emit TreasurySet(newTreasury);
    }

    function setCompensationPool(address newCompensationPool) external override onlyGovernanceExecutor {
        compensationPool = newCompensationPool;
        emit CompensationPoolSet(newCompensationPool);
    }

    function setBurnAddress(address newBurnAddress) external override onlyGovernanceExecutor {
        if (newBurnAddress == address(0)) revert ZeroAddress();
        burnAddress = newBurnAddress;
        emit BurnAddressSet(newBurnAddress);
    }

    function setSnapshotSpaceHash(bytes32 newSnapshotSpaceHash) external override onlyGovernanceExecutor {
        if (newSnapshotSpaceHash == bytes32(0)) revert InvalidSnapshotSpaceHash();
        snapshotSpaceHash = newSnapshotSpaceHash;
        emit SnapshotSpaceHashSet(newSnapshotSpaceHash);
    }

    function _setParams(GovernanceParams memory params) internal {
        proposalThresholdBps = params.proposalThresholdBps;
        quorumBps = params.quorumBps;
        majorityBps = params.majorityBps;
        superMajorityBps = params.superMajorityBps;
        slashingQuorumBps = params.slashingQuorumBps;
        maxSlashingBps = params.maxSlashingBps;
        oracleChallengeWindow = params.oracleChallengeWindow;
        timelockDuration = params.timelockDuration;
        slashingExecutionCooldown = params.slashingExecutionCooldown;
        highImpactTimelockDuration = params.highImpactTimelockDuration;
        emergencyPauseMaxDuration = params.emergencyPauseMaxDuration;
        proposalBond = params.proposalBond;

        emit GovernanceParamsUpdated(
            params.proposalThresholdBps,
            params.quorumBps,
            params.majorityBps,
            params.superMajorityBps,
            params.slashingQuorumBps,
            params.maxSlashingBps,
            params.oracleChallengeWindow,
            params.timelockDuration,
            params.slashingExecutionCooldown,
            params.highImpactTimelockDuration,
            params.emergencyPauseMaxDuration,
            params.proposalBond
        );
    }

    function _validateParams(GovernanceParams memory params) internal pure {
        if (
            params.proposalThresholdBps == 0 ||
            params.proposalThresholdBps > BPS_DENOMINATOR ||
            params.quorumBps == 0 ||
            params.quorumBps > BPS_DENOMINATOR ||
            params.majorityBps <= (BPS_DENOMINATOR / 2) ||
            params.majorityBps > BPS_DENOMINATOR ||
            params.superMajorityBps < params.majorityBps ||
            params.superMajorityBps > BPS_DENOMINATOR ||
            params.superMajorityBps < CONSTITUTION_MIN_SUPER_MAJORITY_BPS ||
            params.slashingQuorumBps < params.quorumBps ||
            params.slashingQuorumBps > BPS_DENOMINATOR ||
            params.quorumBps < CONSTITUTION_MIN_QUORUM_BPS ||
            params.maxSlashingBps == 0 ||
            params.maxSlashingBps > BPS_DENOMINATOR ||
            params.maxSlashingBps > CONSTITUTION_MAX_SLASHING_BPS ||
            params.timelockDuration < CONSTITUTION_MIN_TIMELOCK ||
            params.emergencyPauseMaxDuration == 0
        ) {
            revert InvalidThresholds();
        }
    }
}
