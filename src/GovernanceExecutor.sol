// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IGovernanceExecutor} from "./interfaces/IGovernanceExecutor.sol";
import {IOracleAdapter} from "./interfaces/IOracleAdapter.sol";
import {IParameterManager} from "./interfaces/IParameterManager.sol";
import {IStakeManager} from "./interfaces/IStakeManager.sol";
import {ReentrancyGuard} from "./utils/ReentrancyGuard.sol";

contract GovernanceExecutor is IGovernanceExecutor, ReentrancyGuard {
    error ZeroAddress();
    error EmptyBundle();
    error InvalidOracleSettlement();
    error HashMismatch();
    error AlreadyExecuted();
    error TimelockActive();
    error SlashingCooldownActive();
    error TargetNotApproved(address target);
    error ExecutionFailed(uint256 txIndex, bytes returnData);
    error InvalidMsgValue();
    error OnlySelf();
    error EmergencyPaused();
    error NotEmergencyGuardian();
    error InvalidEmergencyDuration();

    address public override oracleAdapter;
    address public override parameterManager;
    address public override emergencyGuardian;
    uint64 public override emergencyPauseUntil;

    mapping(bytes32 => bool) public executionHashExecuted;
    mapping(uint256 => bool) public proposalExecuted;

    event BundleExecuted(uint256 indexed proposalId, bytes32 indexed executionHash, address indexed caller);
    event TransactionExecuted(uint256 indexed proposalId, uint256 indexed txIndex, address indexed target, uint256 value);
    event OracleAdapterUpdated(address indexed oldOracleAdapter, address indexed newOracleAdapter);
    event ParameterManagerUpdated(address indexed oldParameterManager, address indexed newParameterManager);
    event EmergencyGuardianUpdated(address indexed oldGuardian, address indexed newGuardian);
    event EmergencyPauseTriggered(address indexed guardian, uint64 pauseUntil);
    event EmergencyPauseCleared();

    modifier onlySelf() {
        if (msg.sender != address(this)) revert OnlySelf();
        _;
    }

    modifier onlyEmergencyGuardian() {
        if (msg.sender != emergencyGuardian) revert NotEmergencyGuardian();
        _;
    }

    constructor(address initialOracleAdapter, address initialParameterManager, address initialEmergencyGuardian) {
        if (initialOracleAdapter == address(0) || initialParameterManager == address(0)) revert ZeroAddress();
        oracleAdapter = initialOracleAdapter;
        parameterManager = initialParameterManager;
        emergencyGuardian = initialEmergencyGuardian;
    }

    receive() external payable {}

    function computeExecutionHash(uint256 proposalId, bytes32 salt, Transaction[] calldata txs)
        public
        view
        override
        returns (bytes32)
    {
        bytes32 txsHash = keccak256(_hashTransactions(txs));
        return keccak256(abi.encode(address(this), block.chainid, proposalId, salt, txsHash));
    }

    function executeBundle(uint256 proposalId, bytes32 salt, Transaction[] calldata txs)
        external
        payable
        override
        nonReentrant
    {
        _executeBundle(proposalId, salt, txs);
    }

    function finalizeAndExecuteBundle(uint256 proposalId, bytes32 salt, Transaction[] calldata txs)
        external
        payable
        override
        nonReentrant
    {
        IOracleAdapter.SettlementView memory settlement = IOracleAdapter(oracleAdapter).getSettlement(proposalId);
        if (!settlement.finalized) {
            IOracleAdapter(oracleAdapter).finalizeResult(proposalId);
        }
        _executeBundle(proposalId, salt, txs);
    }

    function setOracleAdapter(address newOracleAdapter) external override onlySelf {
        if (newOracleAdapter == address(0)) revert ZeroAddress();

        address oldOracleAdapter = oracleAdapter;
        oracleAdapter = newOracleAdapter;

        emit OracleAdapterUpdated(oldOracleAdapter, newOracleAdapter);
    }

    function setParameterManager(address newParameterManager) external override onlySelf {
        if (newParameterManager == address(0)) revert ZeroAddress();

        address oldParameterManager = parameterManager;
        parameterManager = newParameterManager;

        emit ParameterManagerUpdated(oldParameterManager, newParameterManager);
    }

    function setEmergencyGuardian(address newEmergencyGuardian) external override onlySelf {
        if (newEmergencyGuardian == address(0)) revert ZeroAddress();

        address oldGuardian = emergencyGuardian;
        emergencyGuardian = newEmergencyGuardian;
        emit EmergencyGuardianUpdated(oldGuardian, newEmergencyGuardian);
    }

    function removeEmergencyGuardian() external override onlySelf {
        address oldGuardian = emergencyGuardian;
        emergencyGuardian = address(0);
        emit EmergencyGuardianUpdated(oldGuardian, address(0));
    }

    function clearEmergencyPause() external override onlySelf {
        emergencyPauseUntil = 0;
        emit EmergencyPauseCleared();
    }

    function triggerEmergencyPause(uint64 duration) external override onlyEmergencyGuardian {
        if (duration == 0 || duration > IParameterManager(parameterManager).emergencyPauseMaxDuration()) {
            revert InvalidEmergencyDuration();
        }

        uint64 newPauseUntil = uint64(block.timestamp + duration);
        if (newPauseUntil > emergencyPauseUntil) {
            emergencyPauseUntil = newPauseUntil;
            emit EmergencyPauseTriggered(msg.sender, newPauseUntil);
        }
    }

    function _hashTransactions(Transaction[] calldata txs) internal pure returns (bytes memory encoded) {
        uint256 length = txs.length;
        bytes32[] memory txHashes = new bytes32[](length);

        for (uint256 i = 0; i < length; ++i) {
            txHashes[i] = keccak256(abi.encode(txs[i].target, txs[i].value, keccak256(txs[i].data)));
        }

        encoded = abi.encode(txHashes);
    }

    function _executeBundle(uint256 proposalId, bytes32 salt, Transaction[] calldata txs) internal {
        if (txs.length == 0) revert EmptyBundle();
        if (proposalExecuted[proposalId]) revert AlreadyExecuted();

        IOracleAdapter.SettlementView memory settlement = IOracleAdapter(oracleAdapter).getSettlement(proposalId);
        if (!settlement.finalized || !settlement.passed || settlement.challenged) revert InvalidOracleSettlement();
        if (
            emergencyPauseUntil > block.timestamp
                && settlement.proposalType != uint8(IStakeManager.ProposalType.Appeal)
        ) revert EmergencyPaused();

        bytes32 executionHash = computeExecutionHash(proposalId, salt, txs);
        if (executionHash != settlement.executionHash) revert HashMismatch();
        if (executionHashExecuted[executionHash]) revert AlreadyExecuted();

        uint256 timelock = IParameterManager(parameterManager).timelockDuration();
        if (_isHighImpactBundle(txs)) {
            timelock += IParameterManager(parameterManager).highImpactTimelockDuration();
        }
        if (block.timestamp < uint256(settlement.finalizedAt) + timelock) revert TimelockActive();

        if (settlement.proposalType == 2) {
            uint256 cooldown = IParameterManager(parameterManager).slashingExecutionCooldown();
            if (block.timestamp < uint256(settlement.finalizedAt) + cooldown) {
                revert SlashingCooldownActive();
            }
        }

        uint256 totalValue;
        uint256 length = txs.length;
        for (uint256 i = 0; i < length; ++i) {
            totalValue += txs[i].value;
        }
        if (totalValue != msg.value) revert InvalidMsgValue();

        executionHashExecuted[executionHash] = true;
        proposalExecuted[proposalId] = true;

        for (uint256 i = 0; i < length; ++i) {
            Transaction calldata txn = txs[i];
            if (txn.target != address(this) && !IParameterManager(parameterManager).isTargetApproved(txn.target)) {
                revert TargetNotApproved(txn.target);
            }

            (bool success, bytes memory returnData) = txn.target.call{value: txn.value}(txn.data);
            if (!success) revert ExecutionFailed(i, returnData);

            emit TransactionExecuted(proposalId, i, txn.target, txn.value);
        }

        emit BundleExecuted(proposalId, executionHash, msg.sender);
    }

    function _isHighImpactBundle(Transaction[] calldata txs) internal view returns (bool) {
        uint256 length = txs.length;
        for (uint256 i = 0; i < length; ++i) {
            address target = txs[i].target;
            if (target == address(this)) return true;
            if (IParameterManager(parameterManager).isHighImpactTarget(target)) return true;
        }
        return false;
    }
}
