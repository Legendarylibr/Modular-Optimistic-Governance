// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IGovernanceExecutor {
    struct Transaction {
        address target;
        uint256 value;
        bytes data;
    }

    function oracleAdapter() external view returns (address);
    function parameterManager() external view returns (address);
    function emergencyGuardian() external view returns (address);
    function emergencyPauseUntil() external view returns (uint64);

    function computeExecutionHash(
        uint256 proposalId,
        bytes32 salt,
        Transaction[] calldata txs
    ) external view returns (bytes32);

    function executeBundle(
        uint256 proposalId,
        bytes32 salt,
        Transaction[] calldata txs
    ) external payable;
    function finalizeAndExecuteBundle(
        uint256 proposalId,
        bytes32 salt,
        Transaction[] calldata txs
    ) external payable;

    function setOracleAdapter(address newOracleAdapter) external;
    function setParameterManager(address newParameterManager) external;
    function setEmergencyGuardian(address newEmergencyGuardian) external;
    function removeEmergencyGuardian() external;
    function clearEmergencyPause() external;
    function triggerEmergencyPause(uint64 duration) external;
}
