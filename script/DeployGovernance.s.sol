// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GovernanceExecutor} from "../src/GovernanceExecutor.sol";
import {OracleAdapter} from "../src/OracleAdapter.sol";
import {ParameterManager} from "../src/ParameterManager.sol";
import {StakeManager} from "../src/StakeManager.sol";
import {IParameterManager} from "../src/interfaces/IParameterManager.sol";

interface Vm {
    function envExists(string calldata name) external view returns (bool);
    function envAddress(string calldata name) external view returns (address);
    function envBytes32(string calldata name) external view returns (bytes32);
    function envUint(string calldata name) external view returns (uint256);
    function addr(uint256 privateKey) external pure returns (address);
    function startBroadcast(uint256 privateKey) external;
    function stopBroadcast() external;
}

contract DeployGovernance {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    struct Deployment {
        ParameterManager parameterManager;
        StakeManager stakeManager;
        OracleAdapter oracleAdapter;
        GovernanceExecutor governanceExecutor;
    }

    function run() external returns (Deployment memory deployed) {
        uint256 deployerPk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address deployer = vm.addr(deployerPk);

        address governanceToken = vm.envAddress("GOV_TOKEN");
        address treasury = vm.envAddress("TREASURY");
        address compensationPool = vm.envAddress("COMPENSATION_POOL");
        address burnAddress = vm.envAddress("BURN_ADDRESS");
        bytes32 snapshotSpaceHash = vm.envBytes32("SNAPSHOT_SPACE_HASH");

        IParameterManager.GovernanceParams memory params = IParameterManager.GovernanceParams({
            proposalThresholdBps: uint16(vm.envUint("PROPOSAL_THRESHOLD_BPS")),
            quorumBps: uint16(vm.envUint("QUORUM_BPS")),
            majorityBps: uint16(vm.envUint("MAJORITY_BPS")),
            superMajorityBps: uint16(vm.envUint("SUPER_MAJORITY_BPS")),
            slashingQuorumBps: uint16(vm.envUint("SLASHING_QUORUM_BPS")),
            maxSlashingBps: uint16(vm.envUint("MAX_SLASHING_BPS")),
            oracleChallengeWindow: uint64(vm.envUint("ORACLE_CHALLENGE_WINDOW")),
            timelockDuration: uint64(vm.envUint("TIMELOCK_DURATION")),
            slashingExecutionCooldown: uint64(vm.envUint("SLASHING_EXECUTION_COOLDOWN")),
            highImpactTimelockDuration: uint64(vm.envUint("HIGH_IMPACT_TIMELOCK_DURATION")),
            emergencyPauseMaxDuration: uint64(vm.envUint("EMERGENCY_PAUSE_MAX_DURATION")),
            proposalBond: vm.envUint("PROPOSAL_BOND")
        });

        uint8 attesterThreshold = uint8(vm.envUint("ORACLE_ATTESTER_THRESHOLD"));
        uint64 fallbackDelay = uint64(vm.envUint("ORACLE_FALLBACK_FINALIZATION_DELAY"));
        address emergencyGuardian = vm.envAddress("EMERGENCY_GUARDIAN");
        address[] memory initialAttesters = new address[](1);
        initialAttesters[0] = vm.envAddress("ORACLE_ATTESTER_1");

        vm.startBroadcast(deployerPk);

        deployed.parameterManager = new ParameterManager(
            deployer,
            params,
            treasury,
            compensationPool,
            burnAddress,
            snapshotSpaceHash
        );

        deployed.stakeManager = new StakeManager(
            deployer,
            governanceToken,
            address(deployed.parameterManager)
        );

        deployed.oracleAdapter = new OracleAdapter(
            address(deployed.stakeManager),
            address(deployed.parameterManager),
            initialAttesters,
            attesterThreshold,
            fallbackDelay
        );

        deployed.governanceExecutor = new GovernanceExecutor(
            address(deployed.oracleAdapter),
            address(deployed.parameterManager),
            emergencyGuardian
        );

        deployed.parameterManager.bootstrapSetTargetApproval(address(deployed.stakeManager), true);
        deployed.parameterManager.bootstrapSetTargetApproval(address(deployed.parameterManager), true);

        // Initial target controls for governance wiring.
        deployed.parameterManager.bootstrapSetTargetApproval(address(deployed.governanceExecutor), true);
        deployed.parameterManager.bootstrapSetHighImpactTarget(address(deployed.parameterManager), true);
        deployed.parameterManager.bootstrapSetHighImpactTarget(address(deployed.stakeManager), true);
        deployed.parameterManager.bootstrapSetHighImpactTarget(address(deployed.governanceExecutor), true);
        if (vm.envExists("SAFE_ADDRESS")) {
            deployed.parameterManager.bootstrapSetTargetApproval(vm.envAddress("SAFE_ADDRESS"), true);
            deployed.parameterManager.bootstrapSetHighImpactTarget(vm.envAddress("SAFE_ADDRESS"), true);
        }

        deployed.parameterManager.setGovernanceExecutor(address(deployed.governanceExecutor));
        deployed.stakeManager.setGovernanceExecutor(address(deployed.governanceExecutor));
        deployed.stakeManager.setOracleAdapter(address(deployed.oracleAdapter));

        vm.stopBroadcast();
    }
}
