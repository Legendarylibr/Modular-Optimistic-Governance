// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GovernanceExecutor} from "../../src/GovernanceExecutor.sol";
import {OracleAdapter} from "../../src/OracleAdapter.sol";
import {ParameterManager} from "../../src/ParameterManager.sol";
import {StakeManager} from "../../src/StakeManager.sol";
import {IGovernanceExecutor} from "../../src/interfaces/IGovernanceExecutor.sol";
import {IOracleAdapter} from "../../src/interfaces/IOracleAdapter.sol";
import {IParameterManager} from "../../src/interfaces/IParameterManager.sol";
import {IStakeManager} from "../../src/interfaces/IStakeManager.sol";
import {ISafe} from "../../src/interfaces/ISafe.sol";
import {MockERC20} from "../mocks/MockERC20.sol";
import {ForkCounter} from "../mocks/ForkCounter.sol";

interface Vm {
    function envExists(string calldata name) external view returns (bool);
    function envString(string calldata name) external view returns (string memory);
    function envAddress(string calldata name) external view returns (address);
    function envUint(string calldata name) external view returns (uint256);
    function addr(uint256 privateKey) external pure returns (address);
    function sign(uint256 privateKey, bytes32 digest) external pure returns (uint8 v, bytes32 r, bytes32 s);

    function createFork(string calldata urlOrAlias) external returns (uint256);
    function selectFork(uint256 forkId) external;

    function warp(uint256) external;
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
}

contract SafeModuleForkTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    bytes32 internal constant SALT = keccak256("safe-module-fork");
    bytes32 internal constant SNAPSHOT_SPACE_HASH = keccak256("dao.snapshot.eth");
    bytes32 internal constant SNAPSHOT_CONFIG_HASH = keccak256("snapshot-config:v1");

    bool internal configured;
    uint256 internal safeOwnerPk;
    address internal safeOwner;

    ISafe internal safe;

    MockERC20 internal token;
    ParameterManager internal parameterManager;
    StakeManager internal stakeManager;
    OracleAdapter internal oracleAdapter;
    GovernanceExecutor internal executor;
    ForkCounter internal counter;

    function setUp() public {
        if (!_hasForkEnv()) {
            configured = false;
            return;
        }

        configured = true;

        uint256 forkId = vm.createFork(vm.envString("FORK_RPC_URL"));
        vm.selectFork(forkId);

        safe = ISafe(vm.envAddress("SAFE_ADDRESS"));
        safeOwnerPk = vm.envUint("SAFE_OWNER_PK");
        safeOwner = vm.addr(safeOwnerPk);

        require(safe.getThreshold() == 1, "SAFE_THRESHOLD_NOT_1");
        require(_isSafeOwner(safeOwner), "SAFE_OWNER_PK_MISMATCH");

        token = new MockERC20("Gov", "GOV");
        counter = new ForkCounter();

        IParameterManager.GovernanceParams memory cfg = IParameterManager.GovernanceParams({
            proposalThresholdBps: 100,
            quorumBps: 2_000,
            majorityBps: 5_100,
            superMajorityBps: 6_700,
            slashingQuorumBps: 3_000,
            maxSlashingBps: 5_000,
            oracleChallengeWindow: 6 hours,
            timelockDuration: 2 hours,
            slashingExecutionCooldown: 4 hours,
            highImpactTimelockDuration: 2 hours,
            emergencyPauseMaxDuration: 24 hours,
            proposalBond: 1_000 ether
        });

        parameterManager = new ParameterManager(
            safeOwner,
            cfg,
            address(safe),
            address(0),
            address(0x000000000000000000000000000000000000dEaD),
            SNAPSHOT_SPACE_HASH,
            SNAPSHOT_CONFIG_HASH
        );
        stakeManager = new StakeManager(safeOwner, address(token), address(parameterManager));
        address[] memory initialAttesters = new address[](1);
        initialAttesters[0] = safeOwner;
        oracleAdapter = new OracleAdapter(address(stakeManager), address(parameterManager), initialAttesters, 1, 1 days);
        executor = new GovernanceExecutor(address(oracleAdapter), address(parameterManager), safeOwner);

        vm.startPrank(safeOwner);
        parameterManager.bootstrapSetTargetApproval(address(stakeManager), true);
        parameterManager.bootstrapSetTargetApproval(address(parameterManager), true);
        parameterManager.bootstrapSetTargetApproval(address(executor), true);
        parameterManager.bootstrapSetTargetApproval(address(safe), true);

        parameterManager.setGovernanceExecutor(address(executor));
        stakeManager.setGovernanceExecutor(address(executor));
        stakeManager.setOracleAdapter(address(oracleAdapter));
        vm.stopPrank();

        address voter = address(0xB0B);

        token.mint(safeOwner, 600_000 ether);
        token.mint(voter, 400_000 ether);

        vm.startPrank(safeOwner);
        token.approve(address(stakeManager), type(uint256).max);
        stakeManager.stake(500_000 ether);
        vm.stopPrank();

        vm.startPrank(voter);
        token.approve(address(stakeManager), type(uint256).max);
        stakeManager.stake(300_000 ether);
        vm.stopPrank();
    }

    function testForkSafeModuleEnablementAndGovernanceExecution() public {
        if (!configured) return;

        _enableExecutorAsSafeModule();
        require(safe.isModuleEnabled(address(executor)), "MODULE_NOT_ENABLED");

        uint256 proposalId = stakeManager.proposalCount() + 1;

        bytes memory downstreamCall = abi.encodeWithSelector(ForkCounter.setValue.selector, 777);
        bytes memory safeModuleCall = abi.encodeWithSelector(
            ISafe.execTransactionFromModule.selector,
            address(counter),
            0,
            downstreamCall,
            uint8(0)
        );

        IGovernanceExecutor.Transaction[] memory txs = new IGovernanceExecutor.Transaction[](1);
        txs[0] = IGovernanceExecutor.Transaction({target: address(safe), value: 0, data: safeModuleCall});

        bytes32 executionHash = executor.computeExecutionHash(proposalId, SALT, txs);

        vm.prank(safeOwner);
        stakeManager.registerProposal(
            executionHash,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            IStakeManager.ProposalType.Standard,
            address(0),
            0
        );

        _settlePassedProposal(proposalId, executionHash, 620_000 ether, 80_000 ether, 10_000 ether);

        vm.warp(block.timestamp + parameterManager.timelockDuration());
        require(_tryExecute(proposalId, SALT, txs), "EXECUTION_FAILED");
        require(counter.value() == 777, "SAFE_MODULE_CALL_NOT_EXECUTED");
    }

    function _enableExecutorAsSafeModule() internal {
        bytes memory data = abi.encodeWithSelector(ISafe.enableModule.selector, address(executor));
        bytes32 txHash = safe.getTransactionHash(
            address(safe),
            0,
            data,
            0,
            0,
            0,
            0,
            address(0),
            address(0),
            safe.nonce()
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(safeOwnerPk, txHash);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.prank(safeOwner);
        bool ok = safe.execTransaction(
            address(safe),
            0,
            data,
            0,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            sig
        );
        require(ok, "SAFE_ENABLE_MODULE_FAILED");
    }

    function _settlePassedProposal(
        uint256 proposalId,
        bytes32 executionHash,
        uint128 forVotes,
        uint128 againstVotes,
        uint128 abstainVotes
    ) internal {
        IStakeManager.ProposalView memory proposal = stakeManager.getProposal(proposalId);
        vm.warp(proposal.voteEnd);

        IOracleAdapter.SnapshotResult memory result = IOracleAdapter.SnapshotResult({
            proposalId: proposalId,
            executionHash: executionHash,
            snapshotProposalHash: keccak256(abi.encodePacked("snapshot-proposal:", proposalId)),
            snapshotSpaceHash: SNAPSHOT_SPACE_HASH,
            snapshotConfigHash: SNAPSHOT_CONFIG_HASH,
            snapshotBlock: proposal.snapshotBlock,
            forVotes: forVotes,
            againstVotes: againstVotes,
            abstainVotes: abstainVotes,
            totalStakedAtSnapshot: uint128(stakeManager.totalStakedAt(proposal.snapshotBlock)),
            passed: true,
            metadataHash: _metadataHash(proposalId, proposal.snapshotBlock, executionHash)
        });

        bytes32 resultHash = oracleAdapter.hashSnapshotResult(result);
        oracleAdapter.submitResultHash(proposalId, resultHash);
        oracleAdapter.proposeResult(result);
        vm.prank(safeOwner);
        oracleAdapter.attestResult(proposalId);

        vm.warp(block.timestamp + parameterManager.oracleChallengeWindow());
        oracleAdapter.finalizeResult(proposalId);
    }

    function _tryExecute(uint256 proposalId, bytes32 salt, IGovernanceExecutor.Transaction[] memory txs)
        internal
        returns (bool ok)
    {
        (ok,) = address(executor).call(abi.encodeCall(IGovernanceExecutor.executeBundle, (proposalId, salt, txs)));
    }

    function _isSafeOwner(address account) internal view returns (bool) {
        address[] memory owners = safe.getOwners();
        uint256 length = owners.length;
        for (uint256 i = 0; i < length; ++i) {
            if (owners[i] == account) {
                return true;
            }
        }
        return false;
    }

    function _hasForkEnv() internal view returns (bool) {
        return vm.envExists("FORK_RPC_URL") && vm.envExists("SAFE_ADDRESS") && vm.envExists("SAFE_OWNER_PK");
    }

    function _metadataHash(uint256 proposalId, uint64 snapshotBlock, bytes32 executionHash)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                keccak256(abi.encodePacked("snapshot-proposal:", proposalId)),
                SNAPSHOT_SPACE_HASH,
                proposalId,
                snapshotBlock,
                executionHash
            )
        );
    }
}
