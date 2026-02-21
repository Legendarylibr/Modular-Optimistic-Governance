// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {GovernanceExecutor} from "../src/GovernanceExecutor.sol";
import {OracleAdapter} from "../src/OracleAdapter.sol";
import {ParameterManager} from "../src/ParameterManager.sol";
import {StakeManager} from "../src/StakeManager.sol";
import {IGovernanceExecutor} from "../src/interfaces/IGovernanceExecutor.sol";
import {IOracleAdapter} from "../src/interfaces/IOracleAdapter.sol";
import {IParameterManager} from "../src/interfaces/IParameterManager.sol";
import {IStakeManager} from "../src/interfaces/IStakeManager.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {MockTarget} from "./mocks/MockTarget.sol";

interface Vm {
    function warp(uint256) external;
    function roll(uint256) external;
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
}

contract GovernanceSystemTest {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    MockERC20 internal token;
    ParameterManager internal parameterManager;
    StakeManager internal stakeManager;
    OracleAdapter internal oracleAdapter;
    GovernanceExecutor internal executor;
    MockTarget internal target;

    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);
    address internal constant CAROL = address(0xCA101);
    address internal constant TREASURY = address(0x7100);
    address internal constant COMP_POOL = address(0x7700);
    address internal constant BURN = address(0x000000000000000000000000000000000000dEaD);

    bytes32 internal constant SALT_A = keccak256("salt-a");
    bytes32 internal constant SALT_B = keccak256("salt-b");
    bytes32 internal constant SNAPSHOT_SPACE_HASH = keccak256("dao.snapshot.eth");

    function setUp() public {
        token = new MockERC20("Gov", "GOV");
        target = new MockTarget();

        IParameterManager.GovernanceParams memory config = IParameterManager.GovernanceParams({
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

        parameterManager = new ParameterManager(address(this), config, TREASURY, COMP_POOL, BURN, SNAPSHOT_SPACE_HASH);
        stakeManager = new StakeManager(address(this), address(token), address(parameterManager));
        address[] memory initialAttesters = new address[](1);
        initialAttesters[0] = address(this);
        oracleAdapter = new OracleAdapter(address(stakeManager), address(parameterManager), initialAttesters, 1, 1 days);
        executor = new GovernanceExecutor(address(oracleAdapter), address(parameterManager), address(this));

        parameterManager.bootstrapSetTargetApproval(address(stakeManager), true);
        parameterManager.bootstrapSetTargetApproval(address(parameterManager), true);
        parameterManager.bootstrapSetTargetApproval(address(target), true);

        parameterManager.setGovernanceExecutor(address(executor));
        stakeManager.setGovernanceExecutor(address(executor));
        stakeManager.setOracleAdapter(address(oracleAdapter));

        token.mint(ALICE, 1_000_000 ether);
        token.mint(BOB, 1_000_000 ether);
        token.mint(CAROL, 1_000_000 ether);

        vm.startPrank(ALICE);
        token.approve(address(stakeManager), type(uint256).max);
        stakeManager.stake(300_000 ether);
        vm.stopPrank();

        vm.startPrank(BOB);
        token.approve(address(stakeManager), type(uint256).max);
        stakeManager.stake(300_000 ether);
        vm.stopPrank();

        vm.startPrank(CAROL);
        token.approve(address(stakeManager), type(uint256).max);
        stakeManager.stake(300_000 ether);
        vm.stopPrank();
    }

    function testStandardProposalExecution() public {
        uint256 proposalId = stakeManager.proposalCount() + 1;

        IGovernanceExecutor.Transaction[] memory txs = new IGovernanceExecutor.Transaction[](1);
        txs[0] = IGovernanceExecutor.Transaction({
            target: address(target),
            value: 0,
            data: abi.encodeWithSelector(MockTarget.setNumber.selector, 42, bytes32("standard"))
        });

        bytes32 executionHash = executor.computeExecutionHash(proposalId, SALT_A, txs);

        vm.prank(ALICE);
        stakeManager.registerProposal(
            executionHash,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            IStakeManager.ProposalType.Standard,
            address(0),
            0
        );

        _settlePassedProposal(proposalId, executionHash, IStakeManager.ProposalType.Standard, 500_000 ether, 100_000 ether, 10_000 ether);

        vm.warp(block.timestamp + parameterManager.timelockDuration());
        bool ok = _tryExecute(proposalId, SALT_A, txs);
        require(ok, "execution failed");

        require(target.number() == 42, "target state mismatch");
        require(executor.proposalExecuted(proposalId), "proposal not marked executed");
    }

    function testReplayAndDoubleExecutionPrevention() public {
        uint256 proposalId = stakeManager.proposalCount() + 1;

        IGovernanceExecutor.Transaction[] memory txs = new IGovernanceExecutor.Transaction[](1);
        txs[0] = IGovernanceExecutor.Transaction({
            target: address(target),
            value: 0,
            data: abi.encodeWithSelector(MockTarget.setNumber.selector, 7, bytes32("once"))
        });

        bytes32 executionHash = executor.computeExecutionHash(proposalId, SALT_B, txs);

        vm.prank(ALICE);
        stakeManager.registerProposal(
            executionHash,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            IStakeManager.ProposalType.Standard,
            address(0),
            0
        );

        _settlePassedProposal(proposalId, executionHash, IStakeManager.ProposalType.Standard, 450_000 ether, 100_000 ether, 10_000 ether);
        vm.warp(block.timestamp + parameterManager.timelockDuration());

        require(_tryExecute(proposalId, SALT_B, txs), "first execution should pass");
        require(!_tryExecute(proposalId, SALT_B, txs), "second execution should revert");
    }

    function testRejectsUnapprovedTargets() public {
        MockTarget unapproved = new MockTarget();
        uint256 proposalId = stakeManager.proposalCount() + 1;

        IGovernanceExecutor.Transaction[] memory txs = new IGovernanceExecutor.Transaction[](1);
        txs[0] = IGovernanceExecutor.Transaction({
            target: address(unapproved),
            value: 0,
            data: abi.encodeWithSelector(MockTarget.setNumber.selector, 99, bytes32("blocked"))
        });

        bytes32 executionHash = executor.computeExecutionHash(proposalId, SALT_A, txs);

        vm.prank(ALICE);
        stakeManager.registerProposal(
            executionHash,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            IStakeManager.ProposalType.Standard,
            address(0),
            0
        );

        _settlePassedProposal(proposalId, executionHash, IStakeManager.ProposalType.Standard, 600_000 ether, 50_000 ether, 10_000 ether);
        vm.warp(block.timestamp + parameterManager.timelockDuration());

        require(!_tryExecute(proposalId, SALT_A, txs), "unapproved target should fail");
        require(unapproved.number() == 0, "unexpected target mutation");
    }

    function testChallengeBlocksFinalization() public {
        uint256 proposalId = stakeManager.proposalCount() + 1;

        IGovernanceExecutor.Transaction[] memory txs = new IGovernanceExecutor.Transaction[](1);
        txs[0] = IGovernanceExecutor.Transaction({
            target: address(target),
            value: 0,
            data: abi.encodeWithSelector(MockTarget.setNumber.selector, 5, bytes32("challenge"))
        });

        bytes32 executionHash = executor.computeExecutionHash(proposalId, SALT_A, txs);

        vm.prank(ALICE);
        stakeManager.registerProposal(
            executionHash,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            IStakeManager.ProposalType.Standard,
            address(0),
            0
        );

        IStakeManager.ProposalView memory proposal = stakeManager.getProposal(proposalId);
        vm.warp(proposal.voteEnd);

        IOracleAdapter.SnapshotResult memory result = IOracleAdapter.SnapshotResult({
            proposalId: proposalId,
            executionHash: executionHash,
            snapshotProposalHash: keccak256(abi.encodePacked("snapshot-proposal:", proposalId)),
            snapshotSpaceHash: SNAPSHOT_SPACE_HASH,
            snapshotBlock: proposal.snapshotBlock,
            forVotes: 500_000 ether,
            againstVotes: 80_000 ether,
            abstainVotes: 10_000 ether,
            totalStakedAtSnapshot: uint128(stakeManager.totalStakedAt(proposal.snapshotBlock)),
            passed: true,
            metadataHash: _metadataHash(proposalId, proposal.snapshotBlock, executionHash)
        });

        bytes32 resultHash = oracleAdapter.hashSnapshotResult(result);
        oracleAdapter.submitResultHash(proposalId, resultHash);
        oracleAdapter.proposeResult(result);

        vm.prank(BOB);
        oracleAdapter.challengeResult(proposalId, keccak256("counter-evidence"));

        vm.warp(block.timestamp + parameterManager.oracleChallengeWindow());

        (bool ok,) = address(oracleAdapter).call(abi.encodeCall(IOracleAdapter.finalizeResult, (proposalId)));
        require(!ok, "challenged result should not finalize");
    }

    function testTwoPhaseSlashingFlow() public {
        uint256 noticeProposalId = stakeManager.proposalCount() + 1;

        IGovernanceExecutor.Transaction[] memory noticeTxs = new IGovernanceExecutor.Transaction[](1);
        noticeTxs[0] = IGovernanceExecutor.Transaction({
            target: address(stakeManager),
            value: 0,
            data: abi.encodeWithSelector(StakeManager.freezeStake.selector, CAROL, noticeProposalId)
        });

        bytes32 noticeExecutionHash = executor.computeExecutionHash(noticeProposalId, SALT_A, noticeTxs);

        vm.prank(ALICE);
        stakeManager.registerProposal(
            noticeExecutionHash,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            IStakeManager.ProposalType.SlashNotice,
            CAROL,
            0
        );

        _settlePassedProposal(
            noticeProposalId,
            noticeExecutionHash,
            IStakeManager.ProposalType.SlashNotice,
            520_000 ether,
            120_000 ether,
            10_000 ether
        );

        vm.warp(block.timestamp + parameterManager.timelockDuration());
        require(_tryExecute(noticeProposalId, SALT_A, noticeTxs), "freeze execution failed");
        require(stakeManager.isFrozen(CAROL), "carol not frozen");
        require(stakeManager.votingPower(CAROL) == 0, "frozen stake should not vote");

        uint256 slashProposalId = stakeManager.proposalCount() + 1;

        IGovernanceExecutor.Transaction[] memory slashTxs = new IGovernanceExecutor.Transaction[](1);
        slashTxs[0] = IGovernanceExecutor.Transaction({
            target: address(stakeManager),
            value: 0,
            data: abi.encodeWithSelector(
                StakeManager.slashStake.selector,
                CAROL,
                uint16(2_000),
                IStakeManager.SlashingDestination.Treasury,
                address(0),
                slashProposalId
            )
        });

        bytes32 slashExecutionHash = executor.computeExecutionHash(slashProposalId, SALT_B, slashTxs);

        vm.prank(BOB);
        stakeManager.registerProposal(
            slashExecutionHash,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            IStakeManager.ProposalType.SlashExecution,
            CAROL,
            2_500
        );

        uint256 treasuryBefore = token.balanceOf(TREASURY);
        uint256 carolStakeBefore = stakeManager.stakeOf(CAROL);

        _settlePassedProposal(
            slashProposalId,
            slashExecutionHash,
            IStakeManager.ProposalType.SlashExecution,
            610_000 ether,
            80_000 ether,
            15_000 ether
        );

        vm.warp(block.timestamp + parameterManager.slashingExecutionCooldown());
        require(_tryExecute(slashProposalId, SALT_B, slashTxs), "slash execution failed");

        uint256 expectedSlash = (carolStakeBefore * 2_000) / 10_000;
        require(token.balanceOf(TREASURY) == treasuryBefore + expectedSlash, "treasury did not receive slash");
        require(stakeManager.stakeOf(CAROL) == carolStakeBefore - expectedSlash, "stake not reduced");
    }

    function testOracleUpdateRequiresGovernanceExecution() public {
        address[] memory replacementAttesters = new address[](1);
        replacementAttesters[0] = address(this);
        OracleAdapter replacement =
            new OracleAdapter(address(stakeManager), address(parameterManager), replacementAttesters, 1, 1 days);

        (bool directOk,) =
            address(executor).call(abi.encodeCall(IGovernanceExecutor.setOracleAdapter, (address(replacement))));
        require(!directOk, "direct oracle update should fail");

        uint256 proposalId = stakeManager.proposalCount() + 1;
        IGovernanceExecutor.Transaction[] memory txs = new IGovernanceExecutor.Transaction[](1);
        txs[0] = IGovernanceExecutor.Transaction({
            target: address(executor),
            value: 0,
            data: abi.encodeWithSelector(IGovernanceExecutor.setOracleAdapter.selector, address(replacement))
        });

        bytes32 executionHash = executor.computeExecutionHash(proposalId, keccak256("oracle-upgrade"), txs);

        vm.prank(ALICE);
        stakeManager.registerProposal(
            executionHash,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            IStakeManager.ProposalType.Standard,
            address(0),
            0
        );

        _settlePassedProposal(proposalId, executionHash, IStakeManager.ProposalType.Standard, 550_000 ether, 60_000 ether, 10_000 ether);

        vm.warp(block.timestamp + parameterManager.timelockDuration() + parameterManager.highImpactTimelockDuration());
        require(_tryExecute(proposalId, keccak256("oracle-upgrade"), txs), "governance oracle update failed");
        require(executor.oracleAdapter() == address(replacement), "oracle not updated");
    }

    function testOracleRejectsSnapshotBindingMismatch() public {
        uint256 proposalId = stakeManager.proposalCount() + 1;

        IGovernanceExecutor.Transaction[] memory txs = new IGovernanceExecutor.Transaction[](1);
        txs[0] = IGovernanceExecutor.Transaction({
            target: address(target),
            value: 0,
            data: abi.encodeWithSelector(MockTarget.setNumber.selector, 55, bytes32("snapshot-mismatch"))
        });

        bytes32 executionHash = executor.computeExecutionHash(proposalId, SALT_A, txs);

        vm.prank(ALICE);
        stakeManager.registerProposalWithSnapshot(
            executionHash,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            uint64(block.number),
            IStakeManager.ProposalType.Standard,
            address(0),
            0
        );

        IStakeManager.ProposalView memory proposal = stakeManager.getProposal(proposalId);
        vm.warp(proposal.voteEnd);

        IOracleAdapter.SnapshotResult memory result = IOracleAdapter.SnapshotResult({
            proposalId: proposalId,
            executionHash: executionHash,
            snapshotProposalHash: keccak256(abi.encodePacked("snapshot-proposal:", proposalId)),
            snapshotSpaceHash: SNAPSHOT_SPACE_HASH,
            snapshotBlock: proposal.snapshotBlock + 1,
            forVotes: 500_000 ether,
            againstVotes: 80_000 ether,
            abstainVotes: 10_000 ether,
            totalStakedAtSnapshot: uint128(stakeManager.totalStakedAt(proposal.snapshotBlock)),
            passed: true,
            metadataHash: _metadataHash(proposalId, proposal.snapshotBlock + 1, executionHash)
        });

        bytes32 resultHash = oracleAdapter.hashSnapshotResult(result);
        oracleAdapter.submitResultHash(proposalId, resultHash);

        (bool ok,) = address(oracleAdapter).call(abi.encodeCall(IOracleAdapter.proposeResult, (result)));
        require(!ok, "mismatched snapshot block should fail");
    }

    function testAttestationThresholdFallbackFinalization() public {
        uint256 proposalId = stakeManager.proposalCount() + 1;

        IGovernanceExecutor.Transaction[] memory txs = new IGovernanceExecutor.Transaction[](1);
        txs[0] = IGovernanceExecutor.Transaction({
            target: address(target),
            value: 0,
            data: abi.encodeWithSelector(MockTarget.setNumber.selector, 77, bytes32("fallback"))
        });

        bytes32 executionHash = executor.computeExecutionHash(proposalId, SALT_A, txs);

        vm.prank(ALICE);
        stakeManager.registerProposal(
            executionHash,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            IStakeManager.ProposalType.Standard,
            address(0),
            0
        );

        IStakeManager.ProposalView memory proposal = stakeManager.getProposal(proposalId);
        vm.warp(proposal.voteEnd);

        IOracleAdapter.SnapshotResult memory result = IOracleAdapter.SnapshotResult({
            proposalId: proposalId,
            executionHash: executionHash,
            snapshotProposalHash: keccak256(abi.encodePacked("snapshot-proposal:", proposalId)),
            snapshotSpaceHash: SNAPSHOT_SPACE_HASH,
            snapshotBlock: proposal.snapshotBlock,
            forVotes: 600_000 ether,
            againstVotes: 80_000 ether,
            abstainVotes: 10_000 ether,
            totalStakedAtSnapshot: uint128(stakeManager.totalStakedAt(proposal.snapshotBlock)),
            passed: true,
            metadataHash: _metadataHash(proposalId, proposal.snapshotBlock, executionHash)
        });

        bytes32 resultHash = oracleAdapter.hashSnapshotResult(result);
        oracleAdapter.submitResultHash(proposalId, resultHash);
        oracleAdapter.proposeResult(result);

        vm.warp(block.timestamp + parameterManager.oracleChallengeWindow());
        (bool preFallbackOk,) = address(oracleAdapter).call(abi.encodeCall(IOracleAdapter.finalizeResult, (proposalId)));
        require(!preFallbackOk, "finalization should require attestation or fallback delay");

        vm.warp(block.timestamp + oracleAdapter.fallbackFinalizationDelay());
        oracleAdapter.finalizeResult(proposalId);
    }

    function testEmergencyPauseBlocksExecutionUntilExpiry() public {
        uint256 proposalId = stakeManager.proposalCount() + 1;

        IGovernanceExecutor.Transaction[] memory txs = new IGovernanceExecutor.Transaction[](1);
        txs[0] = IGovernanceExecutor.Transaction({
            target: address(target),
            value: 0,
            data: abi.encodeWithSelector(MockTarget.setNumber.selector, 88, bytes32("paused"))
        });

        bytes32 executionHash = executor.computeExecutionHash(proposalId, SALT_A, txs);

        vm.prank(ALICE);
        stakeManager.registerProposal(
            executionHash,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            IStakeManager.ProposalType.Standard,
            address(0),
            0
        );

        _settlePassedProposal(proposalId, executionHash, IStakeManager.ProposalType.Standard, 620_000 ether, 70_000 ether, 10_000 ether);

        executor.triggerEmergencyPause(6 hours);
        vm.warp(block.timestamp + parameterManager.timelockDuration());
        require(!_tryExecute(proposalId, SALT_A, txs), "execution should be paused");

        vm.warp(block.timestamp + 6 hours);
        require(_tryExecute(proposalId, SALT_A, txs), "execution should resume after pause expiry");
    }

    function testBondSlashedOnFailedProposal() public {
        uint256 proposalId = stakeManager.proposalCount() + 1;

        IGovernanceExecutor.Transaction[] memory txs = new IGovernanceExecutor.Transaction[](1);
        txs[0] = IGovernanceExecutor.Transaction({
            target: address(target),
            value: 0,
            data: abi.encodeWithSelector(MockTarget.setNumber.selector, 101, bytes32("failed-bond"))
        });

        bytes32 executionHash = executor.computeExecutionHash(proposalId, SALT_A, txs);

        uint256 treasuryBefore = token.balanceOf(TREASURY);
        uint256 aliceStakeBefore = stakeManager.stakeOf(ALICE);
        uint256 bond = parameterManager.proposalBond();

        vm.prank(ALICE);
        stakeManager.registerProposal(
            executionHash,
            uint64(block.timestamp),
            uint64(block.timestamp + 1 days),
            IStakeManager.ProposalType.Standard,
            address(0),
            0
        );

        IStakeManager.ProposalView memory proposal = stakeManager.getProposal(proposalId);
        vm.warp(proposal.voteEnd);

        IOracleAdapter.SnapshotResult memory result = IOracleAdapter.SnapshotResult({
            proposalId: proposalId,
            executionHash: executionHash,
            snapshotProposalHash: keccak256(abi.encodePacked("snapshot-proposal:", proposalId)),
            snapshotSpaceHash: SNAPSHOT_SPACE_HASH,
            snapshotBlock: proposal.snapshotBlock,
            forVotes: 100_000 ether,
            againstVotes: 600_000 ether,
            abstainVotes: 10_000 ether,
            totalStakedAtSnapshot: uint128(stakeManager.totalStakedAt(proposal.snapshotBlock)),
            passed: false,
            metadataHash: _metadataHash(proposalId, proposal.snapshotBlock, executionHash)
        });

        bytes32 resultHash = oracleAdapter.hashSnapshotResult(result);
        oracleAdapter.submitResultHash(proposalId, resultHash);
        oracleAdapter.proposeResult(result);
        oracleAdapter.attestResult(proposalId);

        vm.warp(block.timestamp + parameterManager.oracleChallengeWindow());
        oracleAdapter.finalizeResult(proposalId);

        require(token.balanceOf(TREASURY) == treasuryBefore + bond, "treasury did not receive bond penalty");
        require(stakeManager.stakeOf(ALICE) == aliceStakeBefore - bond, "proposer bond not slashed");
    }

    function _settlePassedProposal(
        uint256 proposalId,
        bytes32 executionHash,
        IStakeManager.ProposalType,
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

    function testSnapshotCheckpointCompatibility() public {
        uint256 checkpointBlock = block.number;
        uint256 aliceStakeAtCheckpoint = stakeManager.stakeAt(ALICE, checkpointBlock);
        uint256 totalAtCheckpoint = stakeManager.totalStakedAt(checkpointBlock);

        vm.roll(block.number + 1);
        vm.startPrank(ALICE);
        stakeManager.unstake(10_000 ether);
        vm.stopPrank();

        require(stakeManager.stakeAt(ALICE, checkpointBlock) == aliceStakeAtCheckpoint, "historic stake changed");
        require(stakeManager.totalStakedAt(checkpointBlock) == totalAtCheckpoint, "historic total changed");
        require(stakeManager.votingPowerAt(ALICE, checkpointBlock) == aliceStakeAtCheckpoint, "historic vote power mismatch");
    }
}
