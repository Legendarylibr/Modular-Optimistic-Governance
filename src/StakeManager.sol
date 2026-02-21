// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "./interfaces/IERC20.sol";
import {IParameterManager} from "./interfaces/IParameterManager.sol";
import {IStakeManager} from "./interfaces/IStakeManager.sol";
import {OwnableBootstrap} from "./utils/OwnableBootstrap.sol";
import {ReentrancyGuard} from "./utils/ReentrancyGuard.sol";

contract StakeManager is IStakeManager, OwnableBootstrap, ReentrancyGuard {
    error NotGovernanceExecutor();
    error NotOracleAdapter();
    error GovernanceExecutorAlreadySet();
    error OracleAdapterAlreadySet();
    error InvalidBps();
    error InvalidAmount();
    error StakeLocked();
    error FrozenStake();
    error InsufficientStake();
    error InsufficientFreeStake();
    error InvalidProposalTiming();
    error InvalidSnapshotBlock();
    error InvalidProposalConfig();
    error ProposalNotFound();
    error ProposalBondAlreadySettled();
    error AlreadyFrozen();
    error NotFrozen();
    error InvalidSlashingRequest();
    error CooldownActive();
    error TokenTransferFailed();

    uint16 internal constant BPS_DENOMINATOR = 10_000;

    IERC20 public immutable token;
    IParameterManager public immutable params;

    struct Checkpoint {
        uint64 fromBlock;
        uint192 value;
    }

    address public override governanceExecutor;
    address public override oracleAdapter;

    uint256 public override totalStaked;
    uint64 public override globalVoteLockUntil;
    uint256 public override proposalCount;

    mapping(address => uint256) private _stakeOf;
    mapping(address => uint64) private _lockedUntil;
    mapping(address => address) private _delegateOf;
    mapping(address => bool) private _isFrozen;
    mapping(address => uint64) private _frozenAt;
    mapping(uint256 => ProposalView) private _proposals;
    mapping(address => Checkpoint[]) private _stakeCheckpoints;
    mapping(address => Checkpoint[]) private _frozenCheckpoints;
    Checkpoint[] private _totalStakeCheckpoints;
    mapping(uint256 => uint256) private _proposalBond;
    mapping(uint256 => bool) private _proposalBondSettled;
    mapping(address => uint256) private _bondLockedByAccount;

    event GovernanceExecutorSet(address indexed executor);
    event OracleAdapterSet(address indexed adapter);
    event Staked(address indexed account, uint256 amount, uint256 totalStaked);
    event Unstaked(address indexed account, uint256 amount, uint256 totalStaked);
    event DelegateSet(address indexed account, address indexed delegatee);
    event StakeLockUpdated(address indexed account, uint64 lockedUntil);
    event GlobalVoteLockUpdated(uint64 globalVoteLockUntil);
    event ProposalRegistered(
        uint256 indexed proposalId,
        address indexed proposer,
        ProposalType proposalType,
        address indexed accused,
        bytes32 executionHash,
        uint64 voteStart,
        uint64 voteEnd,
        uint64 snapshotBlock,
        uint16 maxSlashBps
    );
    event StakeFrozen(address indexed account, uint256 indexed proposalId, uint64 frozenAt);
    event StakeUnfrozen(address indexed account, uint256 indexed proposalId);
    event StakeSlashed(
        address indexed account,
        uint256 indexed proposalId,
        uint16 slashBps,
        uint256 slashedAmount,
        SlashingDestination destination,
        address destinationAddress
    );
    event ProposalBondLocked(uint256 indexed proposalId, address indexed proposer, uint256 amount);
    event ProposalBondSettled(uint256 indexed proposalId, address indexed proposer, uint256 amount, bool passed);

    modifier onlyGovernanceExecutor() {
        if (msg.sender != governanceExecutor) revert NotGovernanceExecutor();
        _;
    }

    modifier onlyOracleAdapter() {
        if (msg.sender != oracleAdapter) revert NotOracleAdapter();
        _;
    }

    constructor(address initialBootstrapOwner, address governanceToken_, address parameterManager_)
        OwnableBootstrap(initialBootstrapOwner)
    {
        if (governanceToken_ == address(0) || parameterManager_ == address(0)) revert ZeroAddress();
        token = IERC20(governanceToken_);
        params = IParameterManager(parameterManager_);
    }

    function governanceToken() external view override returns (address) {
        return address(token);
    }

    function parameterManager() external view override returns (address) {
        return address(params);
    }

    function stakeOf(address account) external view override returns (uint256) {
        return _stakeOf[account];
    }

    function stakeAt(address account, uint256 blockNumber) public view override returns (uint256) {
        return _getCheckpointValueAt(_stakeCheckpoints[account], blockNumber);
    }

    function totalStakedAt(uint256 blockNumber) public view override returns (uint256) {
        return _getCheckpointValueAt(_totalStakeCheckpoints, blockNumber);
    }

    function lockedUntil(address account) external view override returns (uint64) {
        return _lockedUntil[account];
    }

    function delegateOf(address account) external view override returns (address) {
        return _delegateOf[account];
    }

    function isFrozen(address account) external view override returns (bool) {
        return _isFrozen[account];
    }

    function isFrozenAt(address account, uint256 blockNumber) public view override returns (bool) {
        return _getCheckpointValueAt(_frozenCheckpoints[account], blockNumber) == 1;
    }

    function frozenAt(address account) external view override returns (uint64) {
        return _frozenAt[account];
    }

    function votingPower(address account) external view override returns (uint256) {
        if (_isFrozen[account]) return 0;
        return _stakeOf[account];
    }

    function votingPowerAt(address account, uint256 blockNumber) external view override returns (uint256) {
        if (isFrozenAt(account, blockNumber)) return 0;
        return stakeAt(account, blockNumber);
    }

    function clock() external view override returns (uint48) {
        return uint48(block.number);
    }

    function CLOCK_MODE() external pure override returns (string memory) {
        return "mode=blocknumber&from=default";
    }

    function getProposal(uint256 proposalId) external view override returns (ProposalView memory) {
        ProposalView memory proposal = _proposals[proposalId];
        if (!proposal.exists) revert ProposalNotFound();
        return proposal;
    }

    function setGovernanceExecutor(address executor) external override onlyBootstrapOwner {
        if (executor == address(0)) revert ZeroAddress();
        if (governanceExecutor != address(0)) revert GovernanceExecutorAlreadySet();

        governanceExecutor = executor;
        emit GovernanceExecutorSet(executor);
    }

    function setOracleAdapter(address adapter) external override onlyBootstrapOwner {
        if (adapter == address(0)) revert ZeroAddress();
        if (oracleAdapter != address(0)) revert OracleAdapterAlreadySet();
        oracleAdapter = adapter;
        emit OracleAdapterSet(adapter);
    }

    function stake(uint256 amount) external override nonReentrant {
        if (amount == 0) revert InvalidAmount();

        uint256 newStake = _stakeOf[msg.sender] + amount;
        uint256 newTotalStaked = totalStaked + amount;
        _stakeOf[msg.sender] = newStake;
        totalStaked = newTotalStaked;

        bool success = token.transferFrom(msg.sender, address(this), amount);
        if (!success) revert TokenTransferFailed();

        _writeCheckpoint(_stakeCheckpoints[msg.sender], newStake);
        _writeCheckpoint(_totalStakeCheckpoints, newTotalStaked);

        emit Staked(msg.sender, amount, totalStaked);
    }

    function unstake(uint256 amount) external override nonReentrant {
        if (amount == 0) revert InvalidAmount();
        if (_isFrozen[msg.sender]) revert FrozenStake();

        uint256 stakedAmount = _stakeOf[msg.sender];
        if (amount > stakedAmount) revert InsufficientStake();
        if (amount > _freeStake(msg.sender)) revert InsufficientFreeStake();

        uint64 unlockTime = _lockedUntil[msg.sender];
        if (globalVoteLockUntil > unlockTime) unlockTime = globalVoteLockUntil;
        if (block.timestamp < unlockTime) revert StakeLocked();

        uint256 newStake = stakedAmount - amount;
        uint256 newTotalStaked = totalStaked - amount;
        _stakeOf[msg.sender] = newStake;
        totalStaked = newTotalStaked;

        bool success = token.transfer(msg.sender, amount);
        if (!success) revert TokenTransferFailed();

        _writeCheckpoint(_stakeCheckpoints[msg.sender], newStake);
        _writeCheckpoint(_totalStakeCheckpoints, newTotalStaked);

        emit Unstaked(msg.sender, amount, totalStaked);
    }

    function delegate(address delegatee) external override {
        if (_stakeOf[msg.sender] == 0) revert InsufficientStake();
        _delegateOf[msg.sender] = delegatee;
        emit DelegateSet(msg.sender, delegatee);
    }

    function registerProposal(
        bytes32 executionHash,
        uint64 voteStart,
        uint64 voteEnd,
        ProposalType proposalType,
        address accused,
        uint16 maxSlashBps
    ) external override returns (uint256 proposalId) {
        proposalId = _registerProposal(
            executionHash,
            voteStart,
            voteEnd,
            uint64(block.number),
            proposalType,
            accused,
            maxSlashBps
        );
    }

    function registerProposalWithSnapshot(
        bytes32 executionHash,
        uint64 voteStart,
        uint64 voteEnd,
        uint64 snapshotBlock,
        ProposalType proposalType,
        address accused,
        uint16 maxSlashBps
    ) external override returns (uint256 proposalId) {
        proposalId = _registerProposal(
            executionHash,
            voteStart,
            voteEnd,
            snapshotBlock,
            proposalType,
            accused,
            maxSlashBps
        );
    }

    function _registerProposal(
        bytes32 executionHash,
        uint64 voteStart,
        uint64 voteEnd,
        uint64 snapshotBlock,
        ProposalType proposalType,
        address accused,
        uint16 maxSlashBps
    ) internal returns (uint256 proposalId) {
        if (executionHash == bytes32(0)) revert InvalidProposalConfig();
        if (voteEnd <= voteStart || voteEnd <= block.timestamp) revert InvalidProposalTiming();
        if (snapshotBlock == 0 || snapshotBlock > block.number) revert InvalidSnapshotBlock();

        uint256 proposerStake = _stakeOf[msg.sender];
        uint256 freeStakeAmount = _freeStake(msg.sender);
        uint256 threshold = (totalStaked * params.proposalThresholdBps()) / BPS_DENOMINATOR;
        if (threshold == 0) threshold = 1;
        if (proposerStake < threshold || freeStakeAmount < threshold) revert InsufficientStake();

        uint256 proposalBondAmount = params.proposalBond();
        if (freeStakeAmount < threshold + proposalBondAmount) revert InsufficientFreeStake();

        _validateProposalType(proposalType, accused, maxSlashBps);

        proposalId = ++proposalCount;
        _proposals[proposalId] = ProposalView({
            proposer: msg.sender,
            executionHash: executionHash,
            voteStart: voteStart,
            voteEnd: voteEnd,
            snapshotBlock: snapshotBlock,
            proposalType: proposalType,
            accused: accused,
            maxSlashBps: maxSlashBps,
            exists: true
        });

        if (voteEnd > _lockedUntil[msg.sender]) {
            _lockedUntil[msg.sender] = voteEnd;
            emit StakeLockUpdated(msg.sender, voteEnd);
        }

        if (voteEnd > globalVoteLockUntil) {
            globalVoteLockUntil = voteEnd;
            emit GlobalVoteLockUpdated(voteEnd);
        }

        if (proposalBondAmount != 0) {
            _bondLockedByAccount[msg.sender] += proposalBondAmount;
            _proposalBond[proposalId] = proposalBondAmount;
            emit ProposalBondLocked(proposalId, msg.sender, proposalBondAmount);
        }

        _emitProposalRegistered(proposalId);
    }

    function freezeStake(address account, uint256 proposalId) external override onlyGovernanceExecutor {
        if (account == address(0)) revert ZeroAddress();
        if (_isFrozen[account]) revert AlreadyFrozen();

        ProposalView memory proposal = _proposals[proposalId];
        if (!proposal.exists) revert ProposalNotFound();
        if (proposal.proposalType != ProposalType.SlashNotice || proposal.accused != account) {
            revert InvalidSlashingRequest();
        }

        _isFrozen[account] = true;
        _frozenAt[account] = uint64(block.timestamp);
        _writeCheckpoint(_frozenCheckpoints[account], 1);

        emit StakeFrozen(account, proposalId, uint64(block.timestamp));
    }

    function unfreezeStake(address account, uint256 proposalId) external override onlyGovernanceExecutor {
        if (!_isFrozen[account]) revert NotFrozen();

        ProposalView memory proposal = _proposals[proposalId];
        if (!proposal.exists) revert ProposalNotFound();
        if (proposal.proposalType != ProposalType.Appeal || proposal.accused != account) {
            revert InvalidSlashingRequest();
        }

        _isFrozen[account] = false;
        _frozenAt[account] = 0;
        _writeCheckpoint(_frozenCheckpoints[account], 0);

        emit StakeUnfrozen(account, proposalId);
    }

    function slashStake(
        address account,
        uint16 slashBps,
        SlashingDestination destination,
        address destinationOverride,
        uint256 proposalId
    ) external override onlyGovernanceExecutor nonReentrant returns (uint256 slashedAmount) {
        if (!_isFrozen[account]) revert NotFrozen();
        if (slashBps == 0) revert InvalidBps();

        ProposalView memory proposal = _proposals[proposalId];
        if (!proposal.exists) revert ProposalNotFound();
        if (proposal.proposalType != ProposalType.SlashExecution || proposal.accused != account) {
            revert InvalidSlashingRequest();
        }

        if (slashBps > params.maxSlashingBps() || slashBps > proposal.maxSlashBps) revert InvalidBps();

        uint64 frozenTimestamp = _frozenAt[account];
        if (block.timestamp < uint256(frozenTimestamp) + params.slashingExecutionCooldown()) revert CooldownActive();

        uint256 currentStake = _stakeOf[account];
        slashedAmount = (currentStake * slashBps) / BPS_DENOMINATOR;
        if (slashedAmount == 0) revert InvalidAmount();

        address destinationAddress = _resolveDestination(destination, destinationOverride);

        bool success = token.transfer(destinationAddress, slashedAmount);
        if (!success) revert TokenTransferFailed();

        _applySlashState(account, slashedAmount);

        emit StakeSlashed(account, proposalId, slashBps, slashedAmount, destination, destinationAddress);
    }

    function settleProposalBond(uint256 proposalId, bool passed) external override onlyOracleAdapter nonReentrant {
        ProposalView memory proposal = _proposals[proposalId];
        if (!proposal.exists) revert ProposalNotFound();
        if (_proposalBondSettled[proposalId]) revert ProposalBondAlreadySettled();

        _proposalBondSettled[proposalId] = true;

        address proposer = proposal.proposer;
        uint256 bondAmount = _proposalBond[proposalId];
        _proposalBond[proposalId] = 0;

        uint256 lockedAmount = _bondLockedByAccount[proposer];
        uint256 released = bondAmount > lockedAmount ? lockedAmount : bondAmount;
        _bondLockedByAccount[proposer] = lockedAmount - released;

        if (!passed && bondAmount != 0) {
            uint256 penalty = bondAmount;
            uint256 proposerStake = _stakeOf[proposer];
            if (penalty > proposerStake) penalty = proposerStake;

            if (penalty != 0) {
                uint256 newStake = proposerStake - penalty;
                uint256 newTotalStaked = totalStaked - penalty;
                _stakeOf[proposer] = newStake;
                totalStaked = newTotalStaked;
                _writeCheckpoint(_stakeCheckpoints[proposer], newStake);
                _writeCheckpoint(_totalStakeCheckpoints, newTotalStaked);

                bool success = token.transfer(params.treasury(), penalty);
                if (!success) revert TokenTransferFailed();
            }
        }

        emit ProposalBondSettled(proposalId, proposer, bondAmount, passed);
    }

    function _resolveDestination(SlashingDestination destination, address destinationOverride)
        internal
        view
        returns (address)
    {
        if (destination == SlashingDestination.Treasury) {
            return params.treasury();
        }
        if (destination == SlashingDestination.Burn) {
            return params.burnAddress();
        }

        address pool = destinationOverride != address(0) ? destinationOverride : params.compensationPool();
        if (pool == address(0)) revert ZeroAddress();
        return pool;
    }

    function _writeCheckpoint(Checkpoint[] storage checkpoints, uint256 value) internal {
        uint256 length = checkpoints.length;
        uint64 blockNumber = uint64(block.number);
        uint192 checkpointValue = uint192(value);

        if (length == 0) {
            checkpoints.push(Checkpoint({fromBlock: blockNumber, value: checkpointValue}));
            return;
        }

        Checkpoint storage latest = checkpoints[length - 1];
        if (latest.fromBlock == blockNumber) {
            latest.value = checkpointValue;
            return;
        }

        checkpoints.push(Checkpoint({fromBlock: blockNumber, value: checkpointValue}));
    }

    function _applySlashState(address account, uint256 slashedAmount) internal {
        uint256 newStake = _stakeOf[account] - slashedAmount;
        uint256 newTotalStaked = totalStaked - slashedAmount;
        _stakeOf[account] = newStake;
        totalStaked = newTotalStaked;
        _writeCheckpoint(_stakeCheckpoints[account], newStake);
        _writeCheckpoint(_totalStakeCheckpoints, newTotalStaked);
    }

    function _emitProposalRegistered(uint256 proposalId) internal {
        ProposalView memory proposal = _proposals[proposalId];
        emit ProposalRegistered(
            proposalId,
            proposal.proposer,
            proposal.proposalType,
            proposal.accused,
            proposal.executionHash,
            proposal.voteStart,
            proposal.voteEnd,
            proposal.snapshotBlock,
            proposal.maxSlashBps
        );
    }

    function _freeStake(address account) internal view returns (uint256) {
        uint256 staked = _stakeOf[account];
        uint256 locked = _bondLockedByAccount[account];
        if (locked >= staked) return 0;
        return staked - locked;
    }

    function _getCheckpointValueAt(Checkpoint[] storage checkpoints, uint256 blockNumber) internal view returns (uint256) {
        if (blockNumber >= block.number) {
            return checkpoints.length == 0 ? 0 : checkpoints[checkpoints.length - 1].value;
        }

        uint256 length = checkpoints.length;
        if (length == 0) return 0;
        if (blockNumber < checkpoints[0].fromBlock) return 0;

        uint256 low;
        uint256 high = length;

        while (low < high) {
            uint256 mid = (low + high) / 2;
            if (checkpoints[mid].fromBlock > blockNumber) {
                high = mid;
            } else {
                low = mid + 1;
            }
        }

        return checkpoints[low - 1].value;
    }

    function _validateProposalType(ProposalType proposalType, address accused, uint16 maxSlashBps) internal view {
        if (proposalType == ProposalType.Standard) {
            if (accused != address(0) || maxSlashBps != 0) revert InvalidProposalConfig();
            return;
        }

        if (proposalType == ProposalType.SlashNotice) {
            if (accused == address(0) || maxSlashBps != 0) revert InvalidProposalConfig();
            return;
        }

        if (proposalType == ProposalType.SlashExecution) {
            if (accused == address(0) || maxSlashBps == 0) revert InvalidProposalConfig();
            if (!_isFrozen[accused]) revert InvalidSlashingRequest();
            if (maxSlashBps > params.maxSlashingBps()) revert InvalidBps();
            return;
        }

        if (proposalType == ProposalType.Appeal) {
            if (accused == address(0) || maxSlashBps != 0) revert InvalidProposalConfig();
            return;
        }

        revert InvalidProposalConfig();
    }
}
