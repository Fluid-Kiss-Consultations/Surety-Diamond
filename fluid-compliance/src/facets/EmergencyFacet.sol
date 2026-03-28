// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage, Reentrancy} from "../libraries/LibAppStorage.sol";
import {LibRoles} from "../libraries/LibRoles.sol";

/// @title EmergencyFacet
/// @author Surety Compliance System
/// @notice Emergency procedures for critical situations
/// @dev Implements pause, unpause, and emergency withdrawal functions
contract EmergencyFacet {
    using LibAppStorage for LibAppStorage.AppStorage;

    // ============ Events ============

    event EmergencyPause(address indexed initiator, uint256 timestamp);
    event EmergencyUnpause(address indexed initiator, uint256 timestamp);
    event EmergencyWithdrawal(address indexed token, uint256 amount, address indexed recipient);
    event EmergencyUpgradeScheduled(bytes32 indexed upgradeId, uint256 executeAfter);

    // ============ Errors ============

    error AlreadyPaused();
    error NotPaused();
    error InvalidRecipient();
    error WithdrawalFailed();
    error InsufficientTimelock();

    // ============ Modifiers ============

    modifier onlyEmergencyAdmin() {
        LibRoles.checkRole(LibRoles.EMERGENCY_ADMIN_ROLE);
        _;
    }

    modifier onlyPauser() {
        LibRoles.checkRole(LibRoles.PAUSER_ROLE);
        _;
    }

    modifier nonReentrant() {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        if (s._reentrancyStatus == 2) revert Reentrancy();
        s._reentrancyStatus = 2;
        _;
        s._reentrancyStatus = 1;
    }

    // ============ Core Functions ============

    /// @notice Pause all system operations
    function emergencyPause() external onlyPauser {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        if (s.systemPaused) revert AlreadyPaused();
        s.systemPaused = true;
        _logEmergencyAction("EMERGENCY_PAUSE");
        emit EmergencyPause(msg.sender, block.timestamp);
    }

    /// @notice Unpause system operations
    function emergencyUnpause() external onlyEmergencyAdmin {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        if (!s.systemPaused) revert NotPaused();
        s.systemPaused = false;
        _logEmergencyAction("EMERGENCY_UNPAUSE");
        emit EmergencyUnpause(msg.sender, block.timestamp);
    }

    /// @notice Emergency withdrawal of tokens
    /// @param token Token address (address(0) for ETH)
    /// @param amount Amount to withdraw
    function emergencyWithdraw(
        address token,
        uint256 amount
    ) external onlyEmergencyAdmin nonReentrant {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        address recipient = s.treasuryAddress;
        if (recipient == address(0)) revert InvalidRecipient();

        if (token == address(0)) {
            (bool success, ) = recipient.call{value: amount}("");
            if (!success) revert WithdrawalFailed();
        }
        // ERC-20 transfer would be implemented via IERC20 in production

        _logEmergencyAction("EMERGENCY_WITHDRAWAL");
        emit EmergencyWithdrawal(token, amount, recipient);
    }

    /// @notice Schedule emergency upgrade with reduced timelock (minimum 24 hours)
    /// @param upgradeId Unique upgrade identifier
    /// @param reducedTimelock Reduced timelock period
    function scheduleEmergencyUpgrade(
        bytes32 upgradeId,
        uint256 reducedTimelock
    ) external onlyEmergencyAdmin {
        if (reducedTimelock < 24 hours) revert InsufficientTimelock();
        uint256 executeAfter = block.timestamp + reducedTimelock;
        _logEmergencyAction("EMERGENCY_UPGRADE_SCHEDULED");
        emit EmergencyUpgradeScheduled(upgradeId, executeAfter);
    }

    // ============ Internal Functions ============

    function _logEmergencyAction(string memory action) internal {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        bytes32 actionHash = keccak256(abi.encodePacked(action, msg.sender, block.timestamp));
        bytes32 previousHash = s.latestAuditHash;
        bytes32 newHash = keccak256(abi.encodePacked(actionHash, previousHash, block.timestamp));
        s.auditChain[previousHash] = newHash;
        s.latestAuditHash = newHash;
        s.totalAuditEntries++;
    }
}
