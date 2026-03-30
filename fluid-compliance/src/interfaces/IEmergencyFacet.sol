// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IEmergencyFacet
/// @notice Interface for emergency procedures: pause/unpause, withdrawal, and upgrade scheduling
interface IEmergencyFacet {

    // ============ Events ============

    event EmergencyPause(address indexed initiator, uint256 timestamp);
    event EmergencyUnpause(address indexed initiator, uint256 timestamp);
    event EmergencyWithdrawal(address indexed token, uint256 amount, address indexed recipient, uint256 timestamp);
    event EmergencyUpgradeScheduled(bytes32 indexed upgradeId, uint256 executeAfter);

    // ============ Errors ============

    error AlreadyPaused();
    error NotPaused();
    error InvalidRecipient();
    error WithdrawalFailed();
    error InsufficientTimelock();

    // ============ Functions ============

    /// @notice Pause all system operations
    /// @dev Requires PAUSER_ROLE
    function emergencyPause() external;

    /// @notice Unpause system operations
    /// @dev Requires EMERGENCY_ADMIN_ROLE
    function emergencyUnpause() external;

    /// @notice Emergency withdrawal of tokens to treasury
    /// @dev Requires EMERGENCY_ADMIN_ROLE. Protected by reentrancy guard.
    /// @param token Token address (address(0) for ETH)
    /// @param amount Amount to withdraw
    function emergencyWithdraw(address token, uint256 amount) external;

    /// @notice Schedule emergency upgrade with reduced timelock (minimum 24 hours)
    /// @dev Requires EMERGENCY_ADMIN_ROLE. Informational only — does not bypass DiamondCutFacet timelock.
    /// @param upgradeId Unique upgrade identifier
    /// @param reducedTimelock Reduced timelock period (minimum 24 hours)
    function scheduleEmergencyUpgrade(bytes32 upgradeId, uint256 reducedTimelock) external;
}
