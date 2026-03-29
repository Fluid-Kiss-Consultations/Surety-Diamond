// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IEmergencyFacet
/// @notice Interface for circuit-breaker and emergency admin controls
interface IEmergencyFacet {

    event SystemPaused(address indexed pausedBy, string reason, uint256 timestamp);
    event SystemResumed(address indexed resumedBy, uint256 timestamp);
    event EmergencyActionTaken(address indexed actor, bytes32 actionType, uint256 timestamp);

    /// @notice Pause all system operations
    /// @dev Requires EMERGENCY_ADMIN_ROLE or PAUSER_ROLE
    function pauseSystem(string calldata reason) external;

    /// @notice Resume system operations after pause
    /// @dev Requires EMERGENCY_ADMIN_ROLE
    function resumeSystem() external;

    /// @notice Check if system is currently paused
    /// @return paused True if the system is currently paused
    function isSystemPaused() external view returns (bool paused);

    /// @notice Emergency freeze of a specific entity
    /// @dev Requires EMERGENCY_ADMIN_ROLE
    function freezeEntity(address entity, string calldata reason) external;

    /// @notice Lift an emergency freeze
    function unfreezeEntity(address entity) external;

    /// @notice Check if an entity is frozen
    /// @param entity Address of the entity to check
    /// @return frozen True if the entity is currently frozen
    function isEntityFrozen(address entity) external view returns (bool frozen);
}
