// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title ISecurityGuardFacet
/// @notice Interface for threat detection, rate limiting, and security response
interface ISecurityGuardFacet {

    // ============ Events ============

    event RateLimitSet(bytes4 indexed selector, uint256 maxCalls, uint256 windowSeconds, uint256 timestamp);
    event RateLimitRemoved(bytes4 indexed selector, uint256 timestamp);
    event CircuitBreakerConfigured(uint256 threshold, uint256 windowSeconds, uint256 timestamp);
    event CircuitBreakerTriggered(uint256 incidentCount, uint256 timestamp);
    event ThreatIndicatorRegistered(bytes32 indexed indicatorId, bytes32 indexed indicatorType, LibAppStorage.ThreatLevel level, uint256 timestamp);
    event ThreatIndicatorDeactivated(bytes32 indexed indicatorId, uint256 timestamp);
    event SecurityIncidentReported(bytes32 indexed incidentId, address indexed subject, LibAppStorage.ThreatLevel level, uint256 timestamp);
    event AddressBlocked(address indexed target, address indexed blockedBy, uint256 timestamp);
    event AddressUnblocked(address indexed target, address indexed unblockedBy, uint256 timestamp);

    // ============ Errors ============

    error RateLimitExceeded(address caller, bytes4 selector);
    error InvalidRateLimitConfig();
    error ThreatIndicatorNotFound(bytes32 indicatorId);
    error ThreatIndicatorAlreadyInactive(bytes32 indicatorId);
    error AddressAlreadyBlocked(address target);
    error AddressNotBlocked(address target);
    error InvalidCircuitBreakerConfig();
    error ZeroAddress();

    // ============ Rate Limiting ============

    /// @notice Configure a rate limit for a function selector
    /// @param selector The function selector to rate-limit
    /// @param maxCalls Maximum calls allowed within the window
    /// @param windowSeconds Duration of the rate limit window in seconds
    function setRateLimit(bytes4 selector, uint256 maxCalls, uint256 windowSeconds) external;

    /// @notice Remove a rate limit for a function selector
    /// @param selector The function selector to un-limit
    function removeRateLimit(bytes4 selector) external;

    /// @notice Check if a caller is within rate limits for a selector
    /// @param caller The address to check
    /// @param selector The function selector
    /// @return allowed True if within limits
    /// @return remaining Number of calls remaining in the current window
    function checkRateLimit(
        address caller,
        bytes4 selector
    ) external view returns (bool allowed, uint256 remaining);

    /// @notice Record an activity event for rate limiting tracking
    /// @param caller The address performing the activity
    /// @param selector The function selector being called
    function recordActivity(address caller, bytes4 selector) external;

    // ============ Circuit Breaker ============

    /// @notice Configure the circuit breaker auto-pause threshold
    /// @param threshold Number of incidents before auto-pause triggers
    /// @param windowSeconds Time window for counting incidents
    function setCircuitBreakerConfig(uint256 threshold, uint256 windowSeconds) external;

    /// @notice Get current circuit breaker status
    /// @return incidentCount Current incident count in the window
    /// @return threshold Configured threshold for auto-pause
    /// @return windowStart Start of the current counting window
    function getCircuitBreakerStatus() external view returns (
        uint256 incidentCount,
        uint256 threshold,
        uint256 windowStart
    );

    // ============ Threat Management ============

    /// @notice Register a new threat indicator
    /// @param indicatorType Category of the threat (e.g., keccak256("RAPID_ROLE_CHANGE"))
    /// @param level Severity level
    /// @param description Human-readable description hash
    /// @return indicatorId The unique identifier for the registered indicator
    function registerThreatIndicator(
        bytes32 indicatorType,
        LibAppStorage.ThreatLevel level,
        bytes32 description
    ) external returns (bytes32 indicatorId);

    /// @notice Deactivate a threat indicator
    /// @param indicatorId The indicator to deactivate
    function deactivateThreatIndicator(bytes32 indicatorId) external;

    /// @notice Get details of a threat indicator
    /// @param indicatorId The indicator identifier
    /// @return indicator The threat indicator details
    function getThreatIndicator(
        bytes32 indicatorId
    ) external view returns (LibAppStorage.ThreatIndicator memory indicator);

    // ============ Incident Reporting & Response ============

    /// @notice Report a security incident (may trigger circuit breaker)
    /// @param subject The address involved in the incident
    /// @param indicatorType Category of the threat
    /// @param details Additional details hash
    /// @param level Severity level
    /// @return incidentId The unique identifier for the recorded incident
    function reportSecurityIncident(
        address subject,
        bytes32 indicatorType,
        bytes32 details,
        LibAppStorage.ThreatLevel level
    ) external returns (bytes32 incidentId);

    /// @notice Get security incidents for a subject address
    /// @param subject The address to query
    /// @return incidents Array of security incidents involving the subject
    function getSecurityIncidents(
        address subject
    ) external view returns (LibAppStorage.SecurityIncident[] memory incidents);

    // ============ Address Blocking ============

    /// @notice Block an address from system interaction
    /// @param target The address to block
    function blockAddress(address target) external;

    /// @notice Unblock a previously blocked address
    /// @param target The address to unblock
    function unblockAddress(address target) external;

    /// @notice Check if an address is blocked
    /// @param target The address to check
    /// @return blocked True if the address is blocked
    function isAddressBlocked(address target) external view returns (bool blocked);
}
