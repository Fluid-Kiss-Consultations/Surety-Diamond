// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage, SystemPaused} from "../libraries/LibAppStorage.sol";
import {LibRoles} from "../libraries/LibRoles.sol";
import {ISecurityGuardFacet} from "../interfaces/ISecurityGuardFacet.sol";

/// @title SecurityGuardFacet
/// @author Surety Compliance System
/// @notice Threat detection, rate limiting, circuit breakers, and security incident management
/// @dev Provides on-chain security monitoring infrastructure for the compliance diamond.
///      The circuit breaker auto-pauses the system when incident thresholds are breached.
contract SecurityGuardFacet is ISecurityGuardFacet {

    // ============ Modifiers ============

    modifier whenNotPaused() {
        if (LibAppStorage.isPaused()) revert SystemPaused();
        _;
    }

    modifier onlySecurityAdmin() {
        LibRoles.checkRole(LibRoles.SECURITY_ADMIN_ROLE);
        _;
    }

    // ============ Rate Limiting ============

    /// @inheritdoc ISecurityGuardFacet
    function setRateLimit(
        bytes4 selector,
        uint256 maxCalls,
        uint256 windowSeconds
    ) external whenNotPaused onlySecurityAdmin {
        if (maxCalls == 0 || windowSeconds == 0) revert InvalidRateLimitConfig();

        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        s.selectorRateLimits[selector] = LibAppStorage.RateLimitConfig({
            maxCalls: maxCalls,
            windowSeconds: windowSeconds,
            enabled: true
        });

        _logAction("RATE_LIMIT_SET");
        emit RateLimitSet(selector, maxCalls, windowSeconds, block.timestamp);
    }

    /// @inheritdoc ISecurityGuardFacet
    function removeRateLimit(bytes4 selector) external whenNotPaused onlySecurityAdmin {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        delete s.selectorRateLimits[selector];

        _logAction("RATE_LIMIT_REMOVED");
        emit RateLimitRemoved(selector, block.timestamp);
    }

    /// @inheritdoc ISecurityGuardFacet
    function checkRateLimit(
        address caller,
        bytes4 selector
    ) external view returns (bool allowed, uint256 remaining) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.RateLimitConfig storage config = s.selectorRateLimits[selector];

        if (!config.enabled) {
            return (true, type(uint256).max);
        }

        LibAppStorage.ActivityTracker storage tracker = s.addressActivity[caller][selector];

        // Check if window has expired (new window)
        if (block.timestamp >= tracker.windowStart + config.windowSeconds) {
            return (true, config.maxCalls);
        }

        // Within current window
        if (tracker.callCount >= config.maxCalls) {
            return (false, 0);
        }

        return (true, config.maxCalls - tracker.callCount);
    }

    /// @inheritdoc ISecurityGuardFacet
    function recordActivity(
        address caller,
        bytes4 selector
    ) external whenNotPaused onlySecurityAdmin {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.RateLimitConfig storage config = s.selectorRateLimits[selector];
        LibAppStorage.ActivityTracker storage tracker = s.addressActivity[caller][selector];

        // Reset window if expired
        if (block.timestamp >= tracker.windowStart + config.windowSeconds) {
            tracker.callCount = 0;
            tracker.windowStart = block.timestamp;
        }

        tracker.callCount++;
        tracker.lastActivity = block.timestamp;
        tracker.totalLifetimeCalls++;

        // Check rate limit breach
        if (config.enabled && tracker.callCount > config.maxCalls) {
            revert RateLimitExceeded(caller, selector);
        }
    }

    // ============ Circuit Breaker ============

    /// @inheritdoc ISecurityGuardFacet
    function setCircuitBreakerConfig(
        uint256 threshold,
        uint256 windowSeconds
    ) external whenNotPaused onlySecurityAdmin {
        if (threshold == 0 || windowSeconds == 0) revert InvalidCircuitBreakerConfig();

        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        s.circuitBreakerThreshold = threshold;
        s.circuitBreakerWindow = windowSeconds;
        s.circuitBreakerWindowStart = block.timestamp;
        s.circuitBreakerIncidentCount = 0;

        _logAction("CIRCUIT_BREAKER_CONFIGURED");
        emit CircuitBreakerConfigured(threshold, windowSeconds, block.timestamp);
    }

    /// @inheritdoc ISecurityGuardFacet
    function getCircuitBreakerStatus() external view returns (
        uint256 incidentCount,
        uint256 threshold,
        uint256 windowStart
    ) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        return (
            s.circuitBreakerIncidentCount,
            s.circuitBreakerThreshold,
            s.circuitBreakerWindowStart
        );
    }

    // ============ Threat Management ============

    /// @inheritdoc ISecurityGuardFacet
    function registerThreatIndicator(
        bytes32 indicatorType,
        LibAppStorage.ThreatLevel level,
        bytes32 description
    ) external whenNotPaused onlySecurityAdmin returns (bytes32 indicatorId) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        indicatorId = keccak256(abi.encodePacked(indicatorType, level, description, block.timestamp, msg.sender));

        s.threatIndicators[indicatorId] = LibAppStorage.ThreatIndicator({
            indicatorId: indicatorId,
            level: level,
            indicatorType: indicatorType,
            description: description,
            createdAt: block.timestamp,
            active: true
        });

        s.threatIndicatorIds.push(indicatorId);

        _logAction("THREAT_INDICATOR_REGISTERED");
        emit ThreatIndicatorRegistered(indicatorId, indicatorType, level, block.timestamp);
    }

    /// @inheritdoc ISecurityGuardFacet
    function deactivateThreatIndicator(bytes32 indicatorId) external whenNotPaused onlySecurityAdmin {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.ThreatIndicator storage indicator = s.threatIndicators[indicatorId];

        if (indicator.createdAt == 0) revert ThreatIndicatorNotFound(indicatorId);
        if (!indicator.active) revert ThreatIndicatorAlreadyInactive(indicatorId);

        indicator.active = false;

        _logAction("THREAT_INDICATOR_DEACTIVATED");
        emit ThreatIndicatorDeactivated(indicatorId, block.timestamp);
    }

    /// @inheritdoc ISecurityGuardFacet
    function getThreatIndicator(
        bytes32 indicatorId
    ) external view returns (LibAppStorage.ThreatIndicator memory indicator) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        indicator = s.threatIndicators[indicatorId];
        if (indicator.createdAt == 0) revert ThreatIndicatorNotFound(indicatorId);
    }

    // ============ Incident Reporting & Response ============

    /// @inheritdoc ISecurityGuardFacet
    function reportSecurityIncident(
        address subject,
        bytes32 indicatorType,
        bytes32 details,
        LibAppStorage.ThreatLevel level
    ) external onlySecurityAdmin returns (bytes32 incidentId) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        incidentId = keccak256(abi.encodePacked(subject, indicatorType, details, block.timestamp, s.securityIncidents.length));

        LibAppStorage.SecurityAction actionTaken = _determineAction(level);

        s.securityIncidents.push(LibAppStorage.SecurityIncident({
            incidentId: incidentId,
            level: level,
            subject: subject,
            indicatorType: indicatorType,
            details: details,
            timestamp: block.timestamp,
            actionTaken: actionTaken,
            reportedBy: msg.sender
        }));

        s.securityIncidentCount[subject]++;

        // Circuit breaker evaluation
        _evaluateCircuitBreaker();

        // Auto-block on CRITICAL incidents
        if (level == LibAppStorage.ThreatLevel.CRITICAL && !s.blockedAddresses[subject]) {
            s.blockedAddresses[subject] = true;
            emit AddressBlocked(subject, msg.sender, block.timestamp);
        }

        _logAction("SECURITY_INCIDENT_REPORTED");
        emit SecurityIncidentReported(incidentId, subject, level, block.timestamp);
    }

    /// @inheritdoc ISecurityGuardFacet
    function getSecurityIncidents(
        address subject
    ) external view returns (LibAppStorage.SecurityIncident[] memory incidents) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        uint256 count = s.securityIncidentCount[subject];

        if (count == 0) {
            return new LibAppStorage.SecurityIncident[](0);
        }

        // Count matching incidents
        uint256 total = s.securityIncidents.length;
        uint256 matchCount = 0;
        for (uint256 i = 0; i < total; i++) {
            if (s.securityIncidents[i].subject == subject) {
                matchCount++;
            }
        }

        incidents = new LibAppStorage.SecurityIncident[](matchCount);
        uint256 idx = 0;
        for (uint256 i = 0; i < total; i++) {
            if (s.securityIncidents[i].subject == subject) {
                incidents[idx] = s.securityIncidents[i];
                idx++;
            }
        }
    }

    // ============ Address Blocking ============

    /// @inheritdoc ISecurityGuardFacet
    function blockAddress(address target) external whenNotPaused onlySecurityAdmin {
        if (target == address(0)) revert ZeroAddress();
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        if (s.blockedAddresses[target]) revert AddressAlreadyBlocked(target);

        s.blockedAddresses[target] = true;

        _logAction("ADDRESS_BLOCKED");
        emit AddressBlocked(target, msg.sender, block.timestamp);
    }

    /// @inheritdoc ISecurityGuardFacet
    function unblockAddress(address target) external whenNotPaused onlySecurityAdmin {
        if (target == address(0)) revert ZeroAddress();
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        if (!s.blockedAddresses[target]) revert AddressNotBlocked(target);

        s.blockedAddresses[target] = false;

        _logAction("ADDRESS_UNBLOCKED");
        emit AddressUnblocked(target, msg.sender, block.timestamp);
    }

    /// @inheritdoc ISecurityGuardFacet
    function isAddressBlocked(address target) external view returns (bool blocked) {
        return LibAppStorage.appStorage().blockedAddresses[target];
    }

    // ============ Internal Functions ============

    /// @dev Determine the appropriate response action based on threat level
    function _determineAction(
        LibAppStorage.ThreatLevel level
    ) internal pure returns (LibAppStorage.SecurityAction) {
        if (level == LibAppStorage.ThreatLevel.CRITICAL) return LibAppStorage.SecurityAction.BLOCK;
        if (level == LibAppStorage.ThreatLevel.HIGH) return LibAppStorage.SecurityAction.CIRCUIT_BREAK;
        if (level == LibAppStorage.ThreatLevel.MEDIUM) return LibAppStorage.SecurityAction.ALERT;
        return LibAppStorage.SecurityAction.RATE_LIMIT;
    }

    /// @dev Evaluate circuit breaker and auto-pause if threshold breached
    function _evaluateCircuitBreaker() internal {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        if (s.circuitBreakerThreshold == 0) return;

        // Reset window if expired
        if (block.timestamp >= s.circuitBreakerWindowStart + s.circuitBreakerWindow) {
            s.circuitBreakerIncidentCount = 1;
            s.circuitBreakerWindowStart = block.timestamp;
            return;
        }

        s.circuitBreakerIncidentCount++;

        // Trigger auto-pause if threshold breached
        if (s.circuitBreakerIncidentCount >= s.circuitBreakerThreshold) {
            if (!s.systemPaused) {
                s.systemPaused = true;
                emit CircuitBreakerTriggered(s.circuitBreakerIncidentCount, block.timestamp);
            }
        }
    }

    /// @dev Log action to hash-chained audit trail
    function _logAction(string memory action) internal {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        bytes32 actionHash = keccak256(abi.encodePacked(action, msg.sender, block.timestamp));
        bytes32 previousHash = s.latestAuditHash;
        bytes32 newHash = keccak256(abi.encodePacked(actionHash, previousHash, block.timestamp));
        s.auditChain[previousHash] = newHash;
        s.latestAuditHash = newHash;
        s.totalAuditEntries++;
    }
}
