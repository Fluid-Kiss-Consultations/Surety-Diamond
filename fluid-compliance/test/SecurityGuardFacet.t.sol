// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondTestHelper} from "./helpers/DiamondTestHelper.sol";
import {ISecurityGuardFacet} from "../src/interfaces/ISecurityGuardFacet.sol";
import {LibAppStorage} from "../src/libraries/LibAppStorage.sol";
import {LibRoles} from "../src/libraries/LibRoles.sol";

/// @notice Tests for the SecurityGuardFacet
contract SecurityGuardFacetTest is DiamondTestHelper {

    bytes4 constant TEST_SELECTOR = bytes4(keccak256("testFunction()"));
    address constant SUSPECT = address(0xBAD);

    // ============ Rate Limit Tests ============

    function test_setRateLimit() public {
        vm.prank(securityAdmin);
        securityGuard().setRateLimit(TEST_SELECTOR, 10, 3600);

        (bool allowed, uint256 remaining) = securityGuard().checkRateLimit(buyer, TEST_SELECTOR);
        assertTrue(allowed);
        assertEq(remaining, 10);
    }

    function test_setRateLimit_revertsInvalidConfig() public {
        vm.prank(securityAdmin);
        vm.expectRevert(ISecurityGuardFacet.InvalidRateLimitConfig.selector);
        securityGuard().setRateLimit(TEST_SELECTOR, 0, 3600);

        vm.prank(securityAdmin);
        vm.expectRevert(ISecurityGuardFacet.InvalidRateLimitConfig.selector);
        securityGuard().setRateLimit(TEST_SELECTOR, 10, 0);
    }

    function test_removeRateLimit() public {
        vm.prank(securityAdmin);
        securityGuard().setRateLimit(TEST_SELECTOR, 10, 3600);

        vm.prank(securityAdmin);
        securityGuard().removeRateLimit(TEST_SELECTOR);

        (bool allowed, uint256 remaining) = securityGuard().checkRateLimit(buyer, TEST_SELECTOR);
        assertTrue(allowed);
        assertEq(remaining, type(uint256).max);
    }

    function test_checkRateLimit_noLimitSet() public view {
        (bool allowed, uint256 remaining) = securityGuard().checkRateLimit(buyer, TEST_SELECTOR);
        assertTrue(allowed);
        assertEq(remaining, type(uint256).max);
    }

    function test_recordActivity() public {
        vm.prank(securityAdmin);
        securityGuard().setRateLimit(TEST_SELECTOR, 3, 3600);

        // Record 2 activities
        vm.prank(securityAdmin);
        securityGuard().recordActivity(buyer, TEST_SELECTOR);

        vm.prank(securityAdmin);
        securityGuard().recordActivity(buyer, TEST_SELECTOR);

        (bool allowed, uint256 remaining) = securityGuard().checkRateLimit(buyer, TEST_SELECTOR);
        assertTrue(allowed);
        assertEq(remaining, 1);
    }

    function test_recordActivity_exceedsRateLimit() public {
        vm.prank(securityAdmin);
        securityGuard().setRateLimit(TEST_SELECTOR, 2, 3600);

        vm.prank(securityAdmin);
        securityGuard().recordActivity(buyer, TEST_SELECTOR);

        vm.prank(securityAdmin);
        securityGuard().recordActivity(buyer, TEST_SELECTOR);

        // Third call should revert
        vm.prank(securityAdmin);
        vm.expectRevert(abi.encodeWithSelector(ISecurityGuardFacet.RateLimitExceeded.selector, buyer, TEST_SELECTOR));
        securityGuard().recordActivity(buyer, TEST_SELECTOR);
    }

    function test_recordActivity_windowReset() public {
        vm.prank(securityAdmin);
        securityGuard().setRateLimit(TEST_SELECTOR, 2, 3600);

        vm.prank(securityAdmin);
        securityGuard().recordActivity(buyer, TEST_SELECTOR);

        vm.prank(securityAdmin);
        securityGuard().recordActivity(buyer, TEST_SELECTOR);

        // Fast forward past window
        vm.warp(block.timestamp + 3601);

        // Should succeed after window reset
        vm.prank(securityAdmin);
        securityGuard().recordActivity(buyer, TEST_SELECTOR);

        (bool allowed, uint256 remaining) = securityGuard().checkRateLimit(buyer, TEST_SELECTOR);
        assertTrue(allowed);
        assertEq(remaining, 1);
    }

    // ============ Circuit Breaker Tests ============

    function test_setCircuitBreakerConfig() public {
        vm.prank(securityAdmin);
        securityGuard().setCircuitBreakerConfig(5, 3600);

        (uint256 incidentCount, uint256 threshold, uint256 windowStart) = securityGuard().getCircuitBreakerStatus();
        assertEq(incidentCount, 0);
        assertEq(threshold, 5);
        assertGt(windowStart, 0);
    }

    function test_setCircuitBreakerConfig_revertsInvalid() public {
        vm.prank(securityAdmin);
        vm.expectRevert(ISecurityGuardFacet.InvalidCircuitBreakerConfig.selector);
        securityGuard().setCircuitBreakerConfig(0, 3600);

        vm.prank(securityAdmin);
        vm.expectRevert(ISecurityGuardFacet.InvalidCircuitBreakerConfig.selector);
        securityGuard().setCircuitBreakerConfig(5, 0);
    }

    function test_circuitBreaker_autoTriggers() public {
        // Configure circuit breaker: 3 incidents in 1 hour
        vm.prank(securityAdmin);
        securityGuard().setCircuitBreakerConfig(3, 3600);

        // Report 3 incidents — should trigger auto-pause
        for (uint256 i = 0; i < 3; i++) {
            vm.prank(securityAdmin);
            securityGuard().reportSecurityIncident(
                SUSPECT,
                keccak256("BRUTE_FORCE"),
                keccak256(abi.encodePacked("attempt-", i)),
                LibAppStorage.ThreatLevel.HIGH
            );
        }

        // System should now be paused
        // Verify by trying a whenNotPaused operation
        vm.prank(securityAdmin);
        vm.expectRevert(); // SystemPaused
        securityGuard().setRateLimit(TEST_SELECTOR, 10, 3600);
    }

    function test_circuitBreaker_windowReset() public {
        vm.prank(securityAdmin);
        securityGuard().setCircuitBreakerConfig(3, 3600);

        // Report 2 incidents
        vm.prank(securityAdmin);
        securityGuard().reportSecurityIncident(SUSPECT, keccak256("TEST"), keccak256("d1"), LibAppStorage.ThreatLevel.MEDIUM);

        vm.prank(securityAdmin);
        securityGuard().reportSecurityIncident(SUSPECT, keccak256("TEST"), keccak256("d2"), LibAppStorage.ThreatLevel.MEDIUM);

        // Fast forward past window
        vm.warp(block.timestamp + 3601);

        // Report 1 more — window should reset, count starts at 1
        vm.prank(securityAdmin);
        securityGuard().reportSecurityIncident(SUSPECT, keccak256("TEST"), keccak256("d3"), LibAppStorage.ThreatLevel.MEDIUM);

        (uint256 incidentCount,,) = securityGuard().getCircuitBreakerStatus();
        assertEq(incidentCount, 1);
    }

    // ============ Threat Indicator Tests ============

    function test_registerThreatIndicator() public {
        vm.prank(securityAdmin);
        bytes32 indicatorId = securityGuard().registerThreatIndicator(
            keccak256("RAPID_ROLE_CHANGE"),
            LibAppStorage.ThreatLevel.HIGH,
            keccak256("Rapid role assignment changes detected")
        );

        LibAppStorage.ThreatIndicator memory indicator = securityGuard().getThreatIndicator(indicatorId);
        assertEq(indicator.indicatorId, indicatorId);
        assertTrue(indicator.level == LibAppStorage.ThreatLevel.HIGH);
        assertTrue(indicator.active);
        assertEq(indicator.indicatorType, keccak256("RAPID_ROLE_CHANGE"));
    }

    function test_deactivateThreatIndicator() public {
        vm.prank(securityAdmin);
        bytes32 indicatorId = securityGuard().registerThreatIndicator(
            keccak256("VOLUME_SPIKE"),
            LibAppStorage.ThreatLevel.MEDIUM,
            keccak256("Unusual volume detected")
        );

        vm.prank(securityAdmin);
        securityGuard().deactivateThreatIndicator(indicatorId);

        LibAppStorage.ThreatIndicator memory indicator = securityGuard().getThreatIndicator(indicatorId);
        assertFalse(indicator.active);
    }

    function test_deactivateThreatIndicator_revertsNotFound() public {
        vm.prank(securityAdmin);
        vm.expectRevert(abi.encodeWithSelector(ISecurityGuardFacet.ThreatIndicatorNotFound.selector, bytes32(uint256(999))));
        securityGuard().deactivateThreatIndicator(bytes32(uint256(999)));
    }

    function test_deactivateThreatIndicator_revertsAlreadyInactive() public {
        vm.prank(securityAdmin);
        bytes32 indicatorId = securityGuard().registerThreatIndicator(
            keccak256("TEST"),
            LibAppStorage.ThreatLevel.LOW,
            keccak256("test")
        );

        vm.prank(securityAdmin);
        securityGuard().deactivateThreatIndicator(indicatorId);

        vm.prank(securityAdmin);
        vm.expectRevert(abi.encodeWithSelector(ISecurityGuardFacet.ThreatIndicatorAlreadyInactive.selector, indicatorId));
        securityGuard().deactivateThreatIndicator(indicatorId);
    }

    function test_getThreatIndicator_revertsNotFound() public {
        vm.prank(securityAdmin);
        vm.expectRevert(abi.encodeWithSelector(ISecurityGuardFacet.ThreatIndicatorNotFound.selector, bytes32(uint256(123))));
        securityGuard().getThreatIndicator(bytes32(uint256(123)));
    }

    // ============ Security Incident Tests ============

    function test_reportSecurityIncident() public {
        vm.prank(securityAdmin);
        bytes32 incidentId = securityGuard().reportSecurityIncident(
            SUSPECT,
            keccak256("SUSPICIOUS_TX"),
            keccak256("Large value transfer to new address"),
            LibAppStorage.ThreatLevel.HIGH
        );

        LibAppStorage.SecurityIncident[] memory incidents = securityGuard().getSecurityIncidents(SUSPECT);
        assertEq(incidents.length, 1);
        assertEq(incidents[0].incidentId, incidentId);
        assertEq(incidents[0].subject, SUSPECT);
        assertTrue(incidents[0].level == LibAppStorage.ThreatLevel.HIGH);
        assertEq(incidents[0].reportedBy, securityAdmin);
    }

    function test_reportSecurityIncident_criticalAutoBlocks() public {
        vm.prank(securityAdmin);
        securityGuard().reportSecurityIncident(
            SUSPECT,
            keccak256("EXPLOIT_ATTEMPT"),
            keccak256("Critical exploit detected"),
            LibAppStorage.ThreatLevel.CRITICAL
        );

        assertTrue(securityGuard().isAddressBlocked(SUSPECT));
    }

    function test_getSecurityIncidents_empty() public view {
        LibAppStorage.SecurityIncident[] memory incidents = securityGuard().getSecurityIncidents(address(0x123));
        assertEq(incidents.length, 0);
    }

    function test_getSecurityIncidents_multipleIncidents() public {
        vm.prank(securityAdmin);
        securityGuard().reportSecurityIncident(SUSPECT, keccak256("T1"), keccak256("d1"), LibAppStorage.ThreatLevel.LOW);

        vm.prank(securityAdmin);
        securityGuard().reportSecurityIncident(SUSPECT, keccak256("T2"), keccak256("d2"), LibAppStorage.ThreatLevel.MEDIUM);

        vm.prank(securityAdmin);
        securityGuard().reportSecurityIncident(address(0xBEEF), keccak256("T3"), keccak256("d3"), LibAppStorage.ThreatLevel.HIGH);

        LibAppStorage.SecurityIncident[] memory suspectIncidents = securityGuard().getSecurityIncidents(SUSPECT);
        assertEq(suspectIncidents.length, 2);

        LibAppStorage.SecurityIncident[] memory beefIncidents = securityGuard().getSecurityIncidents(address(0xBEEF));
        assertEq(beefIncidents.length, 1);
    }

    // ============ Address Blocking Tests ============

    function test_blockAddress() public {
        vm.prank(securityAdmin);
        securityGuard().blockAddress(SUSPECT);
        assertTrue(securityGuard().isAddressBlocked(SUSPECT));
    }

    function test_unblockAddress() public {
        vm.prank(securityAdmin);
        securityGuard().blockAddress(SUSPECT);

        vm.prank(securityAdmin);
        securityGuard().unblockAddress(SUSPECT);
        assertFalse(securityGuard().isAddressBlocked(SUSPECT));
    }

    function test_blockAddress_revertsAlreadyBlocked() public {
        vm.prank(securityAdmin);
        securityGuard().blockAddress(SUSPECT);

        vm.prank(securityAdmin);
        vm.expectRevert(abi.encodeWithSelector(ISecurityGuardFacet.AddressAlreadyBlocked.selector, SUSPECT));
        securityGuard().blockAddress(SUSPECT);
    }

    function test_unblockAddress_revertsNotBlocked() public {
        vm.prank(securityAdmin);
        vm.expectRevert(abi.encodeWithSelector(ISecurityGuardFacet.AddressNotBlocked.selector, SUSPECT));
        securityGuard().unblockAddress(SUSPECT);
    }

    function test_blockAddress_revertsZeroAddress() public {
        vm.prank(securityAdmin);
        vm.expectRevert(ISecurityGuardFacet.ZeroAddress.selector);
        securityGuard().blockAddress(address(0));
    }

    function test_isAddressBlocked_default() public view {
        assertFalse(securityGuard().isAddressBlocked(buyer));
    }

    // ============ Access Control Tests ============

    function test_setRateLimit_revertsUnauthorized() public {
        vm.prank(buyer);
        vm.expectRevert();
        securityGuard().setRateLimit(TEST_SELECTOR, 10, 3600);
    }

    function test_blockAddress_revertsUnauthorized() public {
        vm.prank(buyer);
        vm.expectRevert();
        securityGuard().blockAddress(SUSPECT);
    }

    function test_reportSecurityIncident_revertsUnauthorized() public {
        vm.prank(buyer);
        vm.expectRevert();
        securityGuard().reportSecurityIncident(SUSPECT, keccak256("T"), keccak256("d"), LibAppStorage.ThreatLevel.LOW);
    }

    // ============ Pause Tests ============

    function test_setRateLimit_revertsWhenPaused() public {
        vm.prank(pauser);
        (bool success,) = diamond.call(abi.encodeWithSignature("emergencyPause()"));
        assertTrue(success);

        vm.prank(securityAdmin);
        vm.expectRevert(); // SystemPaused
        securityGuard().setRateLimit(TEST_SELECTOR, 10, 3600);
    }

    function test_reportSecurityIncident_worksWhenPaused() public {
        vm.prank(pauser);
        (bool success,) = diamond.call(abi.encodeWithSignature("emergencyPause()"));
        assertTrue(success);

        // reportSecurityIncident should still work when paused (no whenNotPaused modifier)
        vm.prank(securityAdmin);
        bytes32 incidentId = securityGuard().reportSecurityIncident(
            SUSPECT,
            keccak256("WHILE_PAUSED"),
            keccak256("Incident during pause"),
            LibAppStorage.ThreatLevel.HIGH
        );
        assertTrue(incidentId != bytes32(0));
    }
}
