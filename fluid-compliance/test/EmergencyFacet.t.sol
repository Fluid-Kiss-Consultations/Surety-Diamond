// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondTestHelper} from "./helpers/DiamondTestHelper.sol";
import {EmergencyFacet} from "../src/facets/EmergencyFacet.sol";
import {LibAppStorage, SystemPaused} from "../src/libraries/LibAppStorage.sol";

contract EmergencyFacetTest is DiamondTestHelper {

    function test_emergencyPause_pausesSystem() public {
        vm.prank(pauser);
        EmergencyFacet(diamond).emergencyPause();

        vm.prank(seller);
        vm.expectRevert(SystemPaused.selector);
        kyc().initiateKYC(seller, keccak256("id"), LibAppStorage.KYCLevel.BASIC, keccak256("US"));
    }

    function test_emergencyPause_revertsIfNotPauser() public {
        vm.prank(seller);
        vm.expectRevert();
        EmergencyFacet(diamond).emergencyPause();
    }

    function test_emergencyPause_revertsIfAlreadyPaused() public {
        vm.prank(pauser);
        EmergencyFacet(diamond).emergencyPause();

        vm.prank(pauser);
        vm.expectRevert();
        EmergencyFacet(diamond).emergencyPause();
    }

    function test_emergencyUnpause_resumesSystem() public {
        vm.prank(pauser);
        EmergencyFacet(diamond).emergencyPause();

        vm.prank(owner);
        EmergencyFacet(diamond).emergencyUnpause();

        vm.prank(seller);
        kyc().initiateKYC(seller, keccak256("id"), LibAppStorage.KYCLevel.BASIC, keccak256("US"));
    }

    function test_emergencyUnpause_revertsIfNotPaused() public {
        vm.prank(owner);
        vm.expectRevert();
        EmergencyFacet(diamond).emergencyUnpause();
    }

    function test_emergencyUnpause_revertsIfNotEmergencyAdmin() public {
        vm.prank(pauser);
        EmergencyFacet(diamond).emergencyPause();

        vm.prank(seller);
        vm.expectRevert();
        EmergencyFacet(diamond).emergencyUnpause();
    }

    function test_scheduleEmergencyUpgrade_emitsEvent() public {
        vm.expectEmit(false, false, false, false, diamond);
        emit EmergencyFacet.EmergencyUpgradeScheduled(bytes32(0), 0);

        vm.prank(owner);
        EmergencyFacet(diamond).scheduleEmergencyUpgrade(keccak256("upgrade-1"), 24 hours);
    }

    function test_scheduleEmergencyUpgrade_revertsIfTimelockTooShort() public {
        vm.prank(owner);
        vm.expectRevert();
        EmergencyFacet(diamond).scheduleEmergencyUpgrade(keccak256("upgrade"), 1 hours);
    }

    function test_scheduleEmergencyUpgrade_revertsIfNotEmergencyAdmin() public {
        vm.prank(seller);
        vm.expectRevert();
        EmergencyFacet(diamond).scheduleEmergencyUpgrade(keccak256("upgrade"), 24 hours);
    }

    function test_emergencyWithdraw_ethToTreasury() public {
        vm.deal(diamond, 1 ether);
        uint256 before = treasury.balance;

        vm.prank(owner);
        EmergencyFacet(diamond).emergencyWithdraw(address(0), 1 ether);

        assertEq(treasury.balance, before + 1 ether);
    }

    /// @notice Assert that scheduleEmergencyUpgrade is informational only:
    ///         it emits an event but has no execution path that can bypass
    ///         the DiamondCutFacet timelock.
    function test_scheduleEmergencyUpgrade_cannotBypassDiamondCutTimelock() public {
        vm.prank(owner);
        EmergencyFacet(diamond).scheduleEmergencyUpgrade(keccak256("upgrade-id"), 24 hours);

        vm.warp(block.timestamp + 25 hours);

        IDiamondCutMin.FacetCut[] memory cuts = new IDiamondCutMin.FacetCut[](0);
        vm.prank(owner);
        vm.expectRevert(); // TimelockRequired
        IDiamondCutMin(diamond).diamondCut(cuts, address(0), "");
    }
}

interface IDiamondCutMin {
    enum FacetCutAction { Add, Replace, Remove }
    struct FacetCut {
        address facetAddress;
        FacetCutAction action;
        bytes4[] functionSelectors;
    }
    function diamondCut(FacetCut[] calldata, address, bytes calldata) external;
}
