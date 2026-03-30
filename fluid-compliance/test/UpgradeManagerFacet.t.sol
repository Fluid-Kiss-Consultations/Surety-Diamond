// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondTestHelper} from "./helpers/DiamondTestHelper.sol";
import {IUpgradeManagerFacet} from "../src/interfaces/IUpgradeManagerFacet.sol";
import {LibAppStorage} from "../src/libraries/LibAppStorage.sol";
import {LibRoles} from "../src/libraries/LibRoles.sol";

/// @notice Tests for the UpgradeManagerFacet
contract UpgradeManagerFacetTest is DiamondTestHelper {

    bytes32 constant UPGRADE_ID = keccak256("test-upgrade-1");
    bytes32 constant LAYOUT_HASH = keccak256("test-layout-hash");

    // ============ Storage Layout Tests ============

    function test_registerStorageLayout() public {
        LibAppStorage.StorageSlotDescriptor[] memory layout = _buildTestLayout();

        vm.prank(upgradeMgr);
        upgradeManager().registerStorageLayout(address(1), layout);

        LibAppStorage.StorageSlotDescriptor[] memory stored = upgradeManager().getStorageLayout(address(1));
        assertEq(stored.length, 2);
        assertEq(stored[0].slot, 0);
        assertEq(stored[0].size, 32);
        assertEq(stored[1].slot, 32);
        assertEq(stored[1].size, 32);
    }

    function test_registerStorageLayout_revertsEmptyLayout() public {
        LibAppStorage.StorageSlotDescriptor[] memory layout = new LibAppStorage.StorageSlotDescriptor[](0);

        vm.prank(upgradeMgr);
        vm.expectRevert(IUpgradeManagerFacet.EmptyStorageLayout.selector);
        upgradeManager().registerStorageLayout(address(1), layout);
    }

    function test_validateStorageLayout() public {
        LibAppStorage.StorageSlotDescriptor[] memory layout = _buildTestLayout();

        vm.prank(upgradeMgr);
        upgradeManager().registerStorageLayout(address(1), layout);

        bytes32 expectedHash = keccak256(abi.encode(layout));
        assertTrue(upgradeManager().validateStorageLayout(address(1), expectedHash));
        assertFalse(upgradeManager().validateStorageLayout(address(1), bytes32(uint256(999))));
    }

    function test_validateStorageLayout_noLayout() public view {
        assertFalse(upgradeManager().validateStorageLayout(address(99), LAYOUT_HASH));
    }

    function test_getStorageLayout_empty() public view {
        LibAppStorage.StorageSlotDescriptor[] memory layout = upgradeManager().getStorageLayout(address(99));
        assertEq(layout.length, 0);
    }

    // ============ Upgrade Proposal Tests ============

    function test_proposeUpgrade() public {
        // Set required approvals first
        vm.prank(owner);
        upgradeManager().setRequiredApprovals(2);

        vm.prank(upgradeMgr);
        upgradeManager().proposeUpgrade(UPGRADE_ID, "Test upgrade", LAYOUT_HASH);

        (
            bytes32 id,
            address proposer,
            uint256 proposedAt,
            uint256 approvalsRequired,
            uint256 approvalsReceived,
            LibAppStorage.UpgradeStatus status
        ) = upgradeManager().getUpgradeProposal(UPGRADE_ID);

        assertEq(id, UPGRADE_ID);
        assertEq(proposer, upgradeMgr);
        assertGt(proposedAt, 0);
        assertEq(approvalsRequired, 2);
        assertEq(approvalsReceived, 0);
        assertTrue(status == LibAppStorage.UpgradeStatus.PROPOSED);
    }

    function test_proposeUpgrade_defaultApprovals() public {
        vm.prank(upgradeMgr);
        upgradeManager().proposeUpgrade(UPGRADE_ID, "Test upgrade", LAYOUT_HASH);

        (,,, uint256 approvalsRequired,,) = upgradeManager().getUpgradeProposal(UPGRADE_ID);
        assertEq(approvalsRequired, 1);
    }

    function test_proposeUpgrade_snapshotCreated() public {
        vm.prank(upgradeMgr);
        upgradeManager().proposeUpgrade(UPGRADE_ID, "Test upgrade", LAYOUT_HASH);

        LibAppStorage.FacetSnapshot[] memory snapshots = upgradeManager().getPreUpgradeSnapshot(UPGRADE_ID);
        // Should have snapshots for all 13 facets
        assertEq(snapshots.length, 13);
    }

    // ============ Approve Upgrade Tests ============

    function test_approveUpgrade_singleApproval() public {
        vm.prank(upgradeMgr);
        upgradeManager().proposeUpgrade(UPGRADE_ID, "Test upgrade", LAYOUT_HASH);

        vm.prank(upgradeMgr);
        upgradeManager().approveUpgrade(UPGRADE_ID);

        (,,,, uint256 approvalsReceived, LibAppStorage.UpgradeStatus status) =
            upgradeManager().getUpgradeProposal(UPGRADE_ID);
        assertEq(approvalsReceived, 1);
        assertTrue(status == LibAppStorage.UpgradeStatus.APPROVED);
    }

    function test_approveUpgrade_multiSig() public {
        // Grant a second upgrade manager
        address upgradeMgr2 = makeAddr("upgradeManager2");
        _grantRole(LibRoles.UPGRADE_MANAGER_ROLE, upgradeMgr2);

        vm.prank(owner);
        upgradeManager().setRequiredApprovals(2);

        vm.prank(upgradeMgr);
        upgradeManager().proposeUpgrade(UPGRADE_ID, "Test upgrade", LAYOUT_HASH);

        // First approval - still PROPOSED
        vm.prank(upgradeMgr);
        upgradeManager().approveUpgrade(UPGRADE_ID);
        (,,,, uint256 received1, LibAppStorage.UpgradeStatus status1) =
            upgradeManager().getUpgradeProposal(UPGRADE_ID);
        assertEq(received1, 1);
        assertTrue(status1 == LibAppStorage.UpgradeStatus.PROPOSED);

        // Second approval - now APPROVED
        vm.prank(upgradeMgr2);
        upgradeManager().approveUpgrade(UPGRADE_ID);
        (,,,, uint256 received2, LibAppStorage.UpgradeStatus status2) =
            upgradeManager().getUpgradeProposal(UPGRADE_ID);
        assertEq(received2, 2);
        assertTrue(status2 == LibAppStorage.UpgradeStatus.APPROVED);
    }

    function test_approveUpgrade_revertsAlreadyApproved() public {
        vm.prank(upgradeMgr);
        upgradeManager().proposeUpgrade(UPGRADE_ID, "Test upgrade", LAYOUT_HASH);

        vm.prank(owner);
        upgradeManager().setRequiredApprovals(2);

        vm.prank(upgradeMgr);
        upgradeManager().approveUpgrade(UPGRADE_ID);

        vm.prank(upgradeMgr);
        vm.expectRevert(abi.encodeWithSelector(IUpgradeManagerFacet.AlreadyApproved.selector, upgradeMgr, UPGRADE_ID));
        upgradeManager().approveUpgrade(UPGRADE_ID);
    }

    function test_approveUpgrade_revertsNotFound() public {
        vm.prank(upgradeMgr);
        vm.expectRevert(abi.encodeWithSelector(IUpgradeManagerFacet.UpgradeNotFound.selector, UPGRADE_ID));
        upgradeManager().approveUpgrade(UPGRADE_ID);
    }

    // ============ Cancel Upgrade Tests ============

    function test_cancelUpgrade() public {
        vm.prank(upgradeMgr);
        upgradeManager().proposeUpgrade(UPGRADE_ID, "Test upgrade", LAYOUT_HASH);

        vm.prank(upgradeMgr);
        upgradeManager().cancelUpgrade(UPGRADE_ID);

        (,,,,, LibAppStorage.UpgradeStatus status) = upgradeManager().getUpgradeProposal(UPGRADE_ID);
        assertTrue(status == LibAppStorage.UpgradeStatus.CANCELLED);
    }

    function test_cancelUpgrade_revertsNotFound() public {
        vm.prank(upgradeMgr);
        vm.expectRevert(abi.encodeWithSelector(IUpgradeManagerFacet.UpgradeNotFound.selector, UPGRADE_ID));
        upgradeManager().cancelUpgrade(UPGRADE_ID);
    }

    // ============ Record Upgrade & History Tests ============

    function test_recordUpgrade() public {
        vm.prank(upgradeMgr);
        upgradeManager().recordUpgrade(UPGRADE_ID, 2, 5, 3, 1);

        LibAppStorage.UpgradeRecord[] memory history = upgradeManager().getUpgradeHistory();
        assertEq(history.length, 1);
        assertEq(history[0].upgradeId, UPGRADE_ID);
        assertEq(history[0].executor, upgradeMgr);
        assertEq(history[0].facetsChanged, 2);
        assertEq(history[0].selectorsAdded, 5);
        assertEq(history[0].selectorsReplaced, 3);
        assertEq(history[0].selectorsRemoved, 1);
    }

    function test_recordUpgrade_updatesProposalStatus() public {
        vm.prank(upgradeMgr);
        upgradeManager().proposeUpgrade(UPGRADE_ID, "Test upgrade", LAYOUT_HASH);

        vm.prank(upgradeMgr);
        upgradeManager().recordUpgrade(UPGRADE_ID, 1, 2, 0, 0);

        (,,,,, LibAppStorage.UpgradeStatus status) = upgradeManager().getUpgradeProposal(UPGRADE_ID);
        assertTrue(status == LibAppStorage.UpgradeStatus.EXECUTED);
    }

    // ============ Configuration Tests ============

    function test_setRequiredApprovals() public {
        vm.prank(owner);
        upgradeManager().setRequiredApprovals(3);

        // Verify by proposing (will use the new threshold)
        vm.prank(upgradeMgr);
        upgradeManager().proposeUpgrade(UPGRADE_ID, "Test", LAYOUT_HASH);

        (,,, uint256 approvalsRequired,,) = upgradeManager().getUpgradeProposal(UPGRADE_ID);
        assertEq(approvalsRequired, 3);
    }

    function test_setRequiredApprovals_revertsZero() public {
        vm.prank(owner);
        vm.expectRevert(IUpgradeManagerFacet.InvalidApprovalCount.selector);
        upgradeManager().setRequiredApprovals(0);
    }

    // ============ Access Control Tests ============

    function test_registerStorageLayout_revertsUnauthorized() public {
        LibAppStorage.StorageSlotDescriptor[] memory layout = _buildTestLayout();

        vm.prank(buyer);
        vm.expectRevert();
        upgradeManager().registerStorageLayout(address(1), layout);
    }

    function test_proposeUpgrade_revertsUnauthorized() public {
        vm.prank(buyer);
        vm.expectRevert();
        upgradeManager().proposeUpgrade(UPGRADE_ID, "Test", LAYOUT_HASH);
    }

    function test_setRequiredApprovals_revertsNonOwner() public {
        vm.prank(upgradeMgr);
        vm.expectRevert();
        upgradeManager().setRequiredApprovals(2);
    }

    // ============ Pause Tests ============

    function test_proposeUpgrade_revertsWhenPaused() public {
        vm.prank(pauser);
        (bool success,) = diamond.call(abi.encodeWithSignature("emergencyPause()"));
        assertTrue(success);

        vm.prank(upgradeMgr);
        vm.expectRevert();
        upgradeManager().proposeUpgrade(UPGRADE_ID, "Test", LAYOUT_HASH);
    }

    // ============ Helpers ============

    function _buildTestLayout() internal pure returns (LibAppStorage.StorageSlotDescriptor[] memory layout) {
        layout = new LibAppStorage.StorageSlotDescriptor[](2);
        layout[0] = LibAppStorage.StorageSlotDescriptor({
            slot: 0,
            size: 32,
            name: keccak256("merkleRoot"),
            typeHash: keccak256("bytes32")
        });
        layout[1] = LibAppStorage.StorageSlotDescriptor({
            slot: 32,
            size: 32,
            name: keccak256("lastUpdate"),
            typeHash: keccak256("uint256")
        });
    }
}
