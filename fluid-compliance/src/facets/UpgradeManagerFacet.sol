// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage, SystemPaused} from "../libraries/LibAppStorage.sol";
import {LibRoles} from "../libraries/LibRoles.sol";
import {LibDiamond} from "../libraries/LibDiamond.sol";
import {IUpgradeManagerFacet} from "../interfaces/IUpgradeManagerFacet.sol";

/// @title UpgradeManagerFacet
/// @author Surety Compliance System
/// @notice Enhanced upgrade governance with storage layout validation and multi-sig approval
/// @dev Complements DiamondCutFacet by adding pre-upgrade validation, multi-sig governance,
///      upgrade history tracking, and rollback snapshots for EIP-2535 diamond upgrades.
contract UpgradeManagerFacet is IUpgradeManagerFacet {

    // ============ Modifiers ============

    modifier whenNotPaused() {
        if (LibAppStorage.isPaused()) revert SystemPaused();
        _;
    }

    modifier onlyUpgradeManager() {
        LibRoles.checkRole(LibRoles.UPGRADE_MANAGER_ROLE);
        _;
    }

    modifier onlyOwner() {
        LibDiamond.enforceIsContractOwner();
        _;
    }

    // ============ Storage Layout Management ============

    /// @inheritdoc IUpgradeManagerFacet
    function registerStorageLayout(
        address facet,
        LibAppStorage.StorageSlotDescriptor[] calldata layout
    ) external whenNotPaused onlyUpgradeManager {
        if (layout.length == 0) revert EmptyStorageLayout();

        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        // Clear existing layout
        delete s.facetStorageLayouts[facet];

        // Store new layout
        for (uint256 i = 0; i < layout.length; i++) {
            s.facetStorageLayouts[facet].push(layout[i]);
        }

        bytes32 layoutHash = keccak256(abi.encode(layout));
        _logAction("STORAGE_LAYOUT_REGISTERED");
        emit StorageLayoutRegistered(facet, layoutHash, block.timestamp);
    }

    /// @inheritdoc IUpgradeManagerFacet
    function validateStorageLayout(
        address facet,
        bytes32 expectedHash
    ) external view returns (bool valid) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.StorageSlotDescriptor[] storage layout = s.facetStorageLayouts[facet];

        if (layout.length == 0) return false;

        // Rebuild hash from stored descriptors
        LibAppStorage.StorageSlotDescriptor[] memory layoutMem = new LibAppStorage.StorageSlotDescriptor[](layout.length);
        for (uint256 i = 0; i < layout.length; i++) {
            layoutMem[i] = layout[i];
        }

        bytes32 actualHash = keccak256(abi.encode(layoutMem));
        return actualHash == expectedHash;
    }

    /// @inheritdoc IUpgradeManagerFacet
    function getStorageLayout(
        address facet
    ) external view returns (LibAppStorage.StorageSlotDescriptor[] memory layout) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.StorageSlotDescriptor[] storage stored = s.facetStorageLayouts[facet];

        layout = new LibAppStorage.StorageSlotDescriptor[](stored.length);
        for (uint256 i = 0; i < stored.length; i++) {
            layout[i] = stored[i];
        }
    }

    // ============ Upgrade Proposals & Multi-sig ============

    /// @inheritdoc IUpgradeManagerFacet
    function proposeUpgrade(
        bytes32 upgradeId,
        string calldata description,
        bytes32 storageLayoutHash
    ) external whenNotPaused onlyUpgradeManager {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        LibAppStorage.UpgradeProposal storage proposal = s.upgradeProposals[upgradeId];
        if (proposal.proposer != address(0)) revert UpgradeNotFound(upgradeId);

        proposal.upgradeId = upgradeId;
        proposal.proposer = msg.sender;
        proposal.proposedAt = block.timestamp;
        proposal.approvalsRequired = s.requiredApprovals > 0 ? s.requiredApprovals : 1;
        proposal.approvalsReceived = 0;
        proposal.status = LibAppStorage.UpgradeStatus.PROPOSED;
        proposal.description = description;
        proposal.storageLayoutHash = storageLayoutHash;

        s.upgradeProposalIds.push(upgradeId);

        // Take snapshot of current facet state for rollback reference
        _takeSnapshot(upgradeId);

        _logAction("UPGRADE_PROPOSED");
        emit UpgradeProposed(upgradeId, msg.sender, block.timestamp);
    }

    /// @inheritdoc IUpgradeManagerFacet
    function approveUpgrade(bytes32 upgradeId) external whenNotPaused onlyUpgradeManager {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.UpgradeProposal storage proposal = s.upgradeProposals[upgradeId];

        if (proposal.proposer == address(0)) revert UpgradeNotFound(upgradeId);
        if (proposal.status != LibAppStorage.UpgradeStatus.PROPOSED) revert UpgradeNotProposed(upgradeId);
        if (proposal.approvals[msg.sender]) revert AlreadyApproved(msg.sender, upgradeId);

        proposal.approvals[msg.sender] = true;
        proposal.approvalsReceived++;

        if (proposal.approvalsReceived >= proposal.approvalsRequired) {
            proposal.status = LibAppStorage.UpgradeStatus.APPROVED;
        }

        _logAction("UPGRADE_APPROVED");
        emit UpgradeApproved(upgradeId, msg.sender, proposal.approvalsReceived, block.timestamp);
    }

    /// @inheritdoc IUpgradeManagerFacet
    function cancelUpgrade(bytes32 upgradeId) external whenNotPaused onlyUpgradeManager {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.UpgradeProposal storage proposal = s.upgradeProposals[upgradeId];

        if (proposal.proposer == address(0)) revert UpgradeNotFound(upgradeId);
        if (proposal.status != LibAppStorage.UpgradeStatus.PROPOSED &&
            proposal.status != LibAppStorage.UpgradeStatus.APPROVED) {
            revert UpgradeNotProposed(upgradeId);
        }

        proposal.status = LibAppStorage.UpgradeStatus.CANCELLED;

        _logAction("UPGRADE_CANCELLED");
        emit UpgradeCancelled(upgradeId, msg.sender, block.timestamp);
    }

    /// @inheritdoc IUpgradeManagerFacet
    function getUpgradeProposal(bytes32 upgradeId) external view returns (
        bytes32 id,
        address proposer,
        uint256 proposedAt,
        uint256 approvalsRequired,
        uint256 approvalsReceived,
        LibAppStorage.UpgradeStatus status
    ) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.UpgradeProposal storage proposal = s.upgradeProposals[upgradeId];

        return (
            proposal.upgradeId,
            proposal.proposer,
            proposal.proposedAt,
            proposal.approvalsRequired,
            proposal.approvalsReceived,
            proposal.status
        );
    }

    // ============ Configuration ============

    /// @inheritdoc IUpgradeManagerFacet
    function setRequiredApprovals(uint256 count) external whenNotPaused onlyOwner {
        if (count == 0) revert InvalidApprovalCount();

        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        uint256 oldCount = s.requiredApprovals;
        s.requiredApprovals = count;

        _logAction("REQUIRED_APPROVALS_UPDATED");
        emit RequiredApprovalsUpdated(oldCount, count, block.timestamp);
    }

    // ============ Upgrade History & Rollback ============

    /// @inheritdoc IUpgradeManagerFacet
    function getUpgradeHistory() external view returns (LibAppStorage.UpgradeRecord[] memory history) {
        return LibAppStorage.appStorage().upgradeHistory;
    }

    /// @inheritdoc IUpgradeManagerFacet
    function recordUpgrade(
        bytes32 upgradeId,
        uint256 facetsChanged,
        uint256 added,
        uint256 replaced,
        uint256 removed
    ) external whenNotPaused onlyUpgradeManager {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        bytes32 previousLayoutHash = s.currentStorageLayoutHash;
        bytes32 newLayoutHash = keccak256(abi.encodePacked(upgradeId, facetsChanged, added, replaced, removed, block.timestamp));
        s.currentStorageLayoutHash = newLayoutHash;

        s.upgradeHistory.push(LibAppStorage.UpgradeRecord({
            upgradeId: upgradeId,
            executor: msg.sender,
            executedAt: block.timestamp,
            facetsChanged: facetsChanged,
            selectorsAdded: added,
            selectorsReplaced: replaced,
            selectorsRemoved: removed,
            previousLayoutHash: previousLayoutHash,
            newLayoutHash: newLayoutHash
        }));

        // Update proposal status if exists
        LibAppStorage.UpgradeProposal storage proposal = s.upgradeProposals[upgradeId];
        if (proposal.proposer != address(0)) {
            proposal.status = LibAppStorage.UpgradeStatus.EXECUTED;
        }

        _logAction("UPGRADE_RECORDED");
        emit UpgradeRecorded(upgradeId, msg.sender, block.timestamp);
    }

    /// @inheritdoc IUpgradeManagerFacet
    function getPreUpgradeSnapshot(
        bytes32 upgradeId
    ) external view returns (LibAppStorage.FacetSnapshot[] memory snapshots) {
        return LibAppStorage.appStorage().preUpgradeSnapshots[upgradeId];
    }

    // ============ Internal Functions ============

    /// @dev Capture current facet configuration as a snapshot for rollback reference
    function _takeSnapshot(bytes32 upgradeId) internal {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();

        address[] memory facetAddresses = ds.facetAddresses;
        for (uint256 i = 0; i < facetAddresses.length; i++) {
            address facetAddr = facetAddresses[i];
            bytes4[] memory selectors = ds.facetFunctionSelectors[facetAddr].functionSelectors;

            LibAppStorage.FacetSnapshot memory snapshot = LibAppStorage.FacetSnapshot({
                facetAddress: facetAddr,
                selectors: selectors
            });

            s.preUpgradeSnapshots[upgradeId].push(snapshot);
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
