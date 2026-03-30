// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title IUpgradeManagerFacet
/// @notice Interface for upgrade governance with storage layout validation and multi-sig approval
interface IUpgradeManagerFacet {

    // ============ Events ============

    event StorageLayoutRegistered(address indexed facet, bytes32 layoutHash, uint256 timestamp);
    event UpgradeProposed(bytes32 indexed upgradeId, address indexed proposer, uint256 timestamp);
    event UpgradeApproved(bytes32 indexed upgradeId, address indexed approver, uint256 approvalsReceived, uint256 timestamp);
    event UpgradeCancelled(bytes32 indexed upgradeId, address indexed cancelledBy, uint256 timestamp);
    event UpgradeRecorded(bytes32 indexed upgradeId, address indexed executor, uint256 timestamp);
    event RequiredApprovalsUpdated(uint256 oldCount, uint256 newCount, uint256 timestamp);

    // ============ Errors ============

    error UpgradeNotFound(bytes32 upgradeId);
    error UpgradeNotProposed(bytes32 upgradeId);
    error AlreadyApproved(address approver, bytes32 upgradeId);
    error InsufficientApprovals(uint256 received, uint256 required);
    error InvalidApprovalCount();
    error StorageLayoutMismatch(bytes32 expected, bytes32 actual);
    error UpgradeNotApproved(bytes32 upgradeId);
    error EmptyStorageLayout();

    // ============ Storage Layout Management ============

    /// @notice Register storage layout descriptors for a facet
    /// @param facet The facet contract address
    /// @param layout Array of storage slot descriptors
    function registerStorageLayout(
        address facet,
        LibAppStorage.StorageSlotDescriptor[] calldata layout
    ) external;

    /// @notice Validate a facet's registered layout against an expected hash
    /// @param facet The facet contract address
    /// @param expectedHash The expected keccak256 hash of the layout
    /// @return valid True if the registered layout matches the expected hash
    function validateStorageLayout(
        address facet,
        bytes32 expectedHash
    ) external view returns (bool valid);

    /// @notice Get the registered storage layout for a facet
    /// @param facet The facet contract address
    /// @return layout Array of storage slot descriptors
    function getStorageLayout(
        address facet
    ) external view returns (LibAppStorage.StorageSlotDescriptor[] memory layout);

    // ============ Upgrade Proposals & Multi-sig ============

    /// @notice Propose an upgrade for multi-sig approval
    /// @param upgradeId The scheduled cut identifier from DiamondCutFacet
    /// @param description Human-readable upgrade description
    /// @param storageLayoutHash Expected post-upgrade storage layout hash
    function proposeUpgrade(
        bytes32 upgradeId,
        string calldata description,
        bytes32 storageLayoutHash
    ) external;

    /// @notice Approve a proposed upgrade
    /// @param upgradeId The upgrade proposal identifier
    function approveUpgrade(bytes32 upgradeId) external;

    /// @notice Cancel a proposed upgrade
    /// @param upgradeId The upgrade proposal identifier
    function cancelUpgrade(bytes32 upgradeId) external;

    /// @notice Get details of an upgrade proposal
    /// @param upgradeId The upgrade proposal identifier
    /// @return id The upgrade identifier
    /// @return proposer The address that proposed the upgrade
    /// @return proposedAt Timestamp when proposed
    /// @return approvalsRequired Number of approvals needed
    /// @return approvalsReceived Number of approvals received
    /// @return status Current proposal status
    function getUpgradeProposal(bytes32 upgradeId) external view returns (
        bytes32 id,
        address proposer,
        uint256 proposedAt,
        uint256 approvalsRequired,
        uint256 approvalsReceived,
        LibAppStorage.UpgradeStatus status
    );

    // ============ Configuration ============

    /// @notice Set the number of approvals required for upgrade proposals
    /// @param count Number of required approvals (must be > 0)
    function setRequiredApprovals(uint256 count) external;

    // ============ Upgrade History & Rollback ============

    /// @notice Get complete upgrade history
    /// @return history Array of completed upgrade records
    function getUpgradeHistory() external view returns (LibAppStorage.UpgradeRecord[] memory history);

    /// @notice Record a completed upgrade with metadata
    /// @param upgradeId The upgrade identifier
    /// @param facetsChanged Number of facets affected
    /// @param added Number of selectors added
    /// @param replaced Number of selectors replaced
    /// @param removed Number of selectors removed
    function recordUpgrade(
        bytes32 upgradeId,
        uint256 facetsChanged,
        uint256 added,
        uint256 replaced,
        uint256 removed
    ) external;

    /// @notice Get the pre-upgrade facet snapshot for rollback reference
    /// @param upgradeId The upgrade identifier
    /// @return snapshots Array of facet snapshots taken before the upgrade
    function getPreUpgradeSnapshot(
        bytes32 upgradeId
    ) external view returns (LibAppStorage.FacetSnapshot[] memory snapshots);
}
