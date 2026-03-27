// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibDiamond} from "../libraries/LibDiamond.sol";
import {LibRoles} from "../libraries/LibRoles.sol";
import {IDiamondCut} from "../interfaces/IDiamondCut.sol";
import {IERC165} from "../interfaces/IERC165.sol";

/// @title SuretyDiamond
/// @author Surety Compliance System
/// @notice Main EIP-2535 diamond proxy contract for the Surety compliance engine
/// @dev Implements the diamond fallback routing pattern with a 48-hour upgrade timelock
///      for regulatory compliance auditability. All compliance logic lives in facets.
contract SuretyDiamond {

    // ============ Events ============

    event DiamondUpgradeScheduled(bytes32 indexed upgradeId, uint256 executeAfter);
    event DiamondUpgradeExecuted(bytes32 indexed upgradeId);
    event DiamondUpgradeCancelled(bytes32 indexed upgradeId);

    // ============ Errors ============

    error FunctionDoesNotExist();
    error UpgradeNotReady();
    error UpgradeAlreadyExecuted();
    error TimelockTooShort();

    // ============ Structs ============

    struct ScheduledUpgrade {
        IDiamondCut.FacetCut[] facetCuts;
        address init;
        bytes initData;
        uint256 executeAfter;
        bool executed;
    }

    mapping(bytes32 => ScheduledUpgrade) public scheduledUpgrades;

    // ============ Constructor ============

    /// @notice Initialize the diamond with owner, timelock, and initial facet cuts
    /// @param _owner Initial contract owner (receives DEFAULT_ADMIN_ROLE)
    /// @param _timelockDuration Upgrade timelock in seconds (minimum 48 hours)
    /// @param _initialCuts Facet cuts to register at deploy time (bootstraps the routing table)
    /// @param _init Optional initializer contract address (address(0) to skip)
    /// @param _initData Calldata for the initializer
    constructor(
        address _owner,
        uint256 _timelockDuration,
        IDiamondCut.FacetCut[] memory _initialCuts,
        address _init,
        bytes memory _initData
    ) {
        if (_timelockDuration < 48 hours) revert TimelockTooShort();

        // Grant initial admin role
        LibRoles.grantRole(LibRoles.DEFAULT_ADMIN_ROLE, _owner);

        // Initialize diamond storage and ownership
        LibDiamond.setContractOwner(_owner);

        // Register ERC165 support
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        ds.supportedInterfaces[type(IERC165).interfaceId] = true;

        // Register all facets — called directly (not via fallback) to bootstrap the routing table
        LibDiamond.diamondCut(_initialCuts, _init, _initData);
    }

    // ============ Upgrade Timelock Functions ============
    // TODO: Implement scheduleUpgrade(), executeUpgrade(), cancelUpgrade()
    // These should live in DiamondCutFacet and call LibDiamond.diamondCut()
    // See docs/architecture.md for design rationale.

    // ============ Fallback - EIP-2535 Routing ============

    /// @notice Routes all calls to the appropriate facet via delegatecall
    /// @dev msg.sig is looked up in LibDiamond.DiamondStorage.selectorToFacetAndPosition
    fallback() external payable {
        LibDiamond.DiamondStorage storage ds = LibDiamond.diamondStorage();
        address facet = ds.selectorToFacetAndPosition[msg.sig].facetAddress;

        if (facet == address(0)) revert FunctionDoesNotExist();

        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), facet, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    receive() external payable {}
}
