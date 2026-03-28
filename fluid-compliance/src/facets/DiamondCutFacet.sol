// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibDiamond} from "../libraries/LibDiamond.sol";
import {LibAppStorage} from "../libraries/LibAppStorage.sol";
import {IDiamondCut} from "../interfaces/IDiamondCut.sol";

/// @title DiamondCutFacet
/// @notice EIP-2535 facet management with timelock enforcement
/// @dev Handles Add/Replace/Remove operations for facet function selectors.
///      All upgrades must be scheduled through the timelock mechanism.
///      The direct diamondCut() path is disabled after initialization — use
///      scheduleDiamondCut() + executeDiamondCut() instead.
contract DiamondCutFacet is IDiamondCut {

    uint256 public constant MIN_TIMELOCK = 48 hours;

    error NotContractOwner();
    error TimelockNotExpired(uint256 executeAfter, uint256 currentTime);
    error UpgradeNotScheduled();
    error UpgradeAlreadyExecuted();
    error DelayTooShort(uint256 provided, uint256 minimum);
    /// @notice Reverts when owner attempts a direct cut after the system has been initialized
    error TimelockRequired();

    // ============ Schedule ============

    /// @notice Schedule a diamond upgrade subject to the timelock
    /// @param _diamondCut Array of facet cuts to apply when executed
    /// @param _init Optional initializer address (address(0) to skip)
    /// @param _calldata Calldata for the initializer
    /// @param _delay Seconds to wait before the upgrade can be executed (minimum MIN_TIMELOCK)
    /// @return upgradeId Unique identifier for this scheduled upgrade
    function scheduleDiamondCut(
        FacetCut[] calldata _diamondCut,
        address _init,
        bytes calldata _calldata,
        uint256 _delay
    ) external returns (bytes32 upgradeId) {
        LibDiamond.enforceIsContractOwner();
        if (_delay < MIN_TIMELOCK) revert DelayTooShort(_delay, MIN_TIMELOCK);

        upgradeId = keccak256(abi.encode(_diamondCut, _init, _calldata, block.timestamp));
        LibAppStorage.ScheduledCut storage sc = LibAppStorage.appStorage().scheduledCuts[upgradeId];
        sc.init = _init;
        sc.initCalldata = _calldata;
        sc.executeAfter = block.timestamp + _delay;

        for (uint256 i = 0; i < _diamondCut.length; i++) {
            sc.cuts.push(_diamondCut[i]);
        }
    }

    // ============ Execute ============

    /// @notice Execute a previously scheduled upgrade after the timelock expires
    /// @param upgradeId The identifier returned by scheduleDiamondCut
    function executeDiamondCut(bytes32 upgradeId) external {
        LibDiamond.enforceIsContractOwner();
        LibAppStorage.ScheduledCut storage sc = LibAppStorage.appStorage().scheduledCuts[upgradeId];

        if (sc.executeAfter == 0) revert UpgradeNotScheduled();
        if (sc.executed) revert UpgradeAlreadyExecuted();
        if (block.timestamp < sc.executeAfter) {
            revert TimelockNotExpired(sc.executeAfter, block.timestamp);
        }

        sc.executed = true;
        LibDiamond.diamondCut(sc.cuts, sc.init, sc.initCalldata);
    }

    // ============ IDiamondCut ============

    /// @notice Direct cut — disabled after initialization. Reverts with TimelockRequired
    ///         once timelockDuration has been set by DiamondInit. Use scheduleDiamondCut()
    ///         followed by executeDiamondCut() for all post-deploy upgrades.
    /// @param _diamondCut Array of facet cuts (unused post-init)
    /// @param _init Optional initializer address (unused post-init)
    /// @param _calldata Calldata for the initializer (unused post-init)
    function diamondCut(
        FacetCut[] calldata _diamondCut,
        address _init,
        bytes calldata _calldata
    ) external override {
        LibDiamond.enforceIsContractOwner();
        // Revert if the system has been initialized — all post-init cuts must go through the timelock
        if (LibAppStorage.appStorage().timelockDuration != 0) revert TimelockRequired();
        LibDiamond.diamondCut(_diamondCut, _init, _calldata);
    }
}
