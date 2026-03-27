// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IDiamondCut
/// @notice EIP-2535 Diamond Standard - facet management interface
/// @dev See https://eips.ethereum.org/EIPS/eip-2535
interface IDiamondCut {

    enum FacetCutAction { Add, Replace, Remove }

    struct FacetCut {
        address facetAddress;
        FacetCutAction action;
        bytes4[] functionSelectors;
    }

    /// @notice Add/replace/remove facet functions
    /// @param _diamondCut Array of FacetCut structs
    /// @param _init Address of contract or facet to execute _calldata
    /// @param _calldata Function call including function selector and arguments
    function diamondCut(
        FacetCut[] calldata _diamondCut,
        address _init,
        bytes calldata _calldata
    ) external;

    event DiamondCut(FacetCut[] _diamondCut, address _init, bytes _calldata);
}
