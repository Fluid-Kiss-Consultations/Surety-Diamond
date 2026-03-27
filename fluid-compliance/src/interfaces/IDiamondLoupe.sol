// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IDiamondLoupe
/// @notice EIP-2535 Diamond Standard - introspection interface
/// @dev See https://eips.ethereum.org/EIPS/eip-2535
interface IDiamondLoupe {

    struct Facet {
        address facetAddress;
        bytes4[] functionSelectors;
    }

    /// @notice Returns all facets and their selectors
    function facets() external view returns (Facet[] memory facets_);

    /// @notice Returns all function selectors for a given facet address
    function facetFunctionSelectors(address _facet) external view returns (bytes4[] memory facetFunctionSelectors_);

    /// @notice Returns all facet addresses used by the diamond
    function facetAddresses() external view returns (address[] memory facetAddresses_);

    /// @notice Returns the facet address that handles a given selector
    function facetAddress(bytes4 _functionSelector) external view returns (address facetAddress_);
}
