// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondTestHelper} from "./helpers/DiamondTestHelper.sol";
import {DiamondCutFacet} from "../src/facets/DiamondCutFacet.sol";
import {IDiamondCut} from "../src/interfaces/IDiamondCut.sol";
import {IDiamondLoupe} from "../src/interfaces/IDiamondLoupe.sol";
import {IERC165} from "../src/interfaces/IERC165.sol";
import {LibAppStorage} from "../src/libraries/LibAppStorage.sol";

contract DiamondTest is DiamondTestHelper {

    // ============================================================
    // Loupe: facetAddresses
    // ============================================================

    function test_loupe_returns11Facets() public view {
        address[] memory addrs = loupe().facetAddresses();
        assertEq(addrs.length, 11);
    }

    function test_loupe_allFacetsHaveSelectors() public view {
        IDiamondLoupe.Facet[] memory facets = loupe().facets();
        for (uint256 i = 0; i < facets.length; i++) {
            assertGt(facets[i].functionSelectors.length, 0);
        }
    }

    // ============================================================
    // Loupe: facetAddress
    // ============================================================

    function test_loupe_facetAddressForKnownSelector() public view {
        bytes4 sel = IKYCFacetMin.isKYCCompliant.selector;
        address facetAddr = loupe().facetAddress(sel);
        assertNotEq(facetAddr, address(0));
    }

    function test_loupe_unknownSelectorReturnsZero() public view {
        bytes4 unknown = 0xdeadbeef;
        address facetAddr = loupe().facetAddress(unknown);
        assertEq(facetAddr, address(0));
    }

    // ============================================================
    // ERC165
    // ============================================================

    function test_supportsInterface_erc165() public view {
        assertTrue(IERC165(diamond).supportsInterface(0x01ffc9a7));
    }

    // ============================================================
    // Fallback: unknown function reverts
    // ============================================================

    function test_fallback_unknownSelectorReverts() public {
        (bool ok, bytes memory err) = diamond.call(abi.encodeWithSelector(0xdeadbeef));
        assertFalse(ok);
        assertTrue(err.length > 0);
    }

    // ============================================================
    // Upgrade timelock
    // ============================================================

    function test_scheduleDiamondCut_requiresMinDelay() public {
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](0);

        vm.prank(owner);
        vm.expectRevert(); // delay too short (< 48 hours)
        DiamondCutFacet(diamond).scheduleDiamondCut(cuts, address(0), "", 1 hours);
    }

    function test_scheduleDiamondCut_schedules() public {
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](0);

        vm.prank(owner);
        bytes32 upgradeId = DiamondCutFacet(diamond).scheduleDiamondCut(cuts, address(0), "", 48 hours);
        assertNotEq(upgradeId, bytes32(0));
    }

    function test_executeDiamondCut_revertsBeforeTimelock() public {
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](0);

        vm.prank(owner);
        bytes32 upgradeId = DiamondCutFacet(diamond).scheduleDiamondCut(cuts, address(0), "", 48 hours);

        vm.prank(owner);
        vm.expectRevert(); // timelock not expired
        DiamondCutFacet(diamond).executeDiamondCut(upgradeId);
    }

    function test_executeDiamondCut_succeedsAfterTimelock() public {
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](0);

        vm.prank(owner);
        bytes32 upgradeId = DiamondCutFacet(diamond).scheduleDiamondCut(cuts, address(0), "", 48 hours);

        vm.warp(block.timestamp + 49 hours);

        vm.prank(owner);
        DiamondCutFacet(diamond).executeDiamondCut(upgradeId); // should not revert
    }

    // ============================================================
    // Direct diamondCut — disabled post-initialization (CRITICAL-1)
    // ============================================================

    function test_diamondCut_revertsIfNotOwner() public {
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](0);
        vm.prank(seller);
        vm.expectRevert();
        IDiamondCut(diamond).diamondCut(cuts, address(0), "");
    }

    function test_diamondCut_revertsForOwnerPostInit() public {
        // After DiamondInit sets timelockDuration, direct cuts must revert
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](0);
        vm.prank(owner);
        vm.expectRevert(); // TimelockRequired
        IDiamondCut(diamond).diamondCut(cuts, address(0), "");
    }
}

interface IKYCFacetMin {
    function isKYCCompliant(address entity, LibAppStorage.KYCLevel requiredLevel) external view returns (bool);
}
