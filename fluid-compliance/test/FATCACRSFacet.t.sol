// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondTestHelper} from "./helpers/DiamondTestHelper.sol";
import {LibAppStorage} from "../src/libraries/LibAppStorage.sol";
import {IFATCACRSFacet} from "../src/interfaces/IFATCACRSFacet.sol";

contract FATCACRSFacetTest is DiamondTestHelper {

    // ============================================================
    // setTaxClassification
    // ============================================================

    function test_setTaxClassification_storesRecord() public {
        LibAppStorage.TaxClassification memory tc = _buildTaxClassification(
            LibAppStorage.FATCAClassification.US_PERSON,
            LibAppStorage.CRSEntityType.INDIVIDUAL
        );
        vm.prank(officer); // officer has TAX_OFFICER_ROLE in helper
        fatca().setTaxClassification(seller, tc);

        LibAppStorage.TaxClassification memory stored = fatca().getTaxClassification(seller);
        assertEq(uint8(stored.fatcaStatus), uint8(LibAppStorage.FATCAClassification.US_PERSON));
        assertEq(uint8(stored.crsType),     uint8(LibAppStorage.CRSEntityType.INDIVIDUAL));
    }

    function test_setTaxClassification_revertsIfNotTaxOfficer() public {
        vm.prank(seller);
        vm.expectRevert();
        fatca().setTaxClassification(seller, _buildTaxClassification(
            LibAppStorage.FATCAClassification.US_PERSON, LibAppStorage.CRSEntityType.INDIVIDUAL
        ));
    }

    // ============================================================
    // recordTaxForm
    // ============================================================

    function test_recordTaxForm_setsW8OnFile() public {
        vm.prank(officer);
        fatca().recordTaxForm(seller, keccak256("W8BEN"), keccak256("doc-hash"), block.timestamp + 365 days);

        LibAppStorage.TaxClassification memory stored = fatca().getTaxClassification(seller);
        assertTrue(stored.w8w9OnFile);
    }

    function test_recordTaxForm_revertsForInvalidFormType() public {
        vm.prank(officer);
        vm.expectRevert();
        fatca().recordTaxForm(seller, keccak256("W2"), keccak256("doc"), block.timestamp + 100 days);
    }

    // ============================================================
    // assessReportingRequirement
    // ============================================================

    function test_assessReportingRequirement_requiresForUSAboveThreshold() public {
        _setupKYCWithJurisdiction(seller, keccak256("US"));
        _setupKYCWithJurisdiction(buyer, keccak256("DE"));

        vm.prank(officer);
        (bool required, bytes32[] memory jurs) = fatca().assessReportingRequirement(
            keccak256("tx-1"), seller, buyer, 60_000 * 1e18, keccak256("INVOICE")
        );
        assertTrue(required);
        assertGt(jurs.length, 0);
    }

    function test_assessReportingRequirement_notRequiredBelowThreshold() public {
        _setupKYCWithJurisdiction(seller, keccak256("US"));
        _setupKYCWithJurisdiction(buyer, keccak256("US"));

        vm.prank(officer);
        (bool required,) = fatca().assessReportingRequirement(
            keccak256("tx-small"), seller, buyer, 1_000 * 1e18, keccak256("INVOICE")
        );
        assertFalse(required);
    }

    // ============================================================
    // createReportingObligation + markAsReported + getPendingObligations
    // ============================================================

    function test_createAndMarkObligation() public {
        vm.prank(officer);
        bytes32 oblId = fatca().createReportingObligation(
            seller, keccak256("US"), 100_000 * 1e18, keccak256("FATCA"), 2025
        );

        LibAppStorage.ReportingObligation[] memory pending = fatca().getPendingObligations(seller, 2025);
        assertEq(pending.length, 1);
        assertEq(pending[0].obligationId, oblId);

        vm.prank(officer);
        fatca().markAsReported(oblId);

        pending = fatca().getPendingObligations(seller, 2025);
        assertEq(pending.length, 0);
    }

    function test_markAsReported_emitsEvent() public {
        vm.prank(officer);
        bytes32 oblId = fatca().createReportingObligation(
            seller, keccak256("US"), 100_000 * 1e18, keccak256("FATCA"), 2025
        );

        vm.expectEmit(true, true, false, true);
        emit IFATCACRSFacet.ReportingObligationFulfilled(oblId, officer, block.timestamp);
        vm.prank(officer);
        fatca().markAsReported(oblId);
    }

    function test_getPendingObligations_filtersByYear() public {
        vm.startPrank(officer);
        fatca().createReportingObligation(seller, keccak256("US"), 100_000 * 1e18, keccak256("FATCA"), 2024);
        fatca().createReportingObligation(seller, keccak256("US"), 100_000 * 1e18, keccak256("FATCA"), 2025);
        vm.stopPrank();

        assertEq(fatca().getPendingObligations(seller, 2024).length, 1);
        assertEq(fatca().getPendingObligations(seller, 2025).length, 1);
        assertEq(fatca().getPendingObligations(seller, 0).length, 2); // 0 = all years
    }

    // ============================================================
    // checkWithholding
    // ============================================================

    function test_checkWithholding_usPayerToNonUs() public {
        _setupKYCWithJurisdiction(seller, keccak256("US"));
        _setupKYCWithJurisdiction(buyer, keccak256("DE"));

        (bool withhold, uint256 rate) = fatca().checkWithholding(seller, buyer, keccak256("DIVIDEND"));
        assertTrue(withhold);
        assertEq(rate, 3000); // 30%
    }

    function test_checkWithholding_noWithholdingForApprovedSameJurisdiction() public {
        _setupKYCWithJurisdiction(seller, keccak256("DE"));
        _setupKYCWithJurisdiction(buyer, keccak256("DE"));

        (bool withhold,) = fatca().checkWithholding(seller, buyer, keccak256("PAYMENT"));
        assertFalse(withhold);
    }

    // ============================================================
    // Helpers
    // ============================================================

    function _buildTaxClassification(
        LibAppStorage.FATCAClassification fatcaStatus,
        LibAppStorage.CRSEntityType crsType
    ) internal view returns (LibAppStorage.TaxClassification memory) {
        bytes32[] memory countries = new bytes32[](1);
        countries[0] = keccak256("US");
        bytes32[] memory tins = new bytes32[](1);
        tins[0] = keccak256("TIN-123");
        return LibAppStorage.TaxClassification({
            fatcaStatus:           fatcaStatus,
            crsType:               crsType,
            taxResidenceCountries: countries,
            taxIdNumbers:          tins,
            classificationDate:    block.timestamp,
            expirationDate:        block.timestamp + 365 days,
            certifiedBy:           officer,
            w8w9OnFile:            false
        });
    }

    function _setupKYCWithJurisdiction(address entity, bytes32 jurisdictionId) internal {
        bytes32 idHash = keccak256(abi.encodePacked("id-", entity));
        vm.prank(entity);
        kyc().initiateKYC(entity, idHash, LibAppStorage.KYCLevel.STANDARD, jurisdictionId);
        vm.prank(verifier);
        kyc().approveKYC(entity, LibAppStorage.KYCLevel.STANDARD, bytes32(0), false, 0);
    }
}
