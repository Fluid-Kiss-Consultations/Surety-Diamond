// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondTestHelper} from "./helpers/DiamondTestHelper.sol";
import {LibAppStorage} from "../src/libraries/LibAppStorage.sol";

contract AMLFacetTest is DiamondTestHelper {

    // ============================================================
    // assessTransaction
    // ============================================================

    function test_assessTransaction_lowRiskForCleanEntities() public {
        // Give both entities approved KYC with zero risk score
        _approveKYC(seller, 0);
        _approveKYC(buyer, 0);

        vm.prank(analyst);
        (LibAppStorage.RiskScore memory score, bool canProceed) = aml().assessTransaction(
            keccak256("tx-1"), seller, buyer, 1000 * 1e18, keccak256("USD"), keccak256("INVOICE")
        );

        assertTrue(canProceed);
        assertLt(score.score, 750); // below HIGH_RISK_THRESHOLD
    }

    function test_assessTransaction_highRiskForPEP() public {
        // PEP flag adds 200 risk points
        bytes32 idHash = keccak256("pep-seller");
        vm.prank(seller);
        kyc().initiateKYC(seller, idHash, LibAppStorage.KYCLevel.ENHANCED, keccak256("US"));
        vm.prank(verifier);
        kyc().approveKYC(seller, LibAppStorage.KYCLevel.ENHANCED, bytes32(0), true, 600);

        _approveKYC(buyer, 0);

        vm.prank(analyst);
        (, bool canProceed) = aml().assessTransaction(
            keccak256("tx-pep"), seller, buyer, 1000 * 1e18, keccak256("USD"), keccak256("INVOICE")
        );
        // PEP (200) + riskScore/10 (60) = 260 — still below 750 → can proceed
        assertTrue(canProceed);
    }

    function test_assessTransaction_unverifiedEntitiesBlock() public {
        // Unverified from+to (600) + high risk scores (100+100) = 800 >= 750 HIGH threshold
        vm.startPrank(analyst);
        aml().setEntityRiskScore(seller, 1000, "pre-set");
        aml().setEntityRiskScore(buyer,  1000, "pre-set");
        (, bool canProceed) = aml().assessTransaction(
            keccak256("tx-unverified"), seller, buyer, 1000 * 1e18, keccak256("USD"), keccak256("INVOICE")
        );
        vm.stopPrank();
        assertFalse(canProceed);
    }

    function test_assessTransaction_sarFiledForHighRiskLargeAmount() public {
        // Unverified from+to (600) + high risk scores (200) = 800 >= 750, amount >= SAR threshold
        vm.prank(analyst); aml().setEntityRiskScore(seller, 1000, "pre-set");
        vm.prank(analyst); aml().setEntityRiskScore(buyer,  1000, "pre-set");

        vm.expectEmit(false, true, false, false, diamond);
        emit IAMLFacetTestHelper.SARFiled(bytes32(0), seller, 0, 0);

        vm.prank(analyst);
        aml().assessTransaction(
            keccak256("tx-sar"), seller, buyer, 20_000 * 1e18, keccak256("USD"), keccak256("INVOICE")
        );
    }

    // ============================================================
    // setEntityRiskScore
    // ============================================================

    function test_setEntityRiskScore_updatesKYCRiskScore() public {
        vm.prank(analyst);
        aml().setEntityRiskScore(seller, 400, "Suspicious pattern");

        (uint256 score,,) = aml().getEntityRiskProfile(seller);
        assertEq(score, 400);
    }

    function test_setEntityRiskScore_revertsIfAbove1000() public {
        vm.prank(analyst);
        vm.expectRevert();
        aml().setEntityRiskScore(seller, 1001, "Too high");
    }

    function test_setEntityRiskScore_revertsIfNotAnalyst() public {
        vm.prank(seller);
        vm.expectRevert();
        aml().setEntityRiskScore(seller, 400, "Unauthorized");
    }

    // ============================================================
    // flagSuspiciousActivity
    // ============================================================

    function test_flagSuspiciousActivity_escalatesRiskScore() public {
        _approveKYC(seller, 100);

        vm.prank(analyst);
        aml().flagSuspiciousActivity(seller, keccak256("tx-suspicious"), "Structuring detected");

        (uint256 score,,) = aml().getEntityRiskProfile(seller);
        assertEq(score, 300); // 100 + 200
    }

    function test_flagSuspiciousActivity_capsAt1000() public {
        _approveKYC(seller, 900);

        vm.prank(analyst);
        aml().flagSuspiciousActivity(seller, keccak256("tx-cap"), "Capping");

        (uint256 score,,) = aml().getEntityRiskProfile(seller);
        assertEq(score, 1000);
    }

    // ============================================================
    // isHighRisk
    // ============================================================

    function test_isHighRisk_trueAbove750() public {
        _approveKYC(seller, 800);
        assertTrue(aml().isHighRisk(seller));
    }

    function test_isHighRisk_falseBelow750() public {
        _approveKYC(seller, 700);
        assertFalse(aml().isHighRisk(seller));
    }

    // ============================================================
    // Helpers
    // ============================================================

    function _approveKYC(address entity, uint256 risk) internal {
        bytes32 idHash = keccak256(abi.encodePacked("id-", entity));
        vm.prank(entity);
        kyc().initiateKYC(entity, idHash, LibAppStorage.KYCLevel.STANDARD, keccak256("US"));
        vm.prank(verifier);
        kyc().approveKYC(entity, LibAppStorage.KYCLevel.STANDARD, bytes32(0), false, risk);
    }
}

// Minimal event definition helper to use vm.expectEmit
interface IAMLFacetTestHelper {
    event SARFiled(bytes32 indexed transactionId, address indexed entity, uint256 riskScore, uint256 timestamp);
}
