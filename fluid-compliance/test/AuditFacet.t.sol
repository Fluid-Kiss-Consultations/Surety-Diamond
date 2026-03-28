// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondTestHelper} from "./helpers/DiamondTestHelper.sol";
import {LibAppStorage} from "../src/libraries/LibAppStorage.sol";

contract AuditFacetTest is DiamondTestHelper {

    function test_logAudit_storesEntry() public {
        vm.prank(auditor);
        bytes32 entryId = audit().logAudit(
            LibAppStorage.AuditEventType.KYC_INITIATED, seller, keccak256("data")
        );

        LibAppStorage.AuditEntry memory entry = audit().getAuditEntry(entryId);
        assertEq(entry.entryId, entryId);
        assertEq(entry.subject, seller);
        assertEq(entry.actor,   auditor);
        assertEq(uint8(entry.eventType), uint8(LibAppStorage.AuditEventType.KYC_INITIATED));
    }

    function test_logAudit_revertsIfNotAuditor() public {
        vm.prank(seller);
        vm.expectRevert();
        audit().logAudit(LibAppStorage.AuditEventType.KYC_INITIATED, seller, keccak256("data"));
    }

    function test_logAudit_updatesLatestHash() public {
        bytes32 before = audit().getLatestAuditHash();

        vm.prank(auditor);
        audit().logAudit(LibAppStorage.AuditEventType.SAR_FILED, seller, keccak256("sar-data"));

        bytes32 after_ = audit().getLatestAuditHash();
        assertNotEq(before, after_);
    }

    function test_hashChainIntegrity_twoEntries() public {
        vm.startPrank(auditor);
        bytes32 id1 = audit().logAudit(LibAppStorage.AuditEventType.KYC_INITIATED, seller, keccak256("1"));
        bytes32 id2 = audit().logAudit(LibAppStorage.AuditEventType.KYC_APPROVED,  buyer,  keccak256("2"));
        vm.stopPrank();

        LibAppStorage.AuditEntry memory entry2 = audit().getAuditEntry(id2);
        assertNotEq(entry2.previousEntryHash, bytes32(0));
    }

    function test_verifyAuditChain_sameEntryIsValid() public {
        vm.prank(auditor);
        bytes32 id1 = audit().logAudit(LibAppStorage.AuditEventType.KYC_INITIATED, seller, keccak256("1"));

        bytes32 hash1 = audit().getLatestAuditHash();
        assertTrue(audit().verifyAuditChain(hash1, hash1));
    }

    function test_verifyAuditChain_invalidChainReturnsFalse() public view {
        assertFalse(audit().verifyAuditChain(keccak256("nonexistent"), keccak256("also-nonexistent")));
    }

    function test_getEntityAuditTrail_filtersCorrectly() public {
        vm.startPrank(auditor);
        audit().logAudit(LibAppStorage.AuditEventType.KYC_INITIATED, seller, keccak256("1"));
        audit().logAudit(LibAppStorage.AuditEventType.KYC_APPROVED,  seller, keccak256("2"));
        audit().logAudit(LibAppStorage.AuditEventType.SAR_FILED,     seller, keccak256("3"));
        vm.stopPrank();

        LibAppStorage.AuditEntry[] memory kycEntries = audit().getEntityAuditTrail(
            seller, LibAppStorage.AuditEventType.KYC_INITIATED, 0, 0
        );
        assertEq(kycEntries.length, 1);

        LibAppStorage.AuditEntry[] memory kycApproved = audit().getEntityAuditTrail(
            seller, LibAppStorage.AuditEventType.KYC_APPROVED, 0, 0
        );
        assertEq(kycApproved.length, 1);
    }

    function test_getEntityAuditTrail_timestampFilter() public {
        uint256 t1 = block.timestamp;
        vm.prank(auditor);
        audit().logAudit(LibAppStorage.AuditEventType.KYC_INITIATED, seller, keccak256("1"));

        vm.warp(block.timestamp + 1 hours);
        vm.prank(auditor);
        audit().logAudit(LibAppStorage.AuditEventType.KYC_INITIATED, seller, keccak256("2"));

        LibAppStorage.AuditEntry[] memory entries = audit().getEntityAuditTrail(
            seller, LibAppStorage.AuditEventType.KYC_INITIATED, t1, t1 + 1 minutes
        );
        assertEq(entries.length, 1);
    }

    function test_logKYCEvent_validType() public {
        vm.prank(auditor); // requires AUDITOR_ROLE
        audit().logKYCEvent(seller, LibAppStorage.AuditEventType.KYC_APPROVED, keccak256("kyc"));
    }

    function test_logKYCEvent_invalidTypeReverts() public {
        vm.prank(auditor);
        vm.expectRevert();
        audit().logKYCEvent(seller, LibAppStorage.AuditEventType.SAR_FILED, keccak256("bad"));
    }

    function test_logAMLEvent_validType() public {
        vm.prank(auditor);
        audit().logAMLEvent(seller, LibAppStorage.AuditEventType.SAR_FILED, keccak256("sar"));
    }

    function test_logSanctionsEvent_validType() public {
        vm.prank(auditor);
        audit().logSanctionsEvent(seller, LibAppStorage.AuditEventType.SANCTIONS_SCREENED, keccak256("s"));
    }

    function test_logSanctionsEvent_invalidTypeReverts() public {
        vm.prank(auditor);
        vm.expectRevert();
        audit().logSanctionsEvent(seller, LibAppStorage.AuditEventType.KYC_APPROVED, keccak256("bad"));
    }
}
