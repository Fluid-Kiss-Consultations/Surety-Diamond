// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondTestHelper} from "./helpers/DiamondTestHelper.sol";
import {LibAppStorage} from "../src/libraries/LibAppStorage.sol";

/// @notice Tests for InvoiceRegistryFacet — double-factoring prevention is the critical path.
contract InvoiceRegistryFacetTest is DiamondTestHelper {

    uint256 internal sellerPk;
    uint256 internal buyerPk;

    function setUp() public override {
        super.setUp();
        (, sellerPk) = makeAddrAndKey("seller");
        (, buyerPk)  = makeAddrAndKey("buyer");
    }

    function test_registerInvoice_storesRecord() public {
        bytes32 invoiceHash = _registerInvoice(100_000 * 1e18);
        LibAppStorage.InvoiceRecord memory rec = invoice().getInvoice(invoiceHash);

        assertEq(rec.seller, seller);
        assertEq(rec.buyer,  buyer);
        assertEq(rec.amount, 100_000 * 1e18);
        assertEq(uint8(rec.status), uint8(LibAppStorage.InvoiceStatus.REGISTERED));
    }

    function test_registerInvoice_marksHashUsed() public {
        bytes32 invoiceHash = _registerInvoice(50_000 * 1e18);
        assertTrue(invoice().isInvoiceHashUsed(invoiceHash));
    }

    function test_registerInvoice_revertsOnDuplicate() public {
        _registerInvoice(50_000 * 1e18);
        vm.expectRevert();
        _registerInvoice(50_000 * 1e18);
    }

    function test_registerInvoice_revertsIfNotSeller() public {
        LibAppStorage.InvoiceRecord memory inv = _buildInvoice(buyer, seller, 10_000 * 1e18);
        bytes32 invHash = keccak256(abi.encodePacked(
            inv.seller, inv.buyer, inv.amount, inv.currency, inv.issueDate, inv.dueDate, inv.purchaseOrderRef
        ));
        bytes memory sig = _buildSellerSig(buyerPk, invHash);
        vm.prank(buyer);
        vm.expectRevert();
        invoice().registerInvoice(inv, sig);
    }

    function test_verifyInvoice_setsVerifiedStatus() public {
        bytes32 invoiceHash = _registerInvoice(100_000 * 1e18);

        bytes memory buyerSig = _buildBuyerSig(buyerPk, invoiceHash);
        vm.prank(buyer);
        invoice().verifyInvoice(invoiceHash, buyerSig);

        LibAppStorage.InvoiceRecord memory rec = invoice().getInvoice(invoiceHash);
        assertEq(uint8(rec.status), uint8(LibAppStorage.InvoiceStatus.VERIFIED));
    }

    function test_verifyInvoice_revertsWithWrongBuyerSig() public {
        bytes32 invoiceHash = _registerInvoice(100_000 * 1e18);

        bytes memory wrongSig = _buildSellerSig(sellerPk, invoiceHash);
        vm.prank(buyer);
        vm.expectRevert();
        invoice().verifyInvoice(invoiceHash, wrongSig);
    }

    function test_createFactoringAgreement_succeeds() public {
        bytes32 invoiceHash = _verifiedInvoice(200_000 * 1e18);

        vm.prank(factor);
        bytes32 agreementId = invoice().createFactoringAgreement(invoiceHash, factor, 8000, 200);
        assertNotEq(agreementId, bytes32(0));

        LibAppStorage.InvoiceRecord memory rec = invoice().getInvoice(invoiceHash);
        assertEq(uint8(rec.status), uint8(LibAppStorage.InvoiceStatus.FACTORED));
    }

    function test_createFactoringAgreement_revertsOnDoubleFactoring() public {
        bytes32 invoiceHash = _verifiedInvoice(200_000 * 1e18);

        vm.prank(factor);
        invoice().createFactoringAgreement(invoiceHash, factor, 8000, 200);

        vm.prank(factor);
        vm.expectRevert();
        invoice().createFactoringAgreement(invoiceHash, factor, 7000, 150);
    }

    function test_createFactoringAgreement_revertsOnInvalidAdvanceRate() public {
        bytes32 invoiceHash = _verifiedInvoice(200_000 * 1e18);

        vm.prank(factor);
        vm.expectRevert();
        invoice().createFactoringAgreement(invoiceHash, factor, 9600, 200);
    }

    function test_canFactor_trueForVerifiedInvoice() public {
        bytes32 invoiceHash = _verifiedInvoice(100_000 * 1e18);
        (bool ok,) = invoice().canFactor(invoiceHash);
        assertTrue(ok);
    }

    function test_canFactor_falseForFactoredInvoice() public {
        bytes32 invoiceHash = _verifiedInvoice(100_000 * 1e18);
        vm.prank(factor);
        invoice().createFactoringAgreement(invoiceHash, factor, 8000, 200);
        (bool ok,) = invoice().canFactor(invoiceHash);
        assertFalse(ok);
    }

    function test_recordPayment_fullPaymentSetsPaid() public {
        bytes32 invoiceHash = _verifiedInvoice(100_000 * 1e18);
        vm.prank(factor);
        invoice().createFactoringAgreement(invoiceHash, factor, 8000, 200);

        vm.prank(factor); // FACTOR_ROLE required to record payment
        invoice().recordPayment(invoiceHash, 100_000 * 1e18, keccak256("PAY-001"));

        LibAppStorage.InvoiceRecord memory rec = invoice().getInvoice(invoiceHash);
        assertEq(uint8(rec.status), uint8(LibAppStorage.InvoiceStatus.PAID));
    }

    function test_recordPayment_partialSetsPartiallyPaid() public {
        bytes32 invoiceHash = _verifiedInvoice(100_000 * 1e18);
        vm.prank(factor);
        invoice().createFactoringAgreement(invoiceHash, factor, 8000, 200);

        vm.prank(factor); // FACTOR_ROLE required to record payment
        invoice().recordPayment(invoiceHash, 50_000 * 1e18, keccak256("PAY-PARTIAL"));

        LibAppStorage.InvoiceRecord memory rec = invoice().getInvoice(invoiceHash);
        assertEq(uint8(rec.status), uint8(LibAppStorage.InvoiceStatus.PARTIALLY_PAID));
    }

    function test_raiseDispute_setsDisputedStatus() public {
        bytes32 invoiceHash = _verifiedInvoice(100_000 * 1e18);

        vm.prank(buyer);
        invoice().raiseDispute(invoiceHash, "Goods not delivered");

        LibAppStorage.InvoiceRecord memory rec = invoice().getInvoice(invoiceHash);
        assertEq(uint8(rec.status), uint8(LibAppStorage.InvoiceStatus.DISPUTED));
    }

    function _registerInvoice(uint256 amount) internal returns (bytes32 invoiceHash) {
        LibAppStorage.InvoiceRecord memory inv = _buildInvoice(seller, buyer, amount);
        invoiceHash = keccak256(abi.encodePacked(
            inv.seller, inv.buyer, inv.amount, inv.currency, inv.issueDate, inv.dueDate, inv.purchaseOrderRef
        ));
        bytes memory sig = _buildSellerSig(sellerPk, invoiceHash);
        vm.prank(seller);
        invoice().registerInvoice(inv, sig);
    }

    function _verifiedInvoice(uint256 amount) internal returns (bytes32 invoiceHash) {
        invoiceHash = _registerInvoice(amount);
        bytes memory buyerSig = _buildBuyerSig(buyerPk, invoiceHash);
        vm.prank(buyer);
        invoice().verifyInvoice(invoiceHash, buyerSig);
    }

    function _buildSellerSig(uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        bytes32 prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(pk, prefixed);
        return abi.encodePacked(r, s_, v);
    }

    function _buildBuyerSig(uint256 pk, bytes32 hash) internal pure returns (bytes memory) {
        return _buildSellerSig(pk, hash);
    }
}
