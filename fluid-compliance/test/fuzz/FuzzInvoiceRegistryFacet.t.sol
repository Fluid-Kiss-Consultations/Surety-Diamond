// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondTestHelper} from "../helpers/DiamondTestHelper.sol";
import {LibAppStorage} from "../../src/libraries/LibAppStorage.sol";

contract FuzzInvoiceRegistryFacetTest is DiamondTestHelper {

    uint256 private constant MAX_INVOICE_AMOUNT = 1e9 * 1e18;
    uint256 private constant MIN_ADVANCE_RATE = 100;
    uint256 private constant MAX_ADVANCE_RATE = 9500;

    uint256 internal sellerPk;
    uint256 internal buyerPk;

    function setUp() public override {
        super.setUp();
        (, sellerPk) = makeAddrAndKey("seller");
        (, buyerPk)  = makeAddrAndKey("buyer");
    }

    // ============================================================
    // registerInvoice — amount bounds
    // ============================================================

    function testFuzz_registerInvoice_amountBounds(uint256 amount) public {
        if (amount == 0 || amount > MAX_INVOICE_AMOUNT) {
            // vm.prank is NOT set here — _tryRegisterInvoice sets it internally
            // immediately before the contract call, preventing double-prank conflict.
            vm.expectRevert();
            vm.prank(seller);
            invoice().registerInvoice(inv, sig);
        } else {
            bytes32 invoiceHash = _tryRegisterInvoice(amount);
            LibAppStorage.InvoiceRecord memory rec = invoice().getInvoice(invoiceHash);
            assertEq(rec.amount, amount);
        }
    }

    // ============================================================
    // createFactoringAgreement — advance rate bounds
    // ============================================================

    function testFuzz_createFactoringAgreement_advanceRate(uint256 rate) public {
        bytes32 invoiceHash = _verifiedInvoice(100_000 * 1e18);

        if (rate < MIN_ADVANCE_RATE || rate > MAX_ADVANCE_RATE) {
            vm.prank(factor);
            vm.expectRevert();
            invoice().createFactoringAgreement(invoiceHash, factor, rate, 200);
        } else {
            vm.prank(factor);
            bytes32 agreementId = invoice().createFactoringAgreement(invoiceHash, factor, rate, 200);
            assertNotEq(agreementId, bytes32(0));
        }
    }

    // ============================================================
    // recordPayment — status transitions
    // ============================================================

    function testFuzz_recordPayment_statusTransition(uint256 paymentAmount) public {
        uint256 invoiceAmount = 100_000 * 1e18;
        paymentAmount = bound(paymentAmount, 1, type(uint128).max);

        bytes32 invoiceHash = _verifiedInvoice(invoiceAmount);
        vm.prank(factor);
        invoice().createFactoringAgreement(invoiceHash, factor, 8000, 200);

        vm.prank(factor);
        invoice().recordPayment(invoiceHash, paymentAmount, keccak256("FUZZ-PAY"));

        LibAppStorage.InvoiceRecord memory rec = invoice().getInvoice(invoiceHash);
        if (paymentAmount >= invoiceAmount) {
            assertEq(uint8(rec.status), uint8(LibAppStorage.InvoiceStatus.PAID));
        } else {
            assertEq(uint8(rec.status), uint8(LibAppStorage.InvoiceStatus.PARTIALLY_PAID));
        }
    }

    // ============================================================
    // Helpers
    // ============================================================

    function _tryRegisterInvoice(uint256 amount) internal returns (bytes32 invoiceHash) {
        LibAppStorage.InvoiceRecord memory inv = _buildInvoice(seller, buyer, amount);
        invoiceHash = keccak256(abi.encodePacked(
            inv.seller, inv.buyer, inv.amount, inv.currency, inv.issueDate, inv.dueDate, inv.purchaseOrderRef
        ));
        bytes memory sig = _buildSellerSig(sellerPk, invoiceHash);
        vm.prank(seller);
        invoice().registerInvoice(inv, sig);
    }

    function _verifiedInvoice(uint256 amount) internal returns (bytes32 invoiceHash) {
        invoiceHash = _tryRegisterInvoice(amount);
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
