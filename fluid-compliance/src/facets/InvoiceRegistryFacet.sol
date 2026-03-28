// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage, SystemPaused} from "../libraries/LibAppStorage.sol";
import {LibRoles} from "../libraries/LibRoles.sol";
import {IInvoiceRegistryFacet} from "../interfaces/IInvoiceRegistryFacet.sol";

/// @title InvoiceRegistryFacet
/// @author Surety Compliance System
/// @notice Prevents double factoring and maintains immutable invoice records
/// @dev Core registry for supply chain finance invoice management
contract InvoiceRegistryFacet is IInvoiceRegistryFacet {
    using LibAppStorage for LibAppStorage.AppStorage;

    // ============ Constants ============

    uint256 private constant MAX_INVOICE_AMOUNT = 1e9 * 1e18;
    uint256 private constant MIN_ADVANCE_RATE = 100;
    uint256 private constant MAX_ADVANCE_RATE = 9500;

    // ============ Errors ============

    error InvoiceAlreadyRegistered();
    error InvoiceNotFound();
    error InvoiceAlreadyFactored();
    error InvalidInvoiceData();
    error UnauthorizedSeller();
    error UnauthorizedBuyer();
    error InvalidSignature();
    error InvalidSignatureLength();
    error InvalidSignatureV();
    error InvalidSignatureRecovery();
    error InvoiceNotVerified();
    error InvalidAdvanceRate();
    error PaymentExceedsInvoice();
    error ZeroAddress();

    // ============ Modifiers ============

    modifier whenNotPaused() {
        if (LibAppStorage.isPaused()) revert SystemPaused();
        _;
    }

    modifier onlyFactor() {
        LibRoles.checkRole(LibRoles.FACTOR_ROLE);
        _;
    }

    modifier onlySeller() {
        LibRoles.checkRole(LibRoles.SELLER_ROLE);
        _;
    }

    // ============ Core Functions ============

    /// @inheritdoc IInvoiceRegistryFacet
    function registerInvoice(
        LibAppStorage.InvoiceRecord calldata invoice,
        bytes calldata signature
    ) external whenNotPaused onlySeller returns (bytes32 invoiceHash) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        if (invoice.seller == address(0) || invoice.buyer == address(0)) revert ZeroAddress();
        if (invoice.amount == 0 || invoice.amount > MAX_INVOICE_AMOUNT) revert InvalidInvoiceData();
        if (invoice.dueDate <= invoice.issueDate) revert InvalidInvoiceData();
        if (invoice.seller != msg.sender) revert UnauthorizedSeller();

        invoiceHash = keccak256(abi.encodePacked(
            invoice.seller, invoice.buyer, invoice.amount, invoice.currency,
            invoice.issueDate, invoice.dueDate, invoice.purchaseOrderRef
        ));

        if (s.usedInvoiceHashes[invoiceHash]) revert InvoiceAlreadyRegistered();

        bytes32 messageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", invoiceHash
        ));
        address signer = _recoverSigner(messageHash, signature);
        if (signer != invoice.seller) revert InvalidSignature();

        s.invoices[invoiceHash] = LibAppStorage.InvoiceRecord({
            invoiceHash: invoiceHash,
            seller: invoice.seller,
            buyer: invoice.buyer,
            amount: invoice.amount,
            currency: invoice.currency,
            issueDate: invoice.issueDate,
            dueDate: invoice.dueDate,
            status: LibAppStorage.InvoiceStatus.REGISTERED,
            purchaseOrderRef: invoice.purchaseOrderRef,
            registrationTime: block.timestamp,
            registeredBy: msg.sender
        });

        s.usedInvoiceHashes[invoiceHash] = true;
        s.sellerInvoices[invoice.seller].push(invoiceHash);
        s.buyerInvoices[invoice.buyer].push(invoiceHash);

        emit InvoiceRegistered(invoiceHash, invoice.seller, invoice.buyer, invoice.amount, invoice.dueDate);
        return invoiceHash;
    }

    /// @inheritdoc IInvoiceRegistryFacet
    function verifyInvoice(
        bytes32 invoiceHash,
        bytes calldata buyerSignature
    ) external whenNotPaused {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.InvoiceRecord storage invoice = s.invoices[invoiceHash];
        if (invoice.invoiceHash == bytes32(0)) revert InvoiceNotFound();

        bytes32 messageHash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32", invoiceHash
        ));
        address signer = _recoverSigner(messageHash, buyerSignature);
        if (signer != invoice.buyer) revert UnauthorizedBuyer();

        invoice.status = LibAppStorage.InvoiceStatus.VERIFIED;
        emit InvoiceStatusChanged(invoiceHash, LibAppStorage.InvoiceStatus.REGISTERED, LibAppStorage.InvoiceStatus.VERIFIED);
    }

    /// @inheritdoc IInvoiceRegistryFacet
    function canFactor(
        bytes32 invoiceHash
    ) external view returns (bool canFactorInvoice, string memory reason) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.InvoiceRecord memory invoice = s.invoices[invoiceHash];
        if (invoice.invoiceHash == bytes32(0)) return (false, "Invoice not found");
        if (invoice.status != LibAppStorage.InvoiceStatus.VERIFIED) return (false, "Invoice not verified");
        if (invoice.status == LibAppStorage.InvoiceStatus.FACTORED) return (false, "Already factored");
        if (invoice.status == LibAppStorage.InvoiceStatus.DISPUTED) return (false, "Invoice disputed");
        if (invoice.dueDate <= block.timestamp) return (false, "Invoice overdue");
        return (true, "");
    }

    /// @inheritdoc IInvoiceRegistryFacet
    function createFactoringAgreement(
        bytes32 invoiceHash,
        address factor,
        uint256 advanceRate,
        uint256 feeRate
    ) external whenNotPaused onlyFactor returns (bytes32 agreementId) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        if (advanceRate < MIN_ADVANCE_RATE || advanceRate > MAX_ADVANCE_RATE) revert InvalidAdvanceRate();

        LibAppStorage.InvoiceRecord storage invoice = s.invoices[invoiceHash];
        if (invoice.invoiceHash == bytes32(0)) revert InvoiceNotFound();
        if (invoice.status != LibAppStorage.InvoiceStatus.VERIFIED) revert InvoiceNotVerified();

        uint256 advanceAmount = (invoice.amount * advanceRate) / 10000;
        agreementId = keccak256(abi.encodePacked(invoiceHash, factor, advanceAmount, block.timestamp));
        invoice.status = LibAppStorage.InvoiceStatus.FACTORED;

        emit InvoiceFactored(invoiceHash, agreementId, factor, advanceAmount);
        emit InvoiceStatusChanged(invoiceHash, LibAppStorage.InvoiceStatus.VERIFIED, LibAppStorage.InvoiceStatus.FACTORED);
        return agreementId;
    }

    /// @inheritdoc IInvoiceRegistryFacet
    function recordPayment(
        bytes32 invoiceHash,
        uint256 paymentAmount,
        bytes32 paymentReference
    ) external whenNotPaused onlyFactor {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.InvoiceRecord storage invoice = s.invoices[invoiceHash];
        if (invoice.invoiceHash == bytes32(0)) revert InvoiceNotFound();

        LibAppStorage.InvoiceStatus prev = invoice.status;
        if (paymentAmount >= invoice.amount) {
            invoice.status = LibAppStorage.InvoiceStatus.PAID;
        } else {
            invoice.status = LibAppStorage.InvoiceStatus.PARTIALLY_PAID;
        }
        // TODO: Store paymentReference for off-chain payment tracking
        emit InvoiceStatusChanged(invoiceHash, prev, invoice.status);
    }

    /// @inheritdoc IInvoiceRegistryFacet
    function raiseDispute(
        bytes32 invoiceHash,
        string calldata reason
    ) external whenNotPaused {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.InvoiceRecord storage invoice = s.invoices[invoiceHash];
        if (invoice.invoiceHash == bytes32(0)) revert InvoiceNotFound();
        if (msg.sender != invoice.buyer && msg.sender != invoice.seller) revert UnauthorizedBuyer();

        LibAppStorage.InvoiceStatus prev = invoice.status;
        invoice.status = LibAppStorage.InvoiceStatus.DISPUTED;
        emit InvoiceStatusChanged(invoiceHash, prev, LibAppStorage.InvoiceStatus.DISPUTED);
    }

    // ============ View Functions ============

    /// @inheritdoc IInvoiceRegistryFacet
    function getInvoice(
        bytes32 invoiceHash
    ) external view returns (LibAppStorage.InvoiceRecord memory record) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        record = s.invoices[invoiceHash];
    }

    /// @inheritdoc IInvoiceRegistryFacet
    function getFactoringStatus(
        bytes32 invoiceHash
    ) external view returns (bool isFactored, address factor) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.InvoiceRecord memory invoice = s.invoices[invoiceHash];
        isFactored = invoice.status == LibAppStorage.InvoiceStatus.FACTORED;
        // TODO: Retrieve actual factor address from FactoringRecord instead of returning address(0)
        factor = address(0);
    }

    /// @inheritdoc IInvoiceRegistryFacet
    function isInvoiceHashUsed(bytes32 invoiceHash) external view returns (bool isUsed) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        isUsed = s.usedInvoiceHashes[invoiceHash];
    }

    // ============ Internal Functions ============

    function _recoverSigner(
        bytes32 messageHash,
        bytes memory signature
    ) internal pure returns (address signer) {
        if (signature.length != 65) revert InvalidSignatureLength();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert InvalidSignatureV();
        signer = ecrecover(messageHash, v, r, s);
        if (signer == address(0)) revert InvalidSignatureRecovery();
    }
}
