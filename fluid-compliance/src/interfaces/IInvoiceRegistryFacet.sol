// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title IInvoiceRegistryFacet
/// @notice Interface for on-chain invoice registration and trade finance lifecycle
interface IInvoiceRegistryFacet {

    event InvoiceRegistered(bytes32 indexed invoiceHash, address indexed seller, address indexed buyer, uint256 amount, uint256 dueDate);
    event InvoiceStatusChanged(bytes32 indexed invoiceHash, LibAppStorage.InvoiceStatus previousStatus, LibAppStorage.InvoiceStatus newStatus);
    event DoubleFactoringAttempt(bytes32 indexed invoiceHash, address indexed attacker, address existingFactor, uint256 timestamp);
    event InvoiceFactored(bytes32 indexed invoiceHash, bytes32 indexed agreementId, address indexed factor, uint256 advanceAmount);

    /// @notice Register a new invoice on-chain with seller signature verification
    /// @param invoice The invoice record to register
    /// @param signature Seller's ECDSA signature over the invoice data
    /// @return invoiceHash Unique hash identifying the registered invoice
    function registerInvoice(
        LibAppStorage.InvoiceRecord calldata invoice,
        bytes calldata signature
    ) external returns (bytes32 invoiceHash);

    /// @notice Verify an invoice with the buyer's signature
    /// @param invoiceHash Hash of the invoice to verify
    /// @param buyerSignature Buyer's ECDSA signature confirming the invoice
    function verifyInvoice(bytes32 invoiceHash, bytes calldata buyerSignature) external;

    /// @notice Check whether an invoice is eligible for factoring
    /// @param invoiceHash Hash of the invoice to check
    /// @return canFactorInvoice True if the invoice can be factored
    /// @return reason Human-readable explanation if factoring is blocked
    function canFactor(
        bytes32 invoiceHash
    ) external view returns (bool canFactorInvoice, string memory reason);

    /// @notice Create a factoring agreement for a verified invoice
    /// @param invoiceHash Hash of the invoice to factor
    /// @param factor Address of the factoring entity
    /// @param advanceRate Advance rate in basis points (e.g., 8000 = 80%)
    /// @param feeRate Fee rate in basis points
    /// @return agreementId Unique identifier for the factoring agreement
    function createFactoringAgreement(
        bytes32 invoiceHash,
        address factor,
        uint256 advanceRate,
        uint256 feeRate
    ) external returns (bytes32 agreementId);

    /// @notice Record a payment against a factored invoice
    /// @param invoiceHash Hash of the invoice being paid
    /// @param paymentAmount Amount paid in wei
    /// @param paymentReference Off-chain payment reference identifier
    function recordPayment(bytes32 invoiceHash, uint256 paymentAmount, bytes32 paymentReference) external;

    /// @notice Raise a dispute on a registered invoice
    /// @param invoiceHash Hash of the disputed invoice
    /// @param reason Description of the dispute
    function raiseDispute(bytes32 invoiceHash, string calldata reason) external;

    /// @notice Retrieve the full invoice record
    /// @param invoiceHash Hash of the invoice to query
    /// @return record The stored invoice record
    function getInvoice(
        bytes32 invoiceHash
    ) external view returns (LibAppStorage.InvoiceRecord memory record);

    /// @notice Get the factoring status of an invoice
    /// @param invoiceHash Hash of the invoice to query
    /// @return isFactored Whether the invoice has been factored
    /// @return factor Address of the factor (address(0) if not factored)
    function getFactoringStatus(
        bytes32 invoiceHash
    ) external view returns (bool isFactored, address factor);

    /// @notice Check whether an invoice hash has already been registered
    /// @param invoiceHash Hash to check
    /// @return isUsed True if the hash is already in the registry
    function isInvoiceHashUsed(bytes32 invoiceHash) external view returns (bool isUsed);
}
