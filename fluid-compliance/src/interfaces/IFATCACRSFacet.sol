// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title IFATCACRSFacet
/// @notice Interface for FATCA/CRS tax compliance reporting
/// @dev All personally identifiable information is stored as keccak256 hashes only - never raw PII
interface IFATCACRSFacet {

    event TaxClassificationUpdated(address indexed entity, uint8 fatcaStatus, uint8 crsType, uint256 timestamp);
    event TaxFormStatusChanged(address indexed entity, bool onFile, uint256 expirationDate);
    event ReportingObligationTriggered(bytes32 indexed obligationId, address indexed entity, bytes32 indexed jurisdiction, uint256 amount);

    /// @notice Set or update the FATCA/CRS tax classification for an entity
    /// @param entity Address of the entity to classify
    /// @param classification The tax classification struct to assign
    function setTaxClassification(
        address entity,
        LibAppStorage.TaxClassification calldata classification
    ) external;

    /// @notice Record submission of a tax form (W-8, W-9, etc.)
    /// @param entity Address of the entity filing the form
    /// @param formType Identifier for the form type (e.g., keccak256("W-8BEN"))
    /// @param documentHash Keccak256 hash of the submitted document
    /// @param expirationDate Timestamp when the form expires
    function recordTaxForm(
        address entity,
        bytes32 formType,
        bytes32 documentHash,
        uint256 expirationDate
    ) external;

    /// @notice Assess whether a transaction triggers reporting requirements
    /// @param transactionId Unique identifier for the transaction
    /// @param from Sender address
    /// @param to Recipient address
    /// @param amount Transaction value in wei
    /// @param transactionType Type of transaction
    /// @return requiresReporting True if reporting is required
    /// @return jurisdictions Array of jurisdiction IDs where reporting is required
    function assessReportingRequirement(
        bytes32 transactionId,
        address from,
        address to,
        uint256 amount,
        bytes32 transactionType
    ) external returns (bool requiresReporting, bytes32[] memory jurisdictions);

    /// @notice Create a reporting obligation for a specific entity and jurisdiction
    /// @param entity Address of the entity with the obligation
    /// @param jurisdiction Jurisdiction requiring the report
    /// @param amount Reportable amount in wei
    /// @param accountType Type of account
    /// @param reportingYear Tax year for the obligation
    /// @return obligationId Unique identifier for the created obligation
    function createReportingObligation(
        address entity,
        bytes32 jurisdiction,
        uint256 amount,
        bytes32 accountType,
        uint256 reportingYear
    ) external returns (bytes32 obligationId);

    /// @notice Mark a reporting obligation as fulfilled
    /// @param obligationId Identifier of the obligation to mark as reported
    function markAsReported(bytes32 obligationId) external;

    /// @notice Retrieve the current tax classification for an entity
    /// @param entity Address to query
    /// @return classification The entity's tax classification struct
    function getTaxClassification(
        address entity
    ) external view returns (LibAppStorage.TaxClassification memory classification);

    /// @notice Check whether withholding is required for a payment between two entities
    /// @param payer Address of the paying entity
    /// @param payee Address of the receiving entity
    /// @param paymentType Type of payment
    /// @return withhold True if withholding applies
    /// @return rate Withholding rate in basis points (e.g., 3000 = 30%)
    function checkWithholding(
        address payer,
        address payee,
        bytes32 paymentType
    ) external view returns (bool withhold, uint256 rate);

    /// @notice Get all pending reporting obligations for an entity in a given year
    /// @param entity Address to query
    /// @param year The tax year to filter by
    /// @return obligations Array of pending reporting obligations
    function getPendingObligations(
        address entity,
        uint256 year
    ) external view returns (LibAppStorage.ReportingObligation[] memory obligations);
}
