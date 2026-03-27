// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";
import {LibRoles} from "../libraries/LibRoles.sol";
import {IFATCACRSFacet} from "../interfaces/IFATCACRSFacet.sol";

/// @title FATCACRSFacet
/// @author Surety Compliance System
/// @notice Tax classification and reporting compliance for cross-border transactions
/// @dev Implements FATCA and CRS requirements for international tax compliance
contract FATCACRSFacet is IFATCACRSFacet {
    using LibAppStorage for LibAppStorage.AppStorage;

    // ============ Constants ============

    uint256 private constant W8_VALIDITY_PERIOD = 1095 days; // 3 years
    uint256 private constant W9_VALIDITY_PERIOD = 1460 days; // 4 years
    uint256 private constant WITHHOLDING_RATE_US = 3000; // 30% in basis points
    uint256 private constant WITHHOLDING_RATE_BACKUP = 2400; // 24% in basis points
    uint256 private constant FATCA_THRESHOLD = 50000 * 1e18; // $50,000
    uint256 private constant CRS_THRESHOLD = 10000 * 1e18; // $10,000

    // ============ Errors ============

    error InvalidClassification();
    error TaxFormExpired();
    error InvalidTaxForm();
    error ReportingNotRequired();
    error ObligationNotFound();
    error UnauthorizedTaxOfficer();

    // ============ Modifiers ============

    modifier whenNotPaused() {
        require(!LibAppStorage.isPaused(), "System paused");
        _;
    }

    modifier onlyTaxOfficer() {
        LibRoles.checkRole(keccak256("TAX_OFFICER_ROLE"));
        _;
    }

    modifier onlyComplianceOfficer() {
        LibRoles.checkRole(LibRoles.COMPLIANCE_OFFICER_ROLE);
        _;
    }

    // ============ Core Functions ============

    /// @inheritdoc IFATCACRSFacet
    function recordTaxForm(
        address entity,
        bytes32 formType,
        bytes32 documentHash,
        uint256 expirationDate
    ) external whenNotPaused onlyTaxOfficer {
        if (
            formType != keccak256("W8BEN") &&
            formType != keccak256("W8BENE") &&
            formType != keccak256("W9") &&
            formType != keccak256("W8IMY")
        ) revert InvalidTaxForm();

        uint256 maxExpiration = block.timestamp +
            (formType == keccak256("W9") ? W9_VALIDITY_PERIOD : W8_VALIDITY_PERIOD);
        if (expirationDate > maxExpiration) expirationDate = maxExpiration;

        emit TaxFormStatusChanged(entity, true, expirationDate);
    }

    /// @inheritdoc IFATCACRSFacet
    function assessReportingRequirement(
        bytes32 transactionId,
        address from,
        address to,
        uint256 amount,
        bytes32 transactionType
    ) external whenNotPaused returns (bool requiresReporting, bytes32[] memory jurisdictions) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        requiresReporting = false;
        jurisdictions = new bytes32[](10);
        uint256 jurisdictionCount = 0;

        LibAppStorage.KYCRecord memory fromKYC = s.kycRecords[from];
        LibAppStorage.KYCRecord memory toKYC = s.kycRecords[to];

        if (amount >= FATCA_THRESHOLD) {
            if (fromKYC.jurisdictionId == keccak256("US") || toKYC.jurisdictionId == keccak256("US")) {
                requiresReporting = true;
                jurisdictions[jurisdictionCount++] = keccak256("US");
            }
        }

        if (amount >= CRS_THRESHOLD && fromKYC.jurisdictionId != toKYC.jurisdictionId) {
            requiresReporting = true;
            if (jurisdictionCount < 10) jurisdictions[jurisdictionCount++] = fromKYC.jurisdictionId;
            if (jurisdictionCount < 10) jurisdictions[jurisdictionCount++] = toKYC.jurisdictionId;
        }

        assembly { mstore(jurisdictions, jurisdictionCount) }

        if (requiresReporting) {
            emit ReportingObligationTriggered(transactionId, from, jurisdictions.length > 0 ? jurisdictions[0] : bytes32(0), amount);
        }
        return (requiresReporting, jurisdictions);
    }

    /// @inheritdoc IFATCACRSFacet
    function createReportingObligation(
        address entity,
        bytes32 jurisdiction,
        uint256 amount,
        bytes32 accountType,
        uint256 reportingYear
    ) external whenNotPaused onlyTaxOfficer returns (bytes32 obligationId) {
        obligationId = keccak256(abi.encodePacked(
            entity, jurisdiction, amount, accountType, reportingYear, block.timestamp
        ));
        emit ReportingObligationTriggered(obligationId, entity, jurisdiction, amount);
        return obligationId;
    }

    /// @inheritdoc IFATCACRSFacet
    function markAsReported(bytes32 obligationId) external whenNotPaused onlyComplianceOfficer {
        // In production, would update obligation status in storage
    }

    // ============ View Functions ============

    /// @inheritdoc IFATCACRSFacet
    function checkWithholding(
        address payer,
        address payee,
        bytes32 paymentType
    ) external view returns (bool withhold, uint256 rate) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.KYCRecord memory payerKYC = s.kycRecords[payer];
        LibAppStorage.KYCRecord memory payeeKYC = s.kycRecords[payee];

        if (payerKYC.jurisdictionId == keccak256("US") && payeeKYC.jurisdictionId != keccak256("US")) {
            return (true, WITHHOLDING_RATE_US);
        }
        if (payeeKYC.status != LibAppStorage.KYCStatus.APPROVED) {
            return (true, WITHHOLDING_RATE_BACKUP);
        }
        return (false, 0);
    }
}
