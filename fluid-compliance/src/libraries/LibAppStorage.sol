// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IDiamondCut} from "../interfaces/IDiamondCut.sol";

/// @notice Reverted when a state-changing call is made while the system is paused
error SystemPaused();

/// @notice Reverted when a reentrant call is detected
error Reentrancy();

/// @title LibAppStorage
/// @author Surety Compliance System
/// @notice Central storage management for the Surety compliance diamond
/// @dev All facets share this storage layout via delegatecall
library LibAppStorage {
    bytes32 constant STORAGE_POSITION = keccak256("surety.compliance.diamond.storage");

    // ============================================================
    // KYC
    // ============================================================

    /// @notice KYC verification levels aligned with FATF recommendations
    enum KYCLevel {
        NONE,          // 0: Not verified
        BASIC,         // 1: Name, DOB, Address
        STANDARD,      // 2: Basic + Government ID
        ENHANCED,      // 3: Standard + Source of funds, PEP check
        INSTITUTIONAL  // 4: Enhanced + Corporate structure, UBO verification
    }

    /// @notice KYC verification status
    enum KYCStatus {
        PENDING,      // 0: Awaiting verification
        APPROVED,     // 1: Verified and active
        REJECTED,     // 2: Failed verification
        EXPIRED,      // 3: Needs renewal
        SUSPENDED,    // 4: Temporarily inactive
        UNDER_REVIEW  // 5: Re-verification in progress
    }

    /// @notice Core KYC record
    struct KYCRecord {
        bytes32 identityHash;    // Hash of identity documents
        KYCLevel level;          // Verification level achieved
        KYCStatus status;        // Current status
        uint256 verificationDate; // Timestamp of verification
        uint256 expirationDate;  // When renewal needed
        bytes32 jurisdictionId;  // Applicable jurisdiction
        address verifier;        // Who verified
        bytes32 documentRoot;    // Merkle root of documents
        bool isPEP;              // Politically Exposed Person
        uint256 riskScore;       // 0-1000 scale
    }

    // ============================================================
    // AML
    // ============================================================

    /// @notice AML risk levels
    enum RiskLevel {
        LOW,       // 0: Normal processing
        MEDIUM,    // 1: Enhanced monitoring
        HIGH,      // 2: Manual review required
        PROHIBITED // 3: Block all transactions
    }

    /// @notice Risk assessment record
    struct RiskScore {
        uint256 score;           // 0-1000 scale
        RiskLevel level;         // Categorized risk
        uint256 calculationDate; // When assessed
        bytes32[] riskFactors;   // Contributing factors
        bool requiresReview;     // Manual review flag
    }

    /// @notice Transaction monitoring record
    struct TransactionRecord {
        bytes32 transactionId;   // Unique identifier
        address from;            // Sender
        address to;              // Recipient
        uint256 amount;          // Value transferred
        bytes32 currency;        // Currency code
        uint256 timestamp;       // When occurred
        bytes32 transactionType; // Category
        RiskScore riskAssessment; // Risk evaluation
        bool flagged;            // Suspicious flag
    }

    // ============================================================
    // Sanctions
    // ============================================================

    /// @notice Sanctions list types
    enum SanctionsList {
        OFAC_SDN,  // 0: US SDN List
        OFAC_CONS, // 1: US Consolidated
        UN_SC,     // 2: UN Security Council
        EU_CONS,   // 3: EU Consolidated
        UK_HMT,    // 4: UK Treasury
        CUSTOM     // 5: Internal list
    }

    /// @notice Sanction record
    struct SanctionRecord {
        bytes32 entityHash;    // Identity hash
        SanctionsList[] lists; // Which lists
        uint256 listingDate;   // When added
        uint256 lastVerified;  // Last check
        bytes32 programCode;   // Sanction program
        bool isActive;         // Current status
    }

    // ============================================================
    // Invoice Registry
    // ============================================================

    /// @notice Invoice lifecycle status
    enum InvoiceStatus {
        REGISTERED,     // 0: Initial registration
        VERIFIED,       // 1: Buyer confirmed
        FACTORED,       // 2: Financing arranged
        PARTIALLY_PAID, // 3: Partial payment
        PAID,           // 4: Fully settled
        DISPUTED,       // 5: Under dispute
        CANCELLED       // 6: Cancelled
    }

    /// @notice Factoring agreement lifecycle status
    enum FactoringStatus {
        PENDING,   // 0: Awaiting activation
        ACTIVE,    // 1: Financing live
        SETTLED,   // 2: Fully repaid
        DEFAULTED, // 3: Buyer defaulted
        CANCELLED  // 4: Cancelled before activation
    }

    /// @notice Factoring agreement record
    struct FactoringRecord {
        bytes32 agreementId;
        bytes32 invoiceHash;
        address factor;
        address seller;
        uint256 advanceAmount;    // Absolute amount advanced
        uint256 advanceRate;      // Basis points (e.g. 8000 = 80%)
        uint256 feeRate;          // Basis points annual fee
        uint256 agreementDate;
        uint256 expectedSettlement;
        FactoringStatus status;
    }

    /// @notice Invoice record
    struct InvoiceRecord {
        bytes32 invoiceHash;      // Document hash
        address seller;           // Vendor
        address buyer;            // Purchaser
        uint256 amount;           // Invoice value
        bytes32 currency;         // Currency code
        uint256 issueDate;        // Creation date
        uint256 dueDate;          // Payment due
        InvoiceStatus status;     // Current state
        bytes32 purchaseOrderRef; // PO reference
        uint256 registrationTime; // When registered
        address registeredBy;     // Who registered
    }

    // ============================================================
    // FATCA / CRS
    // ============================================================

    /// @notice FATCA entity classification
    enum FATCAClassification {
        US_PERSON,               // 0
        NON_US_PERSON,           // 1
        PARTICIPATING_FFI,       // 2
        NON_PARTICIPATING_FFI,   // 3
        EXEMPT_BENEFICIAL_OWNER, // 4
        PASSIVE_NFFE,            // 5
        ACTIVE_NFFE,             // 6
        UNCLASSIFIED             // 7
    }

    /// @notice CRS entity type
    enum CRSEntityType {
        FINANCIAL_INSTITUTION, // 0
        ACTIVE_NFE,            // 1
        PASSIVE_NFE,           // 2
        GOVERNMENT_ENTITY,     // 3
        INTERNATIONAL_ORG,     // 4
        INDIVIDUAL             // 5
    }

    /// @notice Tax classification record
    struct TaxClassification {
        FATCAClassification fatcaStatus;
        CRSEntityType crsType;
        bytes32[] taxResidenceCountries;
        bytes32[] taxIdNumbers;    // Encrypted TIN references — no PII on-chain
        uint256 classificationDate;
        uint256 expirationDate;
        address certifiedBy;
        bool w8w9OnFile;
    }

    /// @notice Reporting obligation record
    struct ReportingObligation {
        bytes32 obligationId;
        address reportableEntity;
        bytes32 reportingJurisdiction;
        uint256 reportableAmount;
        bytes32 accountType;
        uint256 reportingYear;
        bool isReported;
    }

    // ============================================================
    // Jurisdiction
    // ============================================================

    /// @notice Jurisdiction regulatory configuration
    struct JurisdictionConfig {
        bytes32 jurisdictionId;
        bytes32 countryCode;      // ISO 3166-1 alpha-2 as bytes32
        bool isActive;
        // KYC requirements
        KYCLevel minimumKYCLevel;
        uint256 kycExpirationPeriod;
        bool requiresPEPScreening;
        // AML thresholds
        uint256 reportingThreshold;
        uint256 enhancedDueDiligenceThreshold;
        // Sanctions
        SanctionsList[] applicableSanctionsLists;
        // Tax
        bool fatcaApplicable;
        bool crsApplicable;
        uint256 withholdingRate;  // basis points
        // Operational
        bool allowedForFactoring;
        uint256 maxTransactionAmount;
        bytes32[] blockedCounterparties;
    }

    /// @notice Result of a cross-border compliance assessment
    struct CrossBorderAssessment {
        bytes32 sourceJurisdiction;
        bytes32 destinationJurisdiction;
        bool isPermitted;
        KYCLevel requiredKYCLevel;
        uint256 additionalWithholding; // basis points
        bool requiresEnhancedDueDiligence;
        bytes32[] applicableRestrictions;
    }

    // ============================================================
    // Oracle
    // ============================================================

    /// @notice Data types oracles may provide
    enum OracleDataType {
        SANCTIONS_LIST,    // 0
        PEP_LIST,          // 1
        EXCHANGE_RATE,     // 2
        RISK_SCORE,        // 3
        KYC_VERIFICATION,  // 4
        CREDIT_SCORE       // 5
    }

    /// @notice Pending oracle data request
    struct OracleRequest {
        bytes32 requestId;
        OracleDataType dataType;
        bytes32 dataKey;
        uint256 requestTimestamp;
        uint256 expirationTimestamp;
        address requester;
        bool fulfilled;
    }

    // ============================================================
    // Audit
    // ============================================================

    /// @notice Audit event types for hash-chained log
    enum AuditEventType {
        KYC_INITIATED,
        KYC_APPROVED,
        KYC_REJECTED,
        KYC_EXPIRED,
        TRANSACTION_ASSESSED,
        TRANSACTION_BLOCKED,
        SAR_FILED,
        SANCTIONS_SCREENED,
        SANCTIONS_MATCH,
        SANCTIONS_CLEARED,
        INVOICE_REGISTERED,
        INVOICE_FACTORED,
        DOUBLE_FACTOR_ATTEMPT,
        TAX_CLASSIFIED,
        REPORTING_TRIGGERED,
        ACCESS_GRANTED,
        ACCESS_REVOKED,
        SYSTEM_UPDATE,
        EMERGENCY_PAUSE
    }

    /// @notice Individual audit log entry
    struct AuditEntry {
        bytes32 entryId;
        AuditEventType eventType;
        address actor;
        address subject;
        bytes32 dataHash;
        uint256 timestamp;
        bytes32 previousEntryHash;
    }

    // ============================================================
    // Diamond Upgrade Queue
    // ============================================================

    /// @notice A scheduled facet upgrade awaiting timelock expiry
    struct ScheduledCut {
        IDiamondCut.FacetCut[] cuts;
        address init;
        bytes initCalldata;
        uint256 executeAfter;
        bool executed;
    }

    // ============================================================
    // Main Storage Struct
    // ============================================================

    /// @notice Single shared storage struct used by all facets
    struct AppStorage {
        // ===== KYC Storage =====
        mapping(address => KYCRecord) kycRecords;
        mapping(bytes32 => bool) verifiedIdentities;
        mapping(address => KYCStatus) entityStatus;

        // ===== AML Storage =====
        mapping(address => RiskScore) riskScores;
        mapping(address => TransactionRecord[]) transactionHistory;
        mapping(address => uint256) suspiciousActivityCount;
        uint256 reportingThreshold;

        // ===== Sanctions Storage =====
        mapping(bytes32 => bool) sanctionedEntities;
        mapping(bytes32 => SanctionRecord) sanctionDetails;
        mapping(SanctionsList => bytes32) sanctionsListRoots;
        mapping(SanctionsList => uint256) lastSanctionsUpdate;

        // ===== Invoice Registry =====
        mapping(bytes32 => InvoiceRecord) invoices;
        mapping(bytes32 => bool) usedInvoiceHashes;
        mapping(address => bytes32[]) sellerInvoices;
        mapping(address => bytes32[]) buyerInvoices;

        // ===== FATCA/CRS Storage =====
        mapping(address => TaxClassification) taxClassifications;
        mapping(bytes32 => ReportingObligation) reportingObligations;
        mapping(address => bytes32[]) pendingObligationIds;

        // ===== Jurisdiction Storage =====
        mapping(bytes32 => JurisdictionConfig) jurisdictionConfigs;
        mapping(address => bytes32) entityJurisdictions;
        mapping(bytes32 => mapping(bytes32 => bool)) blockedJurisdictionPairs;

        // ===== Oracle Storage =====
        mapping(address => bool) oracleActive;
        // Packed: address => encoded OracleDataType[] (abi.encode)
        mapping(address => bytes) oracleAuthorizedTypes;
        mapping(bytes32 => OracleRequest) oracleRequests;
        // dataType hash => dataKey => cached bytes value
        mapping(bytes32 => mapping(bytes32 => bytes)) oracleCachedData;
        mapping(bytes32 => mapping(bytes32 => uint256)) oracleDataTimestamps;
        uint256 oracleRequestNonce;

        // ===== Audit Trail =====
        bytes32 latestAuditHash;
        uint256 totalAuditEntries;
        mapping(bytes32 => bytes32) auditChain;    // prevHash => nextHash
        mapping(bytes32 => AuditEntry) auditEntries; // entryId => entry
        mapping(address => bytes32[]) entityAuditIds; // entity => entryIds

        // ===== Access Control =====
        mapping(bytes32 => mapping(address => bool)) roleMembers;
        mapping(bytes32 => bytes32) roleAdmins;

        // ===== System State =====
        bool systemPaused;
        uint256 lastSystemUpdate;
        address treasuryAddress;
        uint256 timelockDuration;

        // ===== Diamond Upgrade Queue =====
        mapping(bytes32 => ScheduledCut) scheduledCuts;

        // ===== Reentrancy Guard =====
        // 1 = NOT_ENTERED, 2 = ENTERED
        uint256 _reentrancyStatus;

        // ===== Oracle Nonces =====
        mapping(address => uint256) oracleNonce;

        // ===== Oracle Per-Type Counts =====
        mapping(uint8 => uint256) oracleTypeCount;
    }

    // ============================================================
    // Storage accessor
    // ============================================================

    /// @notice Get the AppStorage pointer at the deterministic slot
    /// @return s The AppStorage struct stored at STORAGE_POSITION
    function appStorage() internal pure returns (AppStorage storage s) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            s.slot := position
        }
    }

    /// @notice Check if the system is paused
    /// @return True if the system pause flag is set
    function isPaused() internal view returns (bool) {
        return appStorage().systemPaused;
    }
}
