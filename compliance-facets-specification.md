# Compliance Facets Specification for Global Supply Chain Finance

## Target Platform: Enterprise Supply Chain Finance

---

## Executive Summary

This specification defines a comprehensive suite of EIP-2535 Diamond Standard compliance facets designed for global supply chain finance (SCF) operations. The target platform is an enterprise provider of working capital and B2B payment solutions operating in 80+ countries, processing high volumes of payment transactions across 30+ currencies.

The compliance facets address the critical regulatory requirements for:

- **KYC (Know Your Customer)** - Identity verification and customer due diligence
- **AML (Anti-Money Laundering)** - Transaction monitoring and suspicious activity reporting
- **Sanctions Screening** - OFAC, UN, EU, HMT watchlist screening
- **FATCA/CRS** - Tax compliance and reporting for cross-border transactions
- **Invoice Verification** - Double-factoring prevention and fraud detection
- **Jurisdictional Compliance** - Multi-jurisdiction regulatory adaptability

---

## 1.0 Business Context and Requirements

### 1.1 SCF Platform Overview

Core services include:

- **Supply Chain Finance (Reverse Factoring)**: Buyers extend payment terms while suppliers receive early payment
- **Dynamic Discounting**: Early payment in exchange for negotiated discounts
- **Receivables Finance**: Suppliers unlock working capital from unpaid invoices
- **Payments as a Service**: Bank-agnostic B2B payment processing

### 1.2 Compliance Challenges in SCF

| Challenge | Impact | Smart Contract Solution |
|-----------|--------|------------------------|
| Double Factoring | Fraud risk, financial loss | Immutable invoice registry with collision detection |
| Cross-Border KYC | Regulatory fragmentation | Modular jurisdiction-specific verification |
| Sanctions Violations | Legal penalties, reputational damage | Real-time screening with automated blocking |
| AML Complexity | 32+ compliance checks per transaction | Automated risk scoring and monitoring |
| FATCA/CRS Reporting | Tax authority compliance | Automated classification and reporting triggers |
| Audit Trail | Regulatory inspection readiness | Permanent, tamper-proof event logging |

### 1.3 Key Regulatory Frameworks

**United States:**

- Bank Secrecy Act (BSA)
- USA PATRIOT Act (Sections 312, 319)
- OFAC Sanctions Programs
- FATCA (Foreign Account Tax Compliance Act)

**European Union:**

- MiCA (Markets in Crypto-Assets)
- 6AMLD (6th Anti-Money Laundering Directive)
- GDPR (General Data Protection Regulation)

**Global:**

- FATF Recommendations
- UNSC Sanctions
- Basel III/IV Capital Requirements

---

## 2.0 Diamond Architecture Overview

### 2.1 Why Diamond Pattern for Compliance

The Diamond Standard (EIP-2535) is the optimal choice for this compliance system because:

1. **Modular Upgrades**: Regulatory requirements change frequently; facets can be updated independently
2. **Jurisdictional Flexibility**: Different facets for different regulatory regimes
3. **Contract Size**: Compliance logic exceeds 24KB limit for single contracts
4. **Granular Access Control**: Different permission models per compliance domain
5. **Audit Compliance**: DiamondLoupe provides full introspection for regulators

### 2.2 High-Level Architecture

┌─────────────────────────────────────────────────────────────────┐
│                     COMPLIANCE DIAMOND                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   DiamondCut │  │DiamondLoupe │  │ Ownership    │          │
│  │   Facet      │  │   Facet     │  │   Facet      │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                 COMPLIANCE FACETS                         │  │
│  ├──────────────┬──────────────┬──────────────┬─────────────┤  │
│  │ KYCFacet     │ AMLFacet     │ Sanctions    │ FATCA/CRS   │  │
│  │              │              │ Facet        │ Facet       │  │
│  ├──────────────┼──────────────┼──────────────┼─────────────┤  │
│  │ Invoice      │ Jurisdiction │ Audit        │ Oracle      │  │
│  │ Registry     │ Facet        │ Facet        │ Facet       │  │
│  └──────────────┴──────────────┴──────────────┴─────────────┘  │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                 SHARED STORAGE (AppStorage)               │  │
│  └──────────────────────────────────────────────────────────┘  │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

### 2.3 Storage Architecture

Using the Diamond Storage pattern with AppStorage for shared state:

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title LibAppStorage - Central storage for compliance diamond
/// @notice All facets share this storage layout via delegatecall
library LibAppStorage {
    bytes32 constant STORAGE_POSITION = keccak256("surety.compliance.diamond.storage");
    
    struct AppStorage {
        // === KYC Storage ===
        mapping(address => KYCRecord) kycRecords;
        mapping(bytes32 => bool) verifiedIdentities;
        mapping(address => KYCStatus) entityStatus;
        
        // === AML Storage ===
        mapping(bytes32 => RiskScore) riskScores;
        mapping(bytes32 => TransactionRecord[]) transactionHistory;
        mapping(address => uint256) suspiciousActivityCount;
        uint256 reportingThreshold;
        
        // === Sanctions Storage ===
        mapping(bytes32 => bool) sanctionedEntities;
        mapping(bytes32 => SanctionRecord) sanctionDetails;
        uint256 lastSanctionsUpdate;
        bytes32 sanctionsListRoot; // Merkle root for efficient verification
        
        // === FATCA/CRS Storage ===
        mapping(address => TaxClassification) taxClassifications;
        mapping(bytes32 => ReportingObligation) reportingObligations;
        
        // === Invoice Registry Storage ===
        mapping(bytes32 => InvoiceRecord) invoices;
        mapping(bytes32 => FactoringRecord) factoringAgreements;
        mapping(bytes32 => bool) usedInvoiceHashes;
        
        // === Jurisdiction Storage ===
        mapping(bytes32 => JurisdictionConfig) jurisdictions;
        mapping(address => bytes32) entityJurisdiction;
        
        // === Access Control ===
        mapping(bytes32 => mapping(address => bool)) roleMembers;
        mapping(address => bool) complianceOfficers;
        mapping(address => bool) trustedOracles;
        
        // === System State ===
        bool systemPaused;
        uint256 lastSystemUpdate;
        address treasuryAddress;
    }
    
    function appStorage() internal pure returns (AppStorage storage s) {
        bytes32 position = STORAGE_POSITION;
        assembly {
            s.slot := position
        }
    }
}
```

---

## 3.0 Facet Specifications

### 3.1 KYC Facet

**Purpose**: Manage customer identity verification, due diligence levels, and compliance status.

#### Data Structures

```solidity
/// @notice KYC verification levels aligned with FATF recommendations
enum KYCLevel {
    NONE,           // Not verified
    BASIC,          // Name, DOB, Address
    STANDARD,       // Basic + Government ID
    ENHANCED,       // Standard + Source of funds, PEP check
    INSTITUTIONAL   // Enhanced + Corporate structure, UBO verification
}

/// @notice Status of KYC verification
enum KYCStatus {
    PENDING,
    APPROVED,
    REJECTED,
    EXPIRED,
    SUSPENDED,
    UNDER_REVIEW
}

/// @notice Core KYC record structure
struct KYCRecord {
    bytes32 identityHash;        // Hash of identity documents
    KYCLevel level;
    KYCStatus status;
    uint256 verificationDate;
    uint256 expirationDate;
    bytes32 jurisdictionId;
    address verifier;
    bytes32 documentRoot;        // Merkle root of supporting documents
    bool isPEP;                  // Politically Exposed Person flag
    uint256 riskScore;
}
```

#### Interface

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IKYCFacet - KYC verification and management
/// @author Surety Compliance Team
/// @notice Handles all KYC-related operations for supply chain finance participants
interface IKYCFacet {
    
    // === Events ===
    
    /// @notice Emitted when KYC verification is initiated
    event KYCInitiated(
        address indexed entity,
        bytes32 indexed identityHash,
        KYCLevel requestedLevel,
        uint256 timestamp
    );
    
    /// @notice Emitted when KYC status changes
    event KYCStatusChanged(
        address indexed entity,
        KYCStatus previousStatus,
        KYCStatus newStatus,
        address indexed updatedBy,
        string reason
    );
    
    /// @notice Emitted when KYC verification is completed
    event KYCVerified(
        address indexed entity,
        KYCLevel level,
        uint256 expirationDate,
        address indexed verifier
    );
    
    // === Core Functions ===
    
    /// @notice Initiate KYC verification for an entity
    /// @param entity Address of the entity to verify
    /// @param identityHash Keccak256 hash of identity documents
    /// @param level Requested verification level
    /// @param jurisdictionId Jurisdiction identifier for applicable rules
    function initiateKYC(
        address entity,
        bytes32 identityHash,
        KYCLevel level,
        bytes32 jurisdictionId
    ) external;
    
    /// @notice Complete KYC verification (compliance officer only)
    /// @param entity Address of the verified entity
    /// @param level Approved verification level
    /// @param documentRoot Merkle root of verified documents
    /// @param isPEP Whether entity is a Politically Exposed Person
    /// @param riskScore Calculated risk score (0-1000)
    function approveKYC(
        address entity,
        KYCLevel level,
        bytes32 documentRoot,
        bool isPEP,
        uint256 riskScore
    ) external;
    
    /// @notice Reject KYC application
    /// @param entity Address of the entity
    /// @param reason Rejection reason code
    function rejectKYC(address entity, string calldata reason) external;
    
    /// @notice Update KYC status (e.g., suspend, expire)
    /// @param entity Address of the entity
    /// @param newStatus New KYC status
    /// @param reason Reason for status change
    function updateKYCStatus(
        address entity,
        KYCStatus newStatus,
        string calldata reason
    ) external;
    
    // === View Functions ===
    
    /// @notice Check if entity meets minimum KYC requirements
    /// @param entity Address to check
    /// @param requiredLevel Minimum required level
    /// @return isCompliant Whether entity meets requirements
    function isKYCCompliant(
        address entity,
        KYCLevel requiredLevel
    ) external view returns (bool isCompliant);
    
    /// @notice Get full KYC record for an entity
    /// @param entity Address to query
    /// @return record Complete KYC record
    function getKYCRecord(address entity) external view returns (KYCRecord memory record);
    
    /// @notice Verify document inclusion in KYC record
    /// @param entity Address of entity
    /// @param documentHash Hash of document to verify
    /// @param proof Merkle proof
    /// @return isValid Whether document is part of KYC record
    function verifyDocument(
        address entity,
        bytes32 documentHash,
        bytes32[] calldata proof
    ) external view returns (bool isValid);
}
```

### 3.2 AML Facet

**Purpose**: Transaction monitoring, risk scoring, and suspicious activity detection.

#### Data Structure

```solidity
/// @notice Risk levels for AML assessment
enum RiskLevel {
    LOW,
    MEDIUM,
    HIGH,
    PROHIBITED
}

/// @notice Transaction risk assessment record
struct RiskScore {
    uint256 score;              // 0-1000 scale
    RiskLevel level;
    uint256 calculationDate;
    bytes32[] riskFactors;      // Contributing risk factor codes
    bool requiresReview;
}

/// @notice Transaction record for monitoring
struct TransactionRecord {
    bytes32 transactionId;
    address from;
    address to;
    uint256 amount;
    bytes32 currency;
    uint256 timestamp;
    bytes32 transactionType;    // INVOICE_FACTOR, PAYMENT, etc.
    RiskScore riskAssessment;
    bool flagged;
}

/// @notice Suspicious Activity Report structure
struct SARReport {
    bytes32 reportId;
    address reportedEntity;
    bytes32[] relatedTransactions;
    string narrative;
    uint256 filingDate;
    address filedBy;
    SARStatus status;
}

enum SARStatus {
    DRAFT,
    SUBMITTED,
    ACKNOWLEDGED,
    CLOSED
}
```

#### Interfaced

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IAMLFacet - Anti-Money Laundering monitoring and reporting
/// @notice Implements transaction monitoring and SAR filing capabilities
interface IAMLFacet {
    
    // === Events ===
    
    /// @notice Emitted when a transaction is assessed
    event TransactionAssessed(
        bytes32 indexed transactionId,
        address indexed entity,
        uint256 amount,
        RiskLevel riskLevel,
        bool flagged
    );
    
    /// @notice Emitted when risk threshold is exceeded
    event RiskThresholdExceeded(
        address indexed entity,
        uint256 riskScore,
        uint256 threshold,
        bytes32[] riskFactors
    );
    
    /// @notice Emitted when SAR is filed
    event SARFiled(
        bytes32 indexed reportId,
        address indexed entity,
        uint256 timestamp,
        address filedBy
    );
    
    /// @notice Emitted when transaction is blocked
    event TransactionBlocked(
        bytes32 indexed transactionId,
        address indexed entity,
        string reason
    );
    
    // === Core Functions ===
    
    /// @notice Assess transaction risk before processing
    /// @param transactionId Unique transaction identifier
    /// @param from Source address
    /// @param to Destination address
    /// @param amount Transaction amount
    /// @param currency Currency identifier
    /// @param transactionType Type of transaction
    /// @return assessment Risk assessment result
    /// @return canProceed Whether transaction can proceed
    function assessTransaction(
        bytes32 transactionId,
        address from,
        address to,
        uint256 amount,
        bytes32 currency,
        bytes32 transactionType
    ) external returns (RiskScore memory assessment, bool canProceed);
    
    /// @notice Record transaction for monitoring
    /// @param record Transaction record to store
    function recordTransaction(TransactionRecord calldata record) external;
    
    /// @notice Flag transaction for review
    /// @param transactionId Transaction to flag
    /// @param reason Flagging reason
    function flagTransaction(bytes32 transactionId, string calldata reason) external;
    
    /// @notice Create draft SAR
    /// @param reportedEntity Entity being reported
    /// @param relatedTransactions Array of related transaction IDs
    /// @param narrative Description of suspicious activity
    /// @return reportId Unique report identifier
    function createSAR(
        address reportedEntity,
        bytes32[] calldata relatedTransactions,
        string calldata narrative
    ) external returns (bytes32 reportId);
    
    /// @notice Submit SAR to authorities (off-chain trigger)
    /// @param reportId SAR to submit
    function submitSAR(bytes32 reportId) external;
    
    /// @notice Update entity risk score
    /// @param entity Entity to update
    /// @param newScore New risk score
    /// @param riskFactors Contributing factors
    function updateRiskScore(
        address entity,
        uint256 newScore,
        bytes32[] calldata riskFactors
    ) external;
    
    /// @notice Set reporting threshold for automatic alerts
    /// @param threshold Amount threshold for reporting
    function setReportingThreshold(uint256 threshold) external;
    
    // === View Functions ===
    
    /// @notice Get entity risk assessment
    /// @param entity Address to query
    /// @return score Current risk score
    function getEntityRiskScore(address entity) external view returns (RiskScore memory score);
    
    /// @notice Get transaction history for entity
    /// @param entity Address to query
    /// @param limit Maximum records to return
    /// @return transactions Array of transaction records
    function getTransactionHistory(
        address entity,
        uint256 limit
    ) external view returns (TransactionRecord[] memory transactions);
    
    /// @notice Check if entity is blocked
    /// @param entity Address to check
    /// @return isBlocked Whether entity is blocked
    /// @return reason Block reason if blocked
    function isBlocked(address entity) external view returns (bool isBlocked, string memory reason);
}
```

### 3.3 Sanctions Facet

**Purpose**: Real-time screening against OFAC, UN, EU, HMT, and other sanctions lists.

#### Data Structured

```solidity
/// @notice Sanctions list identifiers
enum SanctionsList {
    OFAC_SDN,       // US Office of Foreign Assets Control - Specially Designated Nationals
    OFAC_CONS,      // OFAC Consolidated List
    UN_SC,          // United Nations Security Council
    EU_CONS,        // EU Consolidated List
    UK_HMT,         // UK HM Treasury
    CUSTOM          // Custom internal list
}

/// @notice Sanction record details
struct SanctionRecord {
    bytes32 entityHash;
    SanctionsList[] applicableLists;
    uint256 listingDate;
    uint256 lastVerified;
    bytes32 programCode;        // Sanctions program (e.g., IRAN, DPRK)
    bool isActive;
    string[] alternateNames;
}

/// @notice Screening result
struct ScreeningResult {
    bool isMatch;
    bool isPotentialMatch;
    uint256 matchScore;         // 0-100 confidence
    SanctionsList[] matchedLists;
    bytes32 matchedEntityHash;
}
```

#### Interfaces

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title ISanctionsFacet - Sanctions screening and enforcement
/// @notice Implements real-time sanctions checking for all participants
interface ISanctionsFacet {
    
    // === Events ===
    
    /// @notice Emitted when sanctions list is updated
    event SanctionsListUpdated(
        SanctionsList indexed listType,
        bytes32 newRoot,
        uint256 entryCount,
        uint256 timestamp
    );
    
    /// @notice Emitted when entity is screened
    event EntityScreened(
        address indexed entity,
        bytes32 indexed identityHash,
        bool isMatch,
        uint256 matchScore
    );
    
    /// @notice Emitted when sanctions match is found
    event SanctionsMatchFound(
        address indexed entity,
        SanctionsList[] matchedLists,
        bytes32 matchedEntityHash,
        uint256 timestamp
    );
    
    /// @notice Emitted when entity is cleared
    event EntityCleared(
        address indexed entity,
        uint256 clearanceDate,
        address clearedBy
    );
    
    // === Core Functions ===
    
    /// @notice Screen entity against all sanctions lists
    /// @param entity Address to screen
    /// @param identityHash Hash of identity information
    /// @param nameVariants Array of name variants to check
    /// @return result Comprehensive screening result
    function screenEntity(
        address entity,
        bytes32 identityHash,
        bytes32[] calldata nameVariants
    ) external returns (ScreeningResult memory result);
    
    /// @notice Screen entity against specific list using Merkle proof
    /// @param entityHash Entity identifier hash
    /// @param listType Sanctions list to check
    /// @param proof Merkle proof of inclusion/exclusion
    /// @return isListed Whether entity is on the list
    function verifyAgainstList(
        bytes32 entityHash,
        SanctionsList listType,
        bytes32[] calldata proof
    ) external view returns (bool isListed);
    
    /// @notice Update sanctions list (oracle only)
    /// @param listType List to update
    /// @param newRoot New Merkle root
    /// @param entryCount Number of entries in list
    function updateSanctionsList(
        SanctionsList listType,
        bytes32 newRoot,
        uint256 entryCount
    ) external;
    
    /// @notice Add entity to internal sanctions list
    /// @param entityHash Entity identifier
    /// @param record Sanction record details
    function addToSanctionsList(
        bytes32 entityHash,
        SanctionRecord calldata record
    ) external;
    
    /// @notice Remove entity from internal sanctions list
    /// @param entityHash Entity identifier
    /// @param reason Removal reason
    function removeFromSanctionsList(
        bytes32 entityHash,
        string calldata reason
    ) external;
    
    /// @notice Clear false positive match
    /// @param entity Entity address
    /// @param identityHash Identity hash
    /// @param clearanceReason Reason for clearance
    function clearFalsePositive(
        address entity,
        bytes32 identityHash,
        string calldata clearanceReason
    ) external;
    
    // === View Functions ===
    
    /// @notice Quick check if entity is sanctioned
    /// @param entity Address to check
    /// @return isSanctioned Whether entity is on any sanctions list
    function isSanctioned(address entity) external view returns (bool isSanctioned);
    
    /// @notice Get sanction record details
    /// @param entityHash Entity identifier
    /// @return record Sanction record if exists
    function getSanctionRecord(
        bytes32 entityHash
    ) external view returns (SanctionRecord memory record);
    
    /// @notice Get current sanctions list root
    /// @param listType List to query
    /// @return root Current Merkle root
    /// @return lastUpdate Last update timestamp
    function getSanctionsListRoot(
        SanctionsList listType
    ) external view returns (bytes32 root, uint256 lastUpdate);
}
```

### 3.4 FATCA/CRS Facet

**Purpose**: Tax classification and reporting compliance for cross-border transactions.

#### DataStructures

solidity
/// @notice FATCA classification types
enum FATCAClassification {
    US_PERSON,
    NON_US_PERSON,
    PARTICIPATING_FFI,
    NON_PARTICIPATING_FFI,
    EXEMPT_BENEFICIAL_OWNER,
    PASSIVE_NFFE,
    ACTIVE_NFFE,
    UNCLASSIFIED
}

/// @notice CRS entity types
enum CRSEntityType {
    FINANCIAL_INSTITUTION,
    ACTIVE_NFE,
    PASSIVE_NFE,
    GOVERNMENT_ENTITY,
    INTERNATIONAL_ORG,
    INDIVIDUAL
}

/// @notice Tax classification record
struct TaxClassification {
    FATCAClassification fatcaStatus;
    CRSEntityType crsType;
    bytes32[] taxResidenceCountries;
    bytes32[] taxIdNumbers;         // Encrypted TIN references
    uint256 classificationDate;
    uint256 expirationDate;
    address certifiedBy;
    bool w8w9OnFile;
}

/// @notice Reportable transaction for tax authorities
struct ReportingObligation {
    bytes32 obligationId;
    address reportableEntity;
    bytes32 reportingJurisdiction;
    uint256 reportableAmount;
    bytes32 accountType;
    uint256 reportingYear;
    bool isReported;
}

#### Interfaceded

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IFATCACRSFacet - Tax compliance and reporting
/// @notice Handles FATCA and CRS classification and reporting triggers
interface IFATCACRSFacet {
    
    // === Events ===
    
    /// @notice Emitted when tax classification is updated
    event TaxClassificationUpdated(
        address indexed entity,
        FATCAClassification fatcaStatus,
        CRSEntityType crsType,
        uint256 timestamp
    );
    
    /// @notice Emitted when reporting obligation is triggered
    event ReportingObligationTriggered(
        bytes32 indexed obligationId,
        address indexed entity,
        bytes32 jurisdiction,
        uint256 amount
    );
    
    /// @notice Emitted when W-8/W-9 status changes
    event TaxFormStatusChanged(
        address indexed entity,
        bool hasValidForm,
        uint256 expirationDate
    );
    
    // === Core Functions ===
    
    /// @notice Set entity tax classification
    /// @param entity Entity address
    /// @param classification Tax classification details
    function setTaxClassification(
        address entity,
        TaxClassification calldata classification
    ) external;
    
    /// @notice Record W-8/W-9 form submission
    /// @param entity Entity address
    /// @param formType Form type (W8BEN, W8BENE, W9, etc.)
    /// @param documentHash Hash of submitted form
    /// @param expirationDate Form expiration date
    function recordTaxForm(
        address entity,
        bytes32 formType,
        bytes32 documentHash,
        uint256 expirationDate
    ) external;
    
    /// @notice Assess transaction for reporting requirements
    /// @param transactionId Transaction identifier
    /// @param from Payer address
    /// @param to Payee address
    /// @param amount Transaction amount
    /// @param transactionType Type of payment
    /// @return requiresReporting Whether transaction triggers reporting
    /// @return jurisdictions Array of jurisdictions requiring reports
    function assessReportingRequirement(
        bytes32 transactionId,
        address from,
        address to,
        uint256 amount,
        bytes32 transactionType
    ) external returns (bool requiresReporting, bytes32[] memory jurisdictions);
    
    /// @notice Create reporting obligation
    /// @param entity Reportable entity
    /// @param jurisdiction Reporting jurisdiction
    /// @param amount Reportable amount
    /// @param accountType Account type code
    /// @param reportingYear Tax year
    /// @return obligationId Unique obligation identifier
    function createReportingObligation(
        address entity,
        bytes32 jurisdiction,
        uint256 amount,
        bytes32 accountType,
        uint256 reportingYear
    ) external returns (bytes32 obligationId);
    
    /// @notice Mark obligation as reported
    /// @param obligationId Obligation to update
    function markAsReported(bytes32 obligationId) external;
    
    // === View Functions ===
    
    /// @notice Get entity tax classification
    /// @param entity Entity address
    /// @return classification Tax classification record
    function getTaxClassification(
        address entity
    ) external view returns (TaxClassification memory classification);
    
    /// @notice Check if withholding applies
    /// @param payer Payer address
    /// @param payee Payee address
    /// @param paymentType Payment type
    /// @return withhold Whether to withhold
    /// @return rate Withholding rate (basis points)
    function checkWithholding(
        address payer,
        address payee,
        bytes32 paymentType
    ) external view returns (bool withhold, uint256 rate);
    
    /// @notice Get pending reporting obligations
    /// @param entity Entity address
    /// @param year Reporting year
    /// @return obligations Array of pending obligations
    function getPendingObligations(
        address entity,
        uint256 year
    ) external view returns (ReportingObligation[] memory obligations);
}
```

### 3.5 Invoice Registry Facet

**Purpose**: Prevent double factoring and maintain immutable invoice records.

#### Data Structuresed

```solidity
/// @notice Invoice status in lifecycle
enum InvoiceStatus {
    REGISTERED,
    VERIFIED,
    FACTORED,
    PARTIALLY_PAID,
    PAID,
    DISPUTED,
    CANCELLED
}

/// @notice Core invoice record
struct InvoiceRecord {
    bytes32 invoiceHash;        // Hash of invoice document
    address seller;
    address buyer;
    uint256 amount;
    bytes32 currency;
    uint256 issueDate;
    uint256 dueDate;
    InvoiceStatus status;
    bytes32 purchaseOrderRef;
    uint256 registrationTimestamp;
    address registeredBy;
}

/// @notice Factoring agreement record
struct FactoringRecord {
    bytes32 agreementId;
    bytes32 invoiceHash;
    address factor;             // Financial institution
    address seller;
    uint256 advanceAmount;
    uint256 advanceRate;        // Basis points
    uint256 feeRate;            // Basis points
    uint256 agreementDate;
    uint256 expectedSettlement;
    FactoringStatus status;
}

enum FactoringStatus {
    PENDING,
    ACTIVE,
    SETTLED,
    DEFAULTED,
    CANCELLED
}
```

#### Interfaceds

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IInvoiceRegistryFacet - Invoice registration and double-factoring prevention
/// @notice Maintains immutable registry of invoices and factoring agreements
interface IInvoiceRegistryFacet {
    
    // === Events ===
    
    /// @notice Emitted when invoice is registered
    event InvoiceRegistered(
        bytes32 indexed invoiceHash,
        address indexed seller,
        address indexed buyer,
        uint256 amount,
        uint256 dueDate
    );
    
    /// @notice Emitted when invoice is factored
    event InvoiceFactored(
        bytes32 indexed invoiceHash,
        bytes32 indexed agreementId,
        address indexed factor,
        uint256 advanceAmount
    );
    
    /// @notice Emitted when double-factoring attempt is detected
    event DoubleFactoringAttempt(
        bytes32 indexed invoiceHash,
        address attemptedBy,
        address existingFactor,
        uint256 timestamp
    );
    
    /// @notice Emitted when invoice status changes
    event InvoiceStatusChanged(
        bytes32 indexed invoiceHash,
        InvoiceStatus previousStatus,
        InvoiceStatus newStatus
    );
    
    // === Core Functions ===
    
    /// @notice Register new invoice
    /// @param invoice Invoice details
    /// @param signature Seller signature of invoice hash
    /// @return invoiceHash Unique invoice identifier
    function registerInvoice(
        InvoiceRecord calldata invoice,
        bytes calldata signature
    ) external returns (bytes32 invoiceHash);
    
    /// @notice Verify invoice authenticity
    /// @param invoiceHash Invoice identifier
    /// @param buyerSignature Buyer confirmation signature
    function verifyInvoice(
        bytes32 invoiceHash,
        bytes calldata buyerSignature
    ) external;
    
    /// @notice Check if invoice can be factored (not already factored)
    /// @param invoiceHash Invoice identifier
    /// @return canFactor Whether invoice is available for factoring
    /// @return reason Reason if cannot factor
    function canFactor(
        bytes32 invoiceHash
    ) external view returns (bool canFactor, string memory reason);
    
    /// @notice Create factoring agreement
    /// @param invoiceHash Invoice to factor
    /// @param factor Financial institution address
    /// @param advanceRate Advance rate in basis points
    /// @param feeRate Fee rate in basis points
    /// @return agreementId Unique agreement identifier
    function createFactoringAgreement(
        bytes32 invoiceHash,
        address factor,
        uint256 advanceRate,
        uint256 feeRate
    ) external returns (bytes32 agreementId);
    
    /// @notice Record payment against factored invoice
    /// @param invoiceHash Invoice identifier
    /// @param paymentAmount Amount paid
    /// @param paymentReference External payment reference
    function recordPayment(
        bytes32 invoiceHash,
        uint256 paymentAmount,
        bytes32 paymentReference
    ) external;
    
    /// @notice Settle factoring agreement
    /// @param agreementId Agreement to settle
    function settleFactoringAgreement(bytes32 agreementId) external;
    
    /// @notice Raise dispute on invoice
    /// @param invoiceHash Invoice identifier
    /// @param reason Dispute reason
    function raiseDispute(bytes32 invoiceHash, string calldata reason) external;
    
    // === View Functions ===
    
    /// @notice Get invoice details
    /// @param invoiceHash Invoice identifier
    /// @return record Invoice record
    function getInvoice(
        bytes32 invoiceHash
    ) external view returns (InvoiceRecord memory record);
    
    /// @notice Get factoring agreement details
    /// @param agreementId Agreement identifier
    /// @return record Factoring record
    function getFactoringAgreement(
        bytes32 agreementId
    ) external view returns (FactoringRecord memory record);
    
    /// @notice Check invoice factoring status
    /// @param invoiceHash Invoice identifier
    /// @return isFactored Whether invoice is factored
    /// @return factor Current factor address if factored
    function getFactoringStatus(
        bytes32 invoiceHash
    ) external view returns (bool isFactored, address factor);
    
    /// @notice Verify invoice hash hasn't been used
    /// @param invoiceHash Hash to check
    /// @return isUsed Whether hash exists in registry
    function isInvoiceHashUsed(bytes32 invoiceHash) external view returns (bool isUsed);
}
```

### 3.6 Jurisdiction Facet

**Purpose**: Manage jurisdiction-specific compliance rules and requirements.

#### Data Structs

```solidity
/// @notice Jurisdiction configuration
struct JurisdictionConfig {
    bytes32 jurisdictionId;
    bytes32 countryCode;        // ISO 3166-1 alpha-2
    bool isActive;
    
    // KYC Requirements
    KYCLevel minimumKYCLevel;
    uint256 kycExpirationPeriod;
    bool requiresPEPScreening;
    
    // AML Thresholds
    uint256 reportingThreshold;
    uint256 enhancedDueDiligenceThreshold;
    
    // Sanctions
    SanctionsList[] applicableSanctionsLists;
    
    // Tax
    bool fatcaApplicable;
    bool crsApplicable;
    uint256 withholdingRate;    // Basis points
    
    // Operational
    bool allowedForFactoring;
    uint256 maxTransactionAmount;
    bytes32[] blockedCounterparties;
}

/// @notice Cross-border transaction assessment
struct CrossBorderAssessment {
    bytes32 sourceJurisdiction;
    bytes32 destinationJurisdiction;
    bool isPermitted;
    KYCLevel requiredKYCLevel;
    uint256 additionalWithholding;
    bool requiresEnhancedDueDiligence;
    bytes32[] applicableRestrictions;
}
```

#### Interfaceses

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IJurisdictionFacet - Multi-jurisdiction compliance management
/// @notice Handles jurisdiction-specific rules and cross-border compliance
interface IJurisdictionFacet {
    
    // === Events ===
    
    /// @notice Emitted when jurisdiction configuration is updated
    event JurisdictionUpdated(
        bytes32 indexed jurisdictionId,
        bool isActive,
        uint256 timestamp
    );
    
    /// @notice Emitted when entity jurisdiction is assigned
    event EntityJurisdictionAssigned(
        address indexed entity,
        bytes32 indexed jurisdictionId
    );
    
    /// @notice Emitted when cross-border transaction is assessed
    event CrossBorderAssessed(
        bytes32 indexed transactionId,
        bytes32 sourceJurisdiction,
        bytes32 destinationJurisdiction,
        bool permitted
    );
    
    // === Core Functions ===
    
    /// @notice Configure jurisdiction rules
    /// @param config Jurisdiction configuration
    function configureJurisdiction(JurisdictionConfig calldata config) external;
    
    /// @notice Assign entity to jurisdiction
    /// @param entity Entity address
    /// @param jurisdictionId Jurisdiction identifier
    function assignEntityJurisdiction(
        address entity,
        bytes32 jurisdictionId
    ) external;
    
    /// @notice Assess cross-border transaction
    /// @param from Source entity
    /// @param to Destination entity
    /// @param amount Transaction amount
    /// @param transactionType Type of transaction
    /// @return assessment Cross-border assessment result
    function assessCrossBorder(
        address from,
        address to,
        uint256 amount,
        bytes32 transactionType
    ) external returns (CrossBorderAssessment memory assessment);
    
    /// @notice Block jurisdiction for specific operations
    /// @param jurisdictionId Jurisdiction to block
    /// @param operationType Operation type to block
    function blockJurisdictionOperation(
        bytes32 jurisdictionId,
        bytes32 operationType
    ) external;
    
    /// @notice Add blocked counterparty jurisdiction pair
    /// @param jurisdiction1 First jurisdiction
    /// @param jurisdiction2 Second jurisdiction
    /// @param reason Block reason
    function blockCounterpartyPair(
        bytes32 jurisdiction1,
        bytes32 jurisdiction2,
        string calldata reason
    ) external;
    
    // === View Functions ===
    
    /// @notice Get jurisdiction configuration
    /// @param jurisdictionId Jurisdiction identifier
    /// @return config Jurisdiction configuration
    function getJurisdiction(
        bytes32 jurisdictionId
    ) external view returns (JurisdictionConfig memory config);
    
    /// @notice Get entity's jurisdiction
    /// @param entity Entity address
    /// @return jurisdictionId Assigned jurisdiction
    function getEntityJurisdiction(
        address entity
    ) external view returns (bytes32 jurisdictionId);
    
    /// @notice Check if transaction is permitted between jurisdictions
    /// @param sourceJurisdiction Source jurisdiction
    /// @param destJurisdiction Destination jurisdiction
    /// @param transactionType Type of transaction
    /// @return permitted Whether transaction is permitted
    function isTransactionPermitted(
        bytes32 sourceJurisdiction,
        bytes32 destJurisdiction,
        bytes32 transactionType
    ) external view returns (bool permitted);
    
    /// @notice Get minimum KYC level for jurisdiction
    /// @param jurisdictionId Jurisdiction identifier
    /// @return level Minimum required KYC level
    function getMinimumKYCLevel(
        bytes32 jurisdictionId
    ) external view returns (KYCLevel level);
}
```

### 3.7 Audit Facet

**Purpose**: Immutable audit logging for regulatory inspection and compliance verification.

#### Interfacedes

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IAuditFacet - Immutable audit trail management
/// @notice Provides comprehensive audit logging for all compliance activities
interface IAuditFacet {
    
    /// @notice Audit event types
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
    
    /// @notice Audit log entry
    struct AuditEntry {
        bytes32 entryId;
        AuditEventType eventType;
        address actor;
        address subject;
        bytes32 dataHash;
        uint256 timestamp;
        bytes32 previousEntryHash;
    }
    
    // === Events ===
    
    /// @notice Emitted for every audit entry (indexed for filtering)
    event AuditLogged(
        bytes32 indexed entryId,
        AuditEventType indexed eventType,
        address indexed actor,
        address subject,
        bytes32 dataHash,
        uint256 timestamp
    );
    
    // === Core Functions ===
    
    /// @notice Log audit entry (internal, called by other facets)
    /// @param eventType Type of event
    /// @param subject Entity affected
    /// @param dataHash Hash of event data
    /// @return entryId Unique entry identifier
    function logAudit(
        AuditEventType eventType,
        address subject,
        bytes32 dataHash
    ) external returns (bytes32 entryId);
    
    /// @notice Verify audit chain integrity
    /// @param startEntry Starting entry ID
    /// @param endEntry Ending entry ID
    /// @return isValid Whether chain is unbroken
    function verifyAuditChain(
        bytes32 startEntry,
        bytes32 endEntry
    ) external view returns (bool isValid);
    
    // === View Functions ===
    
    /// @notice Get audit entry
    /// @param entryId Entry identifier
    /// @return entry Audit entry details
    function getAuditEntry(bytes32 entryId) external view returns (AuditEntry memory entry);
    
    /// @notice Get audit entries for entity
    /// @param entity Entity address
    /// @param eventType Filter by event type (0 for all)
    /// @param fromTimestamp Start timestamp
    /// @param toTimestamp End timestamp
    /// @return entries Array of audit entries
    function getEntityAuditTrail(
        address entity,
        AuditEventType eventType,
        uint256 fromTimestamp,
        uint256 toTimestamp
    ) external view returns (AuditEntry[] memory entries);
    
    /// @notice Get latest audit entry hash (for chain verification)
    /// @return hash Latest entry hash
    function getLatestAuditHash() external view returns (bytes32 hash);
    
    /// @notice Get audit statistics
    /// @param eventType Event type to query
    /// @param period Time period in seconds
    /// @return count Number of events in period
    function getAuditStats(
        AuditEventType eventType,
        uint256 period
    ) external view returns (uint256 count);
}
```

### 3.8 Oracle Facet

**Purpose**: Secure integration with external compliance data providers.

#### Interfaceeses

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IOracleFacet - External data oracle management
/// @notice Handles secure updates from trusted compliance data providers
interface IOracleFacet {
    
    /// @notice Oracle data types
    enum OracleDataType {
        SANCTIONS_LIST,
        PEP_LIST,
        EXCHANGE_RATE,
        RISK_SCORE,
        KYC_VERIFICATION,
        CREDIT_SCORE
    }
    
    /// @notice Oracle update request
    struct OracleRequest {
        bytes32 requestId;
        OracleDataType dataType;
        bytes32 dataKey;
        uint256 requestTimestamp;
        uint256 expirationTimestamp;
        address requester;
        bool fulfilled;
    }
    
    // === Events ===
    
    /// @notice Emitted when oracle data is updated
    event OracleDataUpdated(
        bytes32 indexed requestId,
        OracleDataType indexed dataType,
        bytes32 dataKey,
        address indexed oracle,
        uint256 timestamp
    );
    
    /// @notice Emitted when oracle is registered
    event OracleRegistered(
        address indexed oracle,
        OracleDataType[] authorizedTypes,
        uint256 timestamp
    );
    
    // === Core Functions ===
    
    /// @notice Register trusted oracle
    /// @param oracle Oracle address
    /// @param authorizedTypes Data types oracle can update
    function registerOracle(
        address oracle,
        OracleDataType[] calldata authorizedTypes
    ) external;
    
    /// @notice Revoke oracle authorization
    /// @param oracle Oracle address
    function revokeOracle(address oracle) external;
    
    /// @notice Submit oracle data update
    /// @param dataType Type of data being updated
    /// @param dataKey Key for the data
    /// @param dataValue Value to store (encoded)
    /// @param signature Oracle signature
    function submitOracleUpdate(
        OracleDataType dataType,
        bytes32 dataKey,
        bytes calldata dataValue,
        bytes calldata signature
    ) external;
    
    /// @notice Request data update from oracle
    /// @param dataType Type of data needed
    /// @param dataKey Specific data key
    /// @return requestId Request identifier
    function requestOracleData(
        OracleDataType dataType,
        bytes32 dataKey
    ) external returns (bytes32 requestId);
    
    // === View Functions ===
    
    /// @notice Check if address is authorized oracle
    /// @param oracle Address to check
    /// @return isAuthorized Whether address is authorized
    function isAuthorizedOracle(address oracle) external view returns (bool isAuthorized);
    
    /// @notice Get oracle's authorized data types
    /// @param oracle Oracle address
    /// @return types Array of authorized data types
    function getOracleAuthorizations(
        address oracle
    ) external view returns (OracleDataType[] memory types);
    
    /// @notice Get pending oracle requests
    /// @param dataType Filter by data type
    /// @return requests Array of pending requests
    function getPendingRequests(
        OracleDataType dataType
    ) external view returns (OracleRequest[] memory requests);
}
```

---

## 4.0 Access Control Architecture

### 4.1 Role Definitions

```solidity
/// @notice Access control roles for compliance system
library LibRoles {
    // Core administrative roles
    bytes32 constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 constant COMPLIANCE_OFFICER_ROLE = keccak256("COMPLIANCE_OFFICER_ROLE");
    bytes32 constant KYC_VERIFIER_ROLE = keccak256("KYC_VERIFIER_ROLE");
    bytes32 constant AML_ANALYST_ROLE = keccak256("AML_ANALYST_ROLE");
    bytes32 constant SANCTIONS_MANAGER_ROLE = keccak256("SANCTIONS_MANAGER_ROLE");
    bytes32 constant TAX_OFFICER_ROLE = keccak256("TAX_OFFICER_ROLE");
    bytes32 constant AUDITOR_ROLE = keccak256("AUDITOR_ROLE");
    
    // Operational roles
    bytes32 constant ORACLE_ROLE = keccak256("ORACLE_ROLE");
    bytes32 constant FACTOR_ROLE = keccak256("FACTOR_ROLE");
    bytes32 constant SELLER_ROLE = keccak256("SELLER_ROLE");
    bytes32 constant BUYER_ROLE = keccak256("BUYER_ROLE");
    
    // Emergency roles
    bytes32 constant EMERGENCY_ADMIN_ROLE = keccak256("EMERGENCY_ADMIN_ROLE");
    bytes32 constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
}
```

### 4.2 Role-Function Mapping

| Function | Required Role(s) |
|----------|-----------------|
| `initiateKYC` | SELLER_ROLE, BUYER_ROLE, FACTOR_ROLE |
| `approveKYC` | KYC_VERIFIER_ROLE |
| `assessTransaction` | FACTOR_ROLE, AML_ANALYST_ROLE |
| `createSAR` | AML_ANALYST_ROLE |
| `submitSAR` | COMPLIANCE_OFFICER_ROLE |
| `updateSanctionsList` | ORACLE_ROLE, SANCTIONS_MANAGER_ROLE |
| `registerInvoice` | SELLER_ROLE |
| `createFactoringAgreement` | FACTOR_ROLE |
| `configureJurisdiction` | ADMIN_ROLE |
| `emergencyPause` | EMERGENCY_ADMIN_ROLE, PAUSER_ROLE |

---

## 5.0 Security Considerations

### 5.1 Critical Security Requirements

| Requirement | Implementation |
|-------------|----------------|
| **Storage Collision Prevention** | Diamond Storage pattern with unique namespace per facet |
| **Function Selector Management** | Automated collision detection in DiamondCut |
| **Reentrancy Protection** | ReentrancyGuard modifier on all state-changing functions |
| **Access Control** | Role-based with multi-signature requirements for critical operations |
| **Upgrade Safety** | Timelock on DiamondCut operations (48-hour minimum) |
| **Oracle Security** | Multi-oracle consensus for sanctions updates |
| **Data Privacy** | Hash-based identity storage; no PII on-chain |
| **Audit Integrity** | Hash-chained audit log with tamper detection |

### 5.2 Emergency Procedures

```solidity
/// @notice Emergency pause modifier
modifier whenNotPaused() {
    AppStorage storage s = LibAppStorage.appStorage();
    if (s.systemPaused) revert SystemPaused();
    _;
}

/// @notice Emergency functions interface
interface IEmergencyFacet {
    function emergencyPause() external;
    function emergencyUnpause() external;
    function emergencyWithdraw(address token, uint256 amount) external;
    function emergencyUpgrade(IDiamondCut.FacetCut[] calldata cuts) external;
}
```

---

## 6.0 Gas Optimization Strategy

### 6.1 Optimization Techniques

1. **Merkle Proofs for Sanctions**: Instead of storing full lists on-chain, store Merkle roots and verify inclusion off-chain
2. **Batch Operations**: Group multiple KYC approvals/sanctions checks in single transactions
3. **Storage Packing**: Pack related boolean flags into single storage slots
4. **Custom Errors**: Use custom errors instead of require strings
5. **Calldata over Memory**: Use calldata for read-only parameters
6. **Lazy Evaluation**: Defer expensive computations until necessary

### 6.2 Estimated Gas Costs

| Operation | Estimated Gas | Notes |
|-----------|---------------|-------|
| `registerInvoice` | ~80,000 | Initial storage writes |
| `screenEntity` (Merkle) | ~35,000 | Single proof verification |
| `assessTransaction` | ~50,000 | Risk calculation + storage |
| `approveKYC` | ~70,000 | Full record creation |
| `createFactoringAgreement` | ~95,000 | Agreement + status updates |

---

## 7.0 Implementation Roadmap

### Phase 1: Core Infrastructure (Weeks 1-4)

- [ ] AppStorage library implementation
- [ ] Diamond core (DiamondCut, DiamondLoupe, Ownership)
- [ ] Access control facet
- [ ] Audit facet
- [ ] Foundry test framework setup

### Phase 2: KYC & Sanctions (Weeks 5-8)

- [ ] KYC Facet implementation
- [ ] Sanctions Facet with Merkle verification
- [ ] Oracle Facet for external data
- [ ] Integration tests

### Phase 3: AML & Tax (Weeks 9-12)

- [ ] AML Facet implementation
- [ ] FATCA/CRS Facet
- [ ] Transaction monitoring logic
- [ ] Risk scoring algorithms

### Phase 4: Invoice Registry (Weeks 13-16)

- [ ] Invoice Registry Facet
- [ ] Double-factoring prevention
- [ ] Factoring agreement management
- [ ] Integration with payment flows

### Phase 5: Jurisdiction & Integration (Weeks 17-20)

- [ ] Jurisdiction Facet
- [ ] Cross-border assessment logic
- [ ] Full system integration testing
- [ ] Security audit preparation

### Phase 6: Audit & Deployment (Weeks 21-24)

- [ ] External security audit
- [ ] Testnet deployment
- [ ] Performance optimization
- [ ] Mainnet deployment

---

## 8.0 Next Steps

### Immediate Actions Required

1. **Storage Layout Review**: Confirm AppStorage structure meets all facet requirements
2. **Interface Finalization**: Review and approve all interface definitions
3. **Access Control Matrix**: Validate role-function mappings with your compliance team
4. **Oracle Selection**: Identify trusted data providers for sanctions/KYC verification
5. **Legal Review**: Ensure on-chain data storage complies with GDPR and data residency requirements

### Questions for Client

1. What specific sanctions lists must be supported at launch?
2. What is the expected transaction volume for gas estimation?
3. Are there existing identity verification providers to integrate?
4. What are the multi-signature requirements for critical operations?
5. What blockchain network(s) are targeted for deployment?

---

*Document Version: 1.0*  
*Last Updated: December 2, 2025*  
*Classification: Open Source — MIT License*
*Author: John A. Welch*
