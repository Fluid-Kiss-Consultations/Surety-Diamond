// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage, SystemPaused} from "../libraries/LibAppStorage.sol";
import {LibRoles} from "../libraries/LibRoles.sol";
import {IAMLFacet} from "../interfaces/IAMLFacet.sol";

/// @title AMLFacet
/// @author Surety Compliance System
/// @notice Anti-Money Laundering transaction monitoring and risk scoring
/// @dev Implements FATF-compliant AML controls with real-time transaction assessment
contract AMLFacet is IAMLFacet {
    using LibAppStorage for LibAppStorage.AppStorage;

    // ============ Constants ============

    uint256 private constant MAX_RISK_SCORE = 1000;
    uint256 private constant HIGH_RISK_THRESHOLD = 750;
    uint256 private constant MEDIUM_RISK_THRESHOLD = 400;
    uint256 private constant SAR_FILING_THRESHOLD = 10000 * 1e18; // $10,000

    // ============ Errors ============

    error TransactionBlocked();
    error InvalidRiskScore();
    error UnauthorizedAnalyst();
    error TransactionNotFound();

    // ============ Modifiers ============

    modifier whenNotPaused() {
        if (LibAppStorage.isPaused()) revert SystemPaused();
        _;
    }

    modifier onlyAMLAnalyst() {
        LibRoles.checkRole(LibRoles.AML_ANALYST_ROLE);
        _;
    }

    modifier onlyComplianceOfficer() {
        LibRoles.checkRole(LibRoles.COMPLIANCE_OFFICER_ROLE);
        _;
    }

    // ============ Core Functions ============

    /// @inheritdoc IAMLFacet
    function assessTransaction(
        bytes32 transactionId,
        address from,
        address to,
        uint256 amount,
        bytes32 currency,
        bytes32 transactionType
    ) external whenNotPaused returns (LibAppStorage.RiskScore memory score, bool canProceed) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        // Base risk factors
        uint256 riskPoints = 0;

        // Check entity KYC risk scores
        LibAppStorage.KYCRecord memory fromKYC = s.kycRecords[from];
        LibAppStorage.KYCRecord memory toKYC = s.kycRecords[to];

        riskPoints += fromKYC.riskScore / 10;
        riskPoints += toKYC.riskScore / 10;

        // PEP involvement raises risk
        if (fromKYC.isPEP || toKYC.isPEP) {
            riskPoints += 200;
        }

        // Unverified entities raise risk
        if (fromKYC.status != LibAppStorage.KYCStatus.APPROVED) riskPoints += 300;
        if (toKYC.status != LibAppStorage.KYCStatus.APPROVED) riskPoints += 300;

        // Large amounts raise risk
        if (amount >= SAR_FILING_THRESHOLD) {
            riskPoints += 100;
        }

        // Cap risk score
        if (riskPoints > MAX_RISK_SCORE) riskPoints = MAX_RISK_SCORE;

        LibAppStorage.RiskLevel riskLevel;
        if (riskPoints >= HIGH_RISK_THRESHOLD) riskLevel = LibAppStorage.RiskLevel.HIGH;
        else if (riskPoints >= MEDIUM_RISK_THRESHOLD) riskLevel = LibAppStorage.RiskLevel.MEDIUM;
        else riskLevel = LibAppStorage.RiskLevel.LOW;

        score = LibAppStorage.RiskScore({
            score: riskPoints,
            level: riskLevel,
            calculationDate: block.timestamp,
            riskFactors: new bytes32[](0),
            requiresReview: riskPoints >= HIGH_RISK_THRESHOLD
        });

        canProceed = riskPoints < HIGH_RISK_THRESHOLD;

        // Auto-file SAR for high-risk large transactions
        if (riskPoints >= HIGH_RISK_THRESHOLD && amount >= SAR_FILING_THRESHOLD) {
            emit SARFiled(transactionId, from, riskPoints, block.timestamp);
        }

        emit TransactionAssessed(
            transactionId,
            from,
            to,
            amount,
            riskPoints,
            canProceed
        );

        return (score, canProceed);
    }

    /// @inheritdoc IAMLFacet
    function setEntityRiskScore(
        address entity,
        uint256 riskScore,
        string calldata rationale
    ) external whenNotPaused onlyAMLAnalyst {
        if (riskScore > MAX_RISK_SCORE) revert InvalidRiskScore();

        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        s.kycRecords[entity].riskScore = riskScore;

        emit RiskScoreUpdated(entity, riskScore, msg.sender, rationale);
    }

    /// @inheritdoc IAMLFacet
    function flagSuspiciousActivity(
        address entity,
        bytes32 transactionId,
        string calldata reason
    ) external whenNotPaused onlyAMLAnalyst {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        // Escalate entity risk score
        uint256 current = s.kycRecords[entity].riskScore;
        uint256 escalated = current + 200 > MAX_RISK_SCORE ? MAX_RISK_SCORE : current + 200;
        s.kycRecords[entity].riskScore = escalated;

        emit SuspiciousActivityFlagged(entity, transactionId, reason, block.timestamp);
    }

    /// @inheritdoc IAMLFacet
    function fileSAR(
        address entity,
        bytes32 transactionId,
        uint256 riskScore,
        string calldata narrative
    ) external whenNotPaused onlyComplianceOfficer {
        // TODO: Store narrative in SAR record — currently only emitted via event fields
        emit SARFiled(transactionId, entity, riskScore, block.timestamp);
    }

    // ============ View Functions ============

    /// @inheritdoc IAMLFacet
    function getEntityRiskProfile(
        address entity
    ) external view returns (uint256 riskScore, bool isPEP, LibAppStorage.KYCStatus status) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.KYCRecord memory record = s.kycRecords[entity];
        riskScore = record.riskScore;
        isPEP = record.isPEP;
        status = record.status;
    }

    /// @inheritdoc IAMLFacet
    function isHighRisk(address entity) external view returns (bool) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        return s.kycRecords[entity].riskScore >= HIGH_RISK_THRESHOLD;
    }
}
