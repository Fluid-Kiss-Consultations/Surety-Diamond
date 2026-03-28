// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title IAMLFacet
/// @notice Interface for Anti-Money Laundering risk scoring and transaction monitoring
interface IAMLFacet {

    event SARFiled(bytes32 indexed transactionId, address indexed entity, uint256 riskScore, uint256 timestamp);
    event TransactionAssessed(bytes32 indexed transactionId, address indexed from, address indexed to, uint256 amount, uint256 riskScore, bool canProceed);
    event RiskScoreUpdated(address indexed entity, uint256 newScore, address indexed updatedBy, string rationale);
    event SuspiciousActivityFlagged(address indexed entity, bytes32 indexed transactionId, string reason, uint256 timestamp);

    /// @notice Assess the AML risk of a transaction and determine if it can proceed
    /// @param transactionId Unique identifier for the transaction
    /// @param from Sender address
    /// @param to Recipient address
    /// @param amount Transaction value in wei
    /// @param currency Currency identifier (e.g., keccak256("USD"))
    /// @param transactionType Type of transaction (e.g., keccak256("PAYMENT"))
    /// @return score The computed risk score breakdown
    /// @return canProceed Whether the transaction is permitted to proceed
    function assessTransaction(
        bytes32 transactionId,
        address from,
        address to,
        uint256 amount,
        bytes32 currency,
        bytes32 transactionType
    ) external returns (LibAppStorage.RiskScore memory score, bool canProceed);

    /// @notice Manually set the risk score for an entity
    /// @param entity Address of the entity to score
    /// @param riskScore Risk score on the 0–1000 scale
    /// @param rationale Human-readable justification for the score
    function setEntityRiskScore(address entity, uint256 riskScore, string calldata rationale) external;

    /// @notice Flag an entity for suspicious activity associated with a transaction
    /// @param entity Address of the flagged entity
    /// @param transactionId Related transaction identifier
    /// @param reason Description of the suspicious activity
    function flagSuspiciousActivity(address entity, bytes32 transactionId, string calldata reason) external;

    /// @notice File a Suspicious Activity Report (SAR) for regulatory submission
    /// @param entity Address of the reported entity
    /// @param transactionId Related transaction identifier
    /// @param riskScore Risk score at time of filing
    /// @param narrative Descriptive narrative for the SAR
    function fileSAR(address entity, bytes32 transactionId, uint256 riskScore, string calldata narrative) external;

    /// @notice Retrieve the current risk profile for an entity
    /// @param entity Address to query
    /// @return riskScore Current risk score (0–1000)
    /// @return isPEP Whether the entity is flagged as a Politically Exposed Person
    /// @return status Current KYC status of the entity
    function getEntityRiskProfile(
        address entity
    ) external view returns (uint256 riskScore, bool isPEP, LibAppStorage.KYCStatus status);

    /// @notice Check whether an entity is classified as high risk (score >= 750)
    /// @param entity Address to query
    /// @return True if the entity's risk score meets or exceeds the high-risk threshold
    function isHighRisk(address entity) external view returns (bool);
}
