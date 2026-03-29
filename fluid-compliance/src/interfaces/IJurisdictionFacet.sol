// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title IJurisdictionFacet
/// @notice Interface for multi-jurisdiction compliance rule management
interface IJurisdictionFacet {

    event JurisdictionUpdated(bytes32 indexed jurisdictionId, bool isActive, uint256 timestamp);
    event EntityJurisdictionAssigned(address indexed entity, bytes32 indexed jurisdictionId, uint256 timestamp);
    event CrossBorderAssessed(bytes32 indexed assessmentId, bytes32 indexed sourceJurisdiction, bytes32 indexed destJurisdiction, bool isPermitted, uint256 timestamp);

    /// @notice Configure or update a jurisdiction's compliance rules
    /// @param config The jurisdiction configuration struct to apply
    function configureJurisdiction(LibAppStorage.JurisdictionConfig calldata config) external;

    /// @notice Assign an entity to a jurisdiction for compliance purposes
    /// @param entity Address of the entity
    /// @param jurisdictionId Identifier of the jurisdiction to assign
    function assignEntityJurisdiction(address entity, bytes32 jurisdictionId) external;

    /// @notice Assess a cross-border transaction between two entities
    /// @param from Sender address
    /// @param to Recipient address
    /// @param amount Transaction value in wei
    /// @param transactionType Type of transaction
    /// @return assessment The cross-border assessment result
    function assessCrossBorder(
        address from,
        address to,
        uint256 amount,
        bytes32 transactionType
    ) external returns (LibAppStorage.CrossBorderAssessment memory assessment);

    /// @notice Block a specific operation type within a jurisdiction
    /// @param jurisdictionId Jurisdiction to restrict
    /// @param operationType Operation to block (e.g., keccak256("FACTORING"))
    function blockJurisdictionOperation(bytes32 jurisdictionId, bytes32 operationType) external;

    /// @notice Block transactions between two jurisdictions
    /// @param jurisdiction1 First jurisdiction identifier
    /// @param jurisdiction2 Second jurisdiction identifier
    /// @param reason Justification for the block
    function blockCounterpartyPair(
        bytes32 jurisdiction1,
        bytes32 jurisdiction2,
        string calldata reason
    ) external;

    /// @notice Retrieve the configuration for a jurisdiction
    /// @param jurisdictionId Jurisdiction to query
    /// @return config The jurisdiction's configuration struct
    function getJurisdiction(
        bytes32 jurisdictionId
    ) external view returns (LibAppStorage.JurisdictionConfig memory config);

    /// @notice Get the jurisdiction assignment for an entity
    /// @param entity Address to query
    /// @return jurisdictionId The jurisdiction the entity is assigned to
    function getEntityJurisdiction(address entity) external view returns (bytes32 jurisdictionId);

    /// @notice Check whether a transaction between two jurisdictions is permitted
    /// @param sourceJurisdiction Originating jurisdiction
    /// @param destJurisdiction Destination jurisdiction
    /// @param transactionType Type of transaction
    /// @return permitted True if the transaction is allowed
    function isTransactionPermitted(
        bytes32 sourceJurisdiction,
        bytes32 destJurisdiction,
        bytes32 transactionType
    ) external view returns (bool permitted);

    /// @notice Get the minimum KYC level required by a jurisdiction
    /// @param jurisdictionId Jurisdiction to query
    /// @return level The minimum KYC level required
    function getMinimumKYCLevel(bytes32 jurisdictionId) external view returns (LibAppStorage.KYCLevel level);
}
