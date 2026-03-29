// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage, SystemPaused} from "../libraries/LibAppStorage.sol";
import {LibRoles} from "../libraries/LibRoles.sol";
import {IJurisdictionFacet} from "../interfaces/IJurisdictionFacet.sol";

/// @title JurisdictionFacet
/// @author Surety Compliance System
/// @notice Multi-jurisdiction compliance rule management
/// @dev Handles cross-border compliance and jurisdiction-specific requirements.
///      All state is stored in LibAppStorage — never in facet instance variables.
contract JurisdictionFacet is IJurisdictionFacet {

    // ============================================================
    // Errors
    // ============================================================

    error JurisdictionNotFound();
    error InvalidJurisdiction();
    error TransactionNotPermitted();
    error JurisdictionBlocked();
    error ExceedsTransactionLimit();
    error ZeroAddress();

    // ============================================================
    // Modifiers
    // ============================================================

    modifier whenNotPaused() {
        if (LibAppStorage.isPaused()) revert SystemPaused();
        _;
    }

    modifier onlyAdmin() {
        LibRoles.checkRole(LibRoles.DEFAULT_ADMIN_ROLE);
        _;
    }

    modifier onlyComplianceOfficer() {
        LibRoles.checkRole(LibRoles.COMPLIANCE_OFFICER_ROLE);
        _;
    }

    // ============================================================
    // Core Functions
    // ============================================================

    /// @inheritdoc IJurisdictionFacet
    function configureJurisdiction(
        LibAppStorage.JurisdictionConfig calldata config
    ) external whenNotPaused onlyAdmin {
        if (config.jurisdictionId == bytes32(0)) revert InvalidJurisdiction();
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        s.jurisdictionConfigs[config.jurisdictionId] = config;
        emit JurisdictionUpdated(config.jurisdictionId, config.isActive, block.timestamp);
    }

    /// @inheritdoc IJurisdictionFacet
    function assignEntityJurisdiction(
        address entity,
        bytes32 jurisdictionId
    ) external whenNotPaused onlyComplianceOfficer {
        if (entity == address(0)) revert ZeroAddress();
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        if (!s.jurisdictionConfigs[jurisdictionId].isActive) revert JurisdictionNotFound();
        s.entityJurisdictions[entity] = jurisdictionId;
        emit EntityJurisdictionAssigned(entity, jurisdictionId, block.timestamp);
    }

    /// @inheritdoc IJurisdictionFacet
    function assessCrossBorder(
        address from,
        address to,
        uint256 amount,
        bytes32 transactionType
    ) external whenNotPaused returns (LibAppStorage.CrossBorderAssessment memory assessment) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        bytes32 sourceJurisdiction = s.entityJurisdictions[from];
        bytes32 destJurisdiction = s.entityJurisdictions[to];

        assessment.sourceJurisdiction = sourceJurisdiction;
        assessment.destinationJurisdiction = destJurisdiction;

        // Blocked pair check
        if (s.blockedJurisdictionPairs[sourceJurisdiction][destJurisdiction]) {
            assessment.isPermitted = false;
            emit CrossBorderAssessed(
                keccak256(abi.encodePacked(from, to, block.timestamp)),
                sourceJurisdiction,
                destJurisdiction,
                false,
                block.timestamp
            );
            revert TransactionNotPermitted();
        }

        LibAppStorage.JurisdictionConfig memory sourceConfig = s.jurisdictionConfigs[sourceJurisdiction];
        LibAppStorage.JurisdictionConfig memory destConfig = s.jurisdictionConfigs[destJurisdiction];

        // Transaction limit check
        if (
            (sourceConfig.maxTransactionAmount > 0 && amount > sourceConfig.maxTransactionAmount) ||
            (destConfig.maxTransactionAmount > 0 && amount > destConfig.maxTransactionAmount)
        ) {
            assessment.isPermitted = false;
            revert ExceedsTransactionLimit();
        }

        // Determine strictest required KYC level
        assessment.requiredKYCLevel = sourceConfig.minimumKYCLevel > destConfig.minimumKYCLevel
            ? sourceConfig.minimumKYCLevel
            : destConfig.minimumKYCLevel;

        // Enhanced due diligence
        assessment.requiresEnhancedDueDiligence =
            (sourceConfig.enhancedDueDiligenceThreshold > 0 && amount > sourceConfig.enhancedDueDiligenceThreshold) ||
            (destConfig.enhancedDueDiligenceThreshold > 0 && amount > destConfig.enhancedDueDiligenceThreshold);

        // Additional withholding for cross-border
        if (sourceJurisdiction != destJurisdiction) {
            assessment.additionalWithholding = destConfig.withholdingRate;
        }

        assessment.isPermitted = true;

        emit CrossBorderAssessed(
            keccak256(abi.encodePacked(from, to, block.timestamp)),
            sourceJurisdiction,
            destJurisdiction,
            true,
            block.timestamp
        );

        return assessment;
    }

    /// @inheritdoc IJurisdictionFacet
    function blockJurisdictionOperation(
        bytes32 jurisdictionId,
        bytes32 operationType
    ) external whenNotPaused onlyAdmin {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.JurisdictionConfig storage config = s.jurisdictionConfigs[jurisdictionId];
        if (config.jurisdictionId == bytes32(0)) revert JurisdictionNotFound();

        if (operationType == keccak256("FACTORING")) {
            config.allowedForFactoring = false;
        }

        emit JurisdictionUpdated(jurisdictionId, config.isActive, block.timestamp);
    }

    /// @inheritdoc IJurisdictionFacet
    function blockCounterpartyPair(
        bytes32 jurisdiction1,
        bytes32 jurisdiction2,
        string calldata reason
    ) external whenNotPaused onlyComplianceOfficer {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        s.blockedJurisdictionPairs[jurisdiction1][jurisdiction2] = true;
        s.blockedJurisdictionPairs[jurisdiction2][jurisdiction1] = true;
        emit CrossBorderAssessed(
            keccak256(abi.encodePacked(jurisdiction1, jurisdiction2, reason)),
            jurisdiction1,
            jurisdiction2,
            false,
            block.timestamp
        );
    }

    // ============================================================
    // View Functions
    // ============================================================

    /// @inheritdoc IJurisdictionFacet
    function getJurisdiction(
        bytes32 jurisdictionId
    ) external view returns (LibAppStorage.JurisdictionConfig memory config) {
        config = LibAppStorage.appStorage().jurisdictionConfigs[jurisdictionId];
    }

    /// @inheritdoc IJurisdictionFacet
    function getEntityJurisdiction(
        address entity
    ) external view returns (bytes32 jurisdictionId) {
        jurisdictionId = LibAppStorage.appStorage().entityJurisdictions[entity];
    }

    /// @inheritdoc IJurisdictionFacet
    function isTransactionPermitted(
        bytes32 sourceJurisdiction,
        bytes32 destJurisdiction,
        bytes32 transactionType
    ) external view returns (bool permitted) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        if (s.blockedJurisdictionPairs[sourceJurisdiction][destJurisdiction]) return false;
        LibAppStorage.JurisdictionConfig memory sourceConfig = s.jurisdictionConfigs[sourceJurisdiction];
        LibAppStorage.JurisdictionConfig memory destConfig = s.jurisdictionConfigs[destJurisdiction];
        permitted = sourceConfig.isActive && destConfig.isActive;
        if (transactionType == keccak256("FACTORING")) {
            permitted = permitted && sourceConfig.allowedForFactoring && destConfig.allowedForFactoring;
        }
    }

    /// @inheritdoc IJurisdictionFacet
    function getMinimumKYCLevel(
        bytes32 jurisdictionId
    ) external view returns (LibAppStorage.KYCLevel level) {
        level = LibAppStorage.appStorage().jurisdictionConfigs[jurisdictionId].minimumKYCLevel;
    }
}
