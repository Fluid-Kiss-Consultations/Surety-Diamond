// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";
import {LibRoles} from "../libraries/LibRoles.sol";
import {IAuditFacet} from "../interfaces/IAuditFacet.sol";

/// @title AuditFacet
/// @author Surety Compliance System
/// @notice Immutable audit logging for regulatory compliance
/// @dev Implements hash-chained audit trail with tamper detection.
///      All entries are written to LibAppStorage for cross-facet access.
contract AuditFacet is IAuditFacet {

    // ============================================================
    // Errors
    // ============================================================

    error InvalidAuditEntry();
    error AuditChainBroken();
    error UnauthorizedAuditor();
    error InvalidKYCEventType();
    error InvalidAMLEventType();
    error InvalidSanctionsEventType();

    // ============================================================
    // Modifiers
    // ============================================================

    modifier onlyAuditor() {
        LibRoles.checkRole(LibRoles.AUDITOR_ROLE);
        _;
    }

    // ============================================================
    // Core Functions
    // ============================================================

    /// @inheritdoc IAuditFacet
    /// @dev Access is gated by AUDITOR_ROLE; internal facets call _logAuditInternal directly.
    function logAudit(
        LibAppStorage.AuditEventType eventType,
        address subject,
        bytes32 dataHash
    ) external onlyAuditor returns (bytes32 entryId) {
        return _logAuditInternal(eventType, subject, dataHash);
    }

    /// @inheritdoc IAuditFacet
    function verifyAuditChain(
        bytes32 startEntry,
        bytes32 endEntry
    ) external view returns (bool isValid) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        bytes32 current = startEntry;
        uint256 maxIterations = 1000;
        uint256 iterations = 0;
        while (current != endEntry && iterations < maxIterations) {
            bytes32 next = s.auditChain[current];
            if (next == bytes32(0)) return false;
            current = next;
            iterations++;
        }
        return current == endEntry;
    }

    // ============================================================
    // View Functions
    // ============================================================

    /// @inheritdoc IAuditFacet
    function getAuditEntry(bytes32 entryId) external view returns (LibAppStorage.AuditEntry memory entry) {
        entry = LibAppStorage.appStorage().auditEntries[entryId];
    }

    /// @inheritdoc IAuditFacet
    function getEntityAuditTrail(
        address entity,
        LibAppStorage.AuditEventType eventType,
        uint256 fromTimestamp,
        uint256 toTimestamp
    ) external view returns (LibAppStorage.AuditEntry[] memory entries) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        bytes32[] memory ids = s.entityAuditIds[entity];

        uint256 count = 0;
        for (uint256 i = 0; i < ids.length; i++) {
            LibAppStorage.AuditEntry memory e = s.auditEntries[ids[i]];
            if (
                e.eventType == eventType &&
                e.timestamp >= fromTimestamp &&
                (toTimestamp == 0 || e.timestamp <= toTimestamp)
            ) count++;
        }

        entries = new LibAppStorage.AuditEntry[](count);
        uint256 idx = 0;
        for (uint256 i = 0; i < ids.length; i++) {
            LibAppStorage.AuditEntry memory e = s.auditEntries[ids[i]];
            if (
                e.eventType == eventType &&
                e.timestamp >= fromTimestamp &&
                (toTimestamp == 0 || e.timestamp <= toTimestamp)
            ) {
                entries[idx++] = e;
            }
        }
    }

    /// @inheritdoc IAuditFacet
    function getLatestAuditHash() external view returns (bytes32 hash) {
        hash = LibAppStorage.appStorage().latestAuditHash;
    }

    /// @inheritdoc IAuditFacet
    function getAuditStats(
        LibAppStorage.AuditEventType eventType,
        uint256 period
    ) external view returns (uint256 count) {
        // TODO: Implement filtering by eventType and period — currently returns total entries unfiltered
        count = LibAppStorage.appStorage().totalAuditEntries;
    }

    // ============================================================
    // Public Typed Logging Functions
    // ============================================================

    /// @notice Log a KYC-related audit event (reverts if eventType is not a KYC type)
    /// @param entity The subject address of the KYC event
    /// @param eventType Must be a KYC_* AuditEventType value
    /// @param dataHash Arbitrary data hash to attach to the entry
    function logKYCEvent(
        address entity,
        LibAppStorage.AuditEventType eventType,
        bytes32 dataHash
    ) external onlyAuditor {
        _requireKYCEventType(eventType);
        _logAuditInternal(eventType, entity, dataHash);
    }

    /// @notice Log an AML-related audit event (reverts if eventType is not an AML type)
    /// @param entity The subject address of the AML event
    /// @param eventType Must be an AML_* AuditEventType value
    /// @param dataHash Arbitrary data hash to attach to the entry
    function logAMLEvent(
        address entity,
        LibAppStorage.AuditEventType eventType,
        bytes32 dataHash
    ) external onlyAuditor {
        _requireAMLEventType(eventType);
        _logAuditInternal(eventType, entity, dataHash);
    }

    /// @notice Log a sanctions-related audit event (reverts if eventType is not a sanctions type)
    /// @param entity The subject address of the sanctions event
    /// @param eventType Must be a SANCTIONS_* AuditEventType value
    /// @param dataHash Arbitrary data hash to attach to the entry
    function logSanctionsEvent(
        address entity,
        LibAppStorage.AuditEventType eventType,
        bytes32 dataHash
    ) external onlyAuditor {
        _requireSanctionsEventType(eventType);
        _logAuditInternal(eventType, entity, dataHash);
    }

    // ============================================================
    // Internal
    // ============================================================

    function _logAuditInternal(
        LibAppStorage.AuditEventType eventType,
        address subject,
        bytes32 dataHash
    ) internal returns (bytes32 entryId) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        entryId = keccak256(abi.encodePacked(
            eventType, msg.sender, subject, dataHash, block.timestamp, s.totalAuditEntries
        ));

        bytes32 previousHash = s.latestAuditHash;
        bytes32 newHash = keccak256(abi.encodePacked(entryId, previousHash, block.timestamp));

        s.auditChain[previousHash] = newHash;
        s.latestAuditHash = newHash;
        s.totalAuditEntries++;

        s.auditEntries[entryId] = LibAppStorage.AuditEntry({
            entryId: entryId,
            eventType: eventType,
            actor: msg.sender,
            subject: subject,
            dataHash: dataHash,
            timestamp: block.timestamp,
            previousEntryHash: previousHash
        });
        s.entityAuditIds[subject].push(entryId);

        emit AuditLogged(entryId, eventType, msg.sender, subject, dataHash, block.timestamp);
        return entryId;
    }

    function _requireKYCEventType(LibAppStorage.AuditEventType eventType) internal pure {
        if (
            eventType != LibAppStorage.AuditEventType.KYC_INITIATED &&
            eventType != LibAppStorage.AuditEventType.KYC_APPROVED &&
            eventType != LibAppStorage.AuditEventType.KYC_REJECTED &&
            eventType != LibAppStorage.AuditEventType.KYC_EXPIRED
        ) revert InvalidKYCEventType();
    }

    function _requireAMLEventType(LibAppStorage.AuditEventType eventType) internal pure {
        if (
            eventType != LibAppStorage.AuditEventType.TRANSACTION_ASSESSED &&
            eventType != LibAppStorage.AuditEventType.TRANSACTION_BLOCKED &&
            eventType != LibAppStorage.AuditEventType.SAR_FILED
        ) revert InvalidAMLEventType();
    }

    function _requireSanctionsEventType(LibAppStorage.AuditEventType eventType) internal pure {
        if (
            eventType != LibAppStorage.AuditEventType.SANCTIONS_SCREENED &&
            eventType != LibAppStorage.AuditEventType.SANCTIONS_MATCH &&
            eventType != LibAppStorage.AuditEventType.SANCTIONS_CLEARED
        ) revert InvalidSanctionsEventType();
    }
}
