// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title IAuditFacet
/// @notice Interface for immutable hash-chained on-chain audit trail
interface IAuditFacet {

    event AuditLogged(
        bytes32 indexed entryId,
        LibAppStorage.AuditEventType indexed eventType,
        address indexed actor,
        address subject,
        bytes32 dataHash,
        uint256 timestamp
    );

    /// @notice Create a new audit log entry linked to the hash chain
    /// @param eventType The type of compliance event being logged
    /// @param subject The address this audit entry pertains to
    /// @param dataHash Arbitrary data hash to attach to the entry
    /// @return entryId Unique identifier for the new audit entry
    function logAudit(
        LibAppStorage.AuditEventType eventType,
        address subject,
        bytes32 dataHash
    ) external returns (bytes32 entryId);

    /// @notice Verify the integrity of the audit hash chain between two entries
    /// @param startEntry Hash of the starting audit entry
    /// @param endEntry Hash of the ending audit entry
    /// @return isValid True if the chain is unbroken between start and end
    function verifyAuditChain(
        bytes32 startEntry,
        bytes32 endEntry
    ) external view returns (bool isValid);

    /// @notice Retrieve a single audit entry by its identifier
    /// @param entryId The unique identifier of the audit entry
    /// @return entry The full audit entry struct
    function getAuditEntry(
        bytes32 entryId
    ) external view returns (LibAppStorage.AuditEntry memory entry);

    /// @notice Retrieve filtered audit entries for a specific entity
    /// @param entity The address to query audit history for
    /// @param eventType Filter by this event type
    /// @param fromTimestamp Start of the time range (inclusive)
    /// @param toTimestamp End of the time range (inclusive, 0 for unbounded)
    /// @return entries Array of matching audit entries
    function getEntityAuditTrail(
        address entity,
        LibAppStorage.AuditEventType eventType,
        uint256 fromTimestamp,
        uint256 toTimestamp
    ) external view returns (LibAppStorage.AuditEntry[] memory entries);

    /// @notice Get the most recent hash in the audit chain
    /// @return hash The latest audit hash
    function getLatestAuditHash() external view returns (bytes32 hash);

    /// @notice Get audit statistics for a given event type and time period
    /// @param eventType The event type to filter by
    /// @param period Time period in seconds to look back from now
    /// @return count Number of matching audit entries
    function getAuditStats(
        LibAppStorage.AuditEventType eventType,
        uint256 period
    ) external view returns (uint256 count);

    /// @notice Log a KYC-related audit event (reverts if eventType is not a KYC type)
    /// @param entity The subject address of the KYC event
    /// @param eventType Must be a KYC_* AuditEventType value
    /// @param dataHash Arbitrary data hash to attach to the entry
    function logKYCEvent(
        address entity,
        LibAppStorage.AuditEventType eventType,
        bytes32 dataHash
    ) external;

    /// @notice Log an AML-related audit event (reverts if eventType is not an AML type)
    /// @param entity The subject address of the AML event
    /// @param eventType Must be an AML_* AuditEventType value
    /// @param dataHash Arbitrary data hash to attach to the entry
    function logAMLEvent(
        address entity,
        LibAppStorage.AuditEventType eventType,
        bytes32 dataHash
    ) external;

    /// @notice Log a sanctions-related audit event (reverts if eventType is not a sanctions type)
    /// @param entity The subject address of the sanctions event
    /// @param eventType Must be a SANCTIONS_* AuditEventType value
    /// @param dataHash Arbitrary data hash to attach to the entry
    function logSanctionsEvent(
        address entity,
        LibAppStorage.AuditEventType eventType,
        bytes32 dataHash
    ) external;
}
