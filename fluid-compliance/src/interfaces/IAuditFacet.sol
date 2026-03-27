// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IAuditFacet
/// @notice Interface for immutable on-chain audit trail management
interface IAuditFacet {

    enum AuditEventType {
        KYC_INITIATED, KYC_APPROVED, KYC_REJECTED,
        SANCTIONS_SCREEN, TRANSACTION_FLAGGED,
        ROLE_GRANTED, ROLE_REVOKED,
        SYSTEM_PAUSED, SYSTEM_RESUMED,
        INVOICE_REGISTERED, INVOICE_PAID
    }

    struct AuditEntry {
        bytes32 entryHash;        // keccak256 of entry data
        bytes32 previousHash;     // Links to prior entry (chain)
        AuditEventType eventType;
        address actor;
        address subject;
        uint256 timestamp;
        bytes32 dataHash;         // keccak256 of event-specific data
    }

    event AuditEntryCreated(bytes32 indexed entryHash, bytes32 indexed previousHash, AuditEventType eventType, address actor, uint256 timestamp);

    function createAuditEntry(AuditEventType eventType, address subject, bytes32 dataHash) external returns (bytes32 entryHash);
    function getAuditEntry(bytes32 entryHash) external view returns (AuditEntry memory entry);
    function getLatestAuditHash() external view returns (bytes32 latestHash);
    function getTotalAuditEntries() external view returns (uint256 count);
    function verifyAuditChain(bytes32 fromHash, bytes32 toHash) external view returns (bool valid);
}
