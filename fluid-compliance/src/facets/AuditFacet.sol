// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";
import {LibRoles} from "../libraries/LibRoles.sol";
import {IAuditFacet} from "../interfaces/IAuditFacet.sol";

/// @title AuditFacet
/// @author Surety Compliance System
/// @notice Immutable audit logging for regulatory compliance
/// @dev Implements hash-chained audit trail with tamper detection
contract AuditFacet is IAuditFacet {
    using LibAppStorage for LibAppStorage.AppStorage;

    // ============ Errors ============

    error InvalidAuditEntry();
    error AuditChainBroken();
    error UnauthorizedAuditor();

    // ============ Modifiers ============

    modifier onlyAuditor() {
        LibRoles.checkRole(LibRoles.AUDITOR_ROLE);
        _;
    }

    // ============ Core Functions ============

    /// @inheritdoc IAuditFacet
    function logAudit(
        AuditEventType eventType,
        address subject,
        bytes32 dataHash
    ) external returns (bytes32 entryId) {
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

    // ============ View Functions ============

    /// @inheritdoc IAuditFacet
    function getLatestAuditHash() external view returns (bytes32 hash) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        hash = s.latestAuditHash;
    }

    /// @inheritdoc IAuditFacet
    function getAuditStats(
        AuditEventType eventType,
        uint256 period
    ) external view returns (uint256 count) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        count = s.totalAuditEntries;
    }

    // ============ Public Logging Functions ============

    /// @notice Log a KYC-related audit event
    function logKYCEvent(
        address entity,
        AuditEventType eventType,
        bytes32 dataHash
    ) external {
        _logAuditInternal(eventType, entity, dataHash);
    }

    /// @notice Log an AML-related audit event
    function logAMLEvent(
        address entity,
        AuditEventType eventType,
        bytes32 dataHash
    ) external {
        _logAuditInternal(eventType, entity, dataHash);
    }

    /// @notice Log a sanctions-related audit event
    function logSanctionsEvent(
        address entity,
        AuditEventType eventType,
        bytes32 dataHash
    ) external {
        _logAuditInternal(eventType, entity, dataHash);
    }

    // ============ Internal Functions ============

    function _logAuditInternal(
        AuditEventType eventType,
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

        emit AuditLogged(entryId, eventType, msg.sender, subject, dataHash, block.timestamp);
        return entryId;
    }
}
