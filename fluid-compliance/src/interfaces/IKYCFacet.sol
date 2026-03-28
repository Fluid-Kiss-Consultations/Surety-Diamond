// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title IKYCFacet
/// @notice Interface for FATF-aligned Know Your Customer operations
interface IKYCFacet {

    event KYCInitiated(address indexed entity, bytes32 identityHash, LibAppStorage.KYCLevel level, uint256 timestamp);
    event KYCVerified(address indexed entity, LibAppStorage.KYCLevel level, uint256 expirationDate, address verifier);
    event KYCStatusChanged(address indexed entity, LibAppStorage.KYCStatus previousStatus, LibAppStorage.KYCStatus newStatus, address changedBy, string reason);

    /// @notice Initiate KYC verification for an entity
    /// @param entity Address of the entity to verify
    /// @param identityHash Keccak256 hash of off-chain identity documents
    /// @param level Requested KYC verification level
    /// @param jurisdictionId Jurisdiction under which KYC is being performed
    function initiateKYC(address entity, bytes32 identityHash, LibAppStorage.KYCLevel level, bytes32 jurisdictionId) external;

    /// @notice Approve a pending KYC application
    /// @param entity Address of the entity being approved
    /// @param level Approved KYC level
    /// @param documentRoot Merkle root of the verified document set
    /// @param isPEP Whether the entity is a Politically Exposed Person
    /// @param riskScore Initial risk score assigned during KYC (0–1000)
    function approveKYC(address entity, LibAppStorage.KYCLevel level, bytes32 documentRoot, bool isPEP, uint256 riskScore) external;

    /// @notice Reject a pending KYC application
    /// @param entity Address of the entity being rejected
    /// @param reason Human-readable rejection reason
    function rejectKYC(address entity, string calldata reason) external;

    /// @notice Update the KYC status of an already-verified entity
    /// @param entity Address of the entity
    /// @param newStatus The new KYC status to assign
    /// @param reason Justification for the status change
    function updateKYCStatus(address entity, LibAppStorage.KYCStatus newStatus, string calldata reason) external;

    /// @notice Check if an entity meets a required KYC level
    /// @param entity Address to check
    /// @param requiredLevel Minimum KYC level required
    /// @return isCompliant True if the entity's verified level meets or exceeds the requirement
    function isKYCCompliant(address entity, LibAppStorage.KYCLevel requiredLevel) external view returns (bool isCompliant);

    /// @notice Retrieve the full KYC record for an entity
    /// @param entity Address to query
    /// @return record The entity's KYC record struct
    function getKYCRecord(address entity) external view returns (LibAppStorage.KYCRecord memory record);

    /// @notice Verify a document hash against the entity's Merkle document root
    /// @param entity Address whose document root to verify against
    /// @param documentHash Hash of the document to verify
    /// @param proof Merkle proof path from documentHash to the root
    /// @return isValid True if the proof is valid
    function verifyDocument(address entity, bytes32 documentHash, bytes32[] calldata proof) external view returns (bool isValid);
}
