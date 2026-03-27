// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title IKYCFacet
/// @notice Interface for FATF-aligned Know Your Customer operations
interface IKYCFacet {

    event KYCInitiated(address indexed entity, bytes32 identityHash, LibAppStorage.KYCLevel level, uint256 timestamp);
    event KYCVerified(address indexed entity, LibAppStorage.KYCLevel level, uint256 expirationDate, address verifier);
    event KYCStatusChanged(address indexed entity, LibAppStorage.KYCStatus previousStatus, LibAppStorage.KYCStatus newStatus, address changedBy, string reason);

    function initiateKYC(address entity, bytes32 identityHash, LibAppStorage.KYCLevel level, bytes32 jurisdictionId) external;
    function approveKYC(address entity, LibAppStorage.KYCLevel level, bytes32 documentRoot, bool isPEP, uint256 riskScore) external;
    function rejectKYC(address entity, string calldata reason) external;
    function updateKYCStatus(address entity, LibAppStorage.KYCStatus newStatus, string calldata reason) external;
    function isKYCCompliant(address entity, LibAppStorage.KYCLevel requiredLevel) external view returns (bool isCompliant);
    function getKYCRecord(address entity) external view returns (LibAppStorage.KYCRecord memory record);
    function verifyDocument(address entity, bytes32 documentHash, bytes32[] calldata proof) external view returns (bool isValid);
}
