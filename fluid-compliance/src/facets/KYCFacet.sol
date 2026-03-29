// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage, SystemPaused} from "../libraries/LibAppStorage.sol";
import {LibRoles} from "../libraries/LibRoles.sol";
import {IKYCFacet} from "../interfaces/IKYCFacet.sol";

/// @title KYCFacet
/// @author Surety Compliance System
/// @notice Handles KYC verification and management
/// @dev Implements comprehensive KYC operations with FATF compliance
contract KYCFacet is IKYCFacet {
    using LibAppStorage for LibAppStorage.AppStorage;

    // ============ Constants ============

    uint256 private constant KYC_VALIDITY_PERIOD = 365 days;

    // ============ Errors ============

    error KYCAlreadyInitiated();
    error KYCNotFound();
    error InvalidKYCLevel();
    error KYCExpired();
    error InvalidVerifier();
    error DocumentVerificationFailed();
    error ZeroAddress();

    // ============ Modifiers ============

    modifier whenNotPaused() {
        if (LibAppStorage.isPaused()) revert SystemPaused();
        _;
    }

    modifier onlyVerifier() {
        LibRoles.checkRole(LibRoles.KYC_VERIFIER_ROLE);
        _;
    }

    // ============ Core Functions ============

    /// @inheritdoc IKYCFacet
    function initiateKYC(
        address entity,
        bytes32 identityHash,
        LibAppStorage.KYCLevel level,
        bytes32 jurisdictionId
    ) external whenNotPaused {
        if (entity == address(0)) revert ZeroAddress();
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        if (s.kycRecords[entity].status == LibAppStorage.KYCStatus.APPROVED) {
            revert KYCAlreadyInitiated();
        }

        if (uint8(level) > uint8(LibAppStorage.KYCLevel.INSTITUTIONAL)) {
            revert InvalidKYCLevel();
        }

        s.kycRecords[entity] = LibAppStorage.KYCRecord({
            identityHash: identityHash,
            level: level,
            status: LibAppStorage.KYCStatus.PENDING,
            verificationDate: 0,
            expirationDate: 0,
            jurisdictionId: jurisdictionId,
            verifier: address(0),
            documentRoot: bytes32(0),
            isPEP: false,
            riskScore: 0
        });

        s.entityStatus[entity] = LibAppStorage.KYCStatus.PENDING;

        emit KYCInitiated(entity, identityHash, level, block.timestamp);
    }

    /// @inheritdoc IKYCFacet
    function approveKYC(
        address entity,
        LibAppStorage.KYCLevel level,
        bytes32 documentRoot,
        bool isPEP,
        uint256 riskScore
    ) external whenNotPaused onlyVerifier {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        LibAppStorage.KYCRecord storage record = s.kycRecords[entity];
        if (record.identityHash == bytes32(0)) {
            revert KYCNotFound();
        }

        record.level = level;
        record.status = LibAppStorage.KYCStatus.APPROVED;
        record.verificationDate = block.timestamp;
        record.expirationDate = block.timestamp + KYC_VALIDITY_PERIOD;
        record.verifier = msg.sender;
        record.documentRoot = documentRoot;
        record.isPEP = isPEP;
        record.riskScore = riskScore;

        s.entityStatus[entity] = LibAppStorage.KYCStatus.APPROVED;
        s.verifiedIdentities[record.identityHash] = true;

        emit KYCVerified(entity, level, record.expirationDate, msg.sender);
        emit KYCStatusChanged(
            entity,
            LibAppStorage.KYCStatus.PENDING,
            LibAppStorage.KYCStatus.APPROVED,
            msg.sender,
            "Verification complete"
        );
    }

    /// @inheritdoc IKYCFacet
    function rejectKYC(
        address entity,
        string calldata reason
    ) external whenNotPaused onlyVerifier {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        LibAppStorage.KYCRecord storage record = s.kycRecords[entity];
        if (record.identityHash == bytes32(0)) {
            revert KYCNotFound();
        }

        LibAppStorage.KYCStatus previousStatus = record.status;
        record.status = LibAppStorage.KYCStatus.REJECTED;
        s.entityStatus[entity] = LibAppStorage.KYCStatus.REJECTED;

        emit KYCStatusChanged(entity, previousStatus, LibAppStorage.KYCStatus.REJECTED, msg.sender, reason);
    }

    /// @inheritdoc IKYCFacet
    function updateKYCStatus(
        address entity,
        LibAppStorage.KYCStatus newStatus,
        string calldata reason
    ) external whenNotPaused onlyVerifier {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        LibAppStorage.KYCRecord storage record = s.kycRecords[entity];
        if (record.identityHash == bytes32(0)) {
            revert KYCNotFound();
        }

        LibAppStorage.KYCStatus previousStatus = record.status;
        record.status = newStatus;
        s.entityStatus[entity] = newStatus;

        emit KYCStatusChanged(entity, previousStatus, newStatus, msg.sender, reason);
    }

    // ============ View Functions ============

    /// @inheritdoc IKYCFacet
    function isKYCCompliant(
        address entity,
        LibAppStorage.KYCLevel requiredLevel
    ) external view returns (bool isCompliant) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.KYCRecord memory record = s.kycRecords[entity];

        isCompliant = record.status == LibAppStorage.KYCStatus.APPROVED &&
            uint8(record.level) >= uint8(requiredLevel) &&
            record.expirationDate > block.timestamp;
    }

    /// @inheritdoc IKYCFacet
    function getKYCRecord(
        address entity
    ) external view returns (LibAppStorage.KYCRecord memory record) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        record = s.kycRecords[entity];
    }

    /// @inheritdoc IKYCFacet
    function verifyDocument(
        address entity,
        bytes32 documentHash,
        bytes32[] calldata proof
    ) external view returns (bool isValid) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        LibAppStorage.KYCRecord memory record = s.kycRecords[entity];

        if (record.documentRoot == bytes32(0)) {
            return false;
        }

        bytes32 computedHash = documentHash;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        isValid = computedHash == record.documentRoot;
    }
}
