// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage, SystemPaused} from "../libraries/LibAppStorage.sol";
import {LibRoles} from "../libraries/LibRoles.sol";
import {ISanctionsFacet} from "../interfaces/ISanctionsFacet.sol";

/// @title SanctionsFacet
/// @author Surety Compliance System
/// @notice Real-time sanctions screening with Merkle proof verification
/// @dev Implements gas-efficient sanctions checking using Merkle trees
contract SanctionsFacet is ISanctionsFacet {
    using LibAppStorage for LibAppStorage.AppStorage;

    // ============ Errors ============

    error EntitySanctioned();
    error InvalidMerkleProof();
    error UnauthorizedOracle();
    error SanctionsListOutdated();

    // ============ Modifiers ============

    modifier whenNotPaused() {
        if (LibAppStorage.isPaused()) revert SystemPaused();
        _;
    }

    modifier onlySanctionsManager() {
        LibRoles.checkRole(LibRoles.SANCTIONS_MANAGER_ROLE);
        _;
    }

    modifier onlyOracle() {
        LibRoles.checkRole(LibRoles.ORACLE_ROLE);
        _;
    }

    // ============ Core Functions ============

    /// @inheritdoc ISanctionsFacet
    function screenEntity(
        address entity,
        bytes32 identityHash,
        bytes32[] calldata nameVariants
    ) external whenNotPaused returns (ScreeningResult memory result) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        if (s.sanctionedEntities[identityHash]) {
            LibAppStorage.SanctionRecord memory record = s.sanctionDetails[identityHash];
            result.isMatch = true;
            result.isPotentialMatch = false;
            result.matchScore = 100;
            result.matchedLists = record.lists;
            result.matchedEntityHash = identityHash;
            emit SanctionsMatchFound(entity, record.lists, identityHash, block.timestamp);
            return result;
        }

        for (uint256 i = 0; i < nameVariants.length; i++) {
            if (s.sanctionedEntities[nameVariants[i]]) {
                result.isPotentialMatch = true;
                result.matchScore = 75;
            }
        }

        emit EntityScreened(entity, identityHash, result.isMatch, result.matchScore);
        return result;
    }

    /// @inheritdoc ISanctionsFacet
    function verifyAgainstList(
        bytes32 entityHash,
        LibAppStorage.SanctionsList listType,
        bytes32[] calldata proof
    ) external view returns (bool isListed) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        bytes32 root = s.sanctionsListRoots[listType];
        if (root == bytes32(0)) return false;

        bytes32 computedHash = entityHash;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];
            if (computedHash <= proofElement) {
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        isListed = computedHash == root;
    }

    /// @inheritdoc ISanctionsFacet
    function updateSanctionsList(
        LibAppStorage.SanctionsList listType,
        bytes32 newRoot,
        uint256 entryCount
    ) external whenNotPaused onlyOracle {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        s.sanctionsListRoots[listType] = newRoot;
        s.lastSanctionsUpdate[listType] = block.timestamp;
        emit SanctionsListUpdated(listType, newRoot, entryCount, block.timestamp);
    }

    /// @inheritdoc ISanctionsFacet
    function addToSanctionsList(
        bytes32 entityHash,
        LibAppStorage.SanctionRecord calldata record
    ) external whenNotPaused onlySanctionsManager {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        s.sanctionedEntities[entityHash] = true;
        s.sanctionDetails[entityHash] = record;
        emit SanctionsMatchFound(address(0), record.lists, entityHash, block.timestamp);
    }

    /// @inheritdoc ISanctionsFacet
    function removeFromSanctionsList(
        bytes32 entityHash,
        string calldata reason
    ) external whenNotPaused onlySanctionsManager {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        s.sanctionedEntities[entityHash] = false;
        delete s.sanctionDetails[entityHash];
        emit EntityCleared(address(0), block.timestamp, msg.sender);
    }

    /// @inheritdoc ISanctionsFacet
    function clearFalsePositive(
        address entity,
        bytes32 identityHash,
        string calldata clearanceReason
    ) external whenNotPaused onlySanctionsManager {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        s.sanctionedEntities[identityHash] = false;
        delete s.sanctionDetails[identityHash];
        emit EntityCleared(entity, block.timestamp, msg.sender);
    }

    // ============ View Functions ============

    /// @inheritdoc ISanctionsFacet
    function isSanctioned(address entity) external view returns (bool) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        bytes32 identityHash = s.kycRecords[entity].identityHash;
        // Entities with no KYC record have no identity hash to screen against.
        // Access control elsewhere (KYC gates) must prevent unverified entities from transacting.
        if (identityHash == bytes32(0)) return false;
        return s.sanctionedEntities[identityHash];
    }

    /// @inheritdoc ISanctionsFacet
    function getSanctionRecord(
        bytes32 entityHash
    ) external view returns (LibAppStorage.SanctionRecord memory record) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        record = s.sanctionDetails[entityHash];
    }

    /// @inheritdoc ISanctionsFacet
    function getSanctionsListRoot(
        LibAppStorage.SanctionsList listType
    ) external view returns (bytes32 root, uint256 lastUpdate) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        root = s.sanctionsListRoots[listType];
        lastUpdate = s.lastSanctionsUpdate[listType];
    }
}
