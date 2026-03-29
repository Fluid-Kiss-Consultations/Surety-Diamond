// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title ISanctionsFacet
/// @notice Interface for OFAC/UN/EU sanctions screening operations
interface ISanctionsFacet {

    struct ScreeningResult {
        bool isMatch;
        bool isPotentialMatch;
        uint256 matchScore;
        LibAppStorage.SanctionsList[] matchedLists;
        bytes32 matchedEntityHash;
    }

    event SanctionsMatchFound(address indexed entity, LibAppStorage.SanctionsList[] lists, bytes32 entityHash, uint256 timestamp);
    event EntityScreened(address indexed entity, bytes32 identityHash, bool isMatch, uint256 matchScore, uint256 timestamp);
    event SanctionsListUpdated(LibAppStorage.SanctionsList indexed listType, bytes32 newRoot, uint256 entryCount, uint256 timestamp);
    event EntityCleared(address indexed entity, uint256 timestamp, address clearedBy);

    /// @notice Screen an entity against all active sanctions lists
    /// @param entity Address of the entity to screen
    /// @param identityHash Keccak256 hash of the entity's identity data
    /// @param nameVariants Array of hashed name variants to check
    /// @return result The screening result including match status and matched lists
    function screenEntity(address entity, bytes32 identityHash, bytes32[] calldata nameVariants) external returns (ScreeningResult memory result);

    /// @notice Verify an entity hash against a specific sanctions list using a Merkle proof
    /// @param entityHash Hash of the entity to verify
    /// @param listType The sanctions list to check against
    /// @param proof Merkle proof for the entity against the list root
    /// @return isListed True if the entity is on the specified list
    function verifyAgainstList(bytes32 entityHash, LibAppStorage.SanctionsList listType, bytes32[] calldata proof) external view returns (bool isListed);

    /// @notice Update the Merkle root of a sanctions list
    /// @param listType The sanctions list to update
    /// @param newRoot New Merkle root hash
    /// @param entryCount Number of entries in the updated list
    function updateSanctionsList(LibAppStorage.SanctionsList listType, bytes32 newRoot, uint256 entryCount) external;

    /// @notice Add an entity to the sanctions records
    /// @param entity Address of the entity being sanctioned
    /// @param entityHash Hash identifying the entity
    /// @param record Full sanction record to store
    function addToSanctionsList(address entity, bytes32 entityHash, LibAppStorage.SanctionRecord calldata record) external;

    /// @notice Remove an entity from the sanctions records
    /// @param entity Address of the entity being removed
    /// @param entityHash Hash identifying the entity to remove
    /// @param reason Justification for removal
    function removeFromSanctionsList(address entity, bytes32 entityHash, string calldata reason) external;

    /// @notice Clear a false positive sanctions match for an entity
    /// @param entity Address of the entity to clear
    /// @param identityHash Keccak256 hash of the entity's identity data
    /// @param clearanceReason Justification for clearing the match
    function clearFalsePositive(address entity, bytes32 identityHash, string calldata clearanceReason) external;

    /// @notice Check whether an entity is currently sanctioned
    /// @param entity Address to check
    /// @return True if the entity is flagged as sanctioned
    function isSanctioned(address entity) external view returns (bool);

    /// @notice Retrieve the sanction record for an entity hash
    /// @param entityHash Hash identifying the entity
    /// @return record The stored sanction record
    function getSanctionRecord(bytes32 entityHash) external view returns (LibAppStorage.SanctionRecord memory record);

    /// @notice Get the current Merkle root and last update timestamp for a sanctions list
    /// @param listType The sanctions list to query
    /// @return root Current Merkle root
    /// @return lastUpdate Timestamp of the most recent update
    function getSanctionsListRoot(LibAppStorage.SanctionsList listType) external view returns (bytes32 root, uint256 lastUpdate);
}
