// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage, SystemPaused} from "../libraries/LibAppStorage.sol";
import {LibRoles} from "../libraries/LibRoles.sol";
import {IOracleFacet} from "../interfaces/IOracleFacet.sol";

/// @title OracleFacet
/// @author Surety Compliance System
/// @notice Secure integration with external compliance data providers
/// @dev Manages oracle registration and data validation for real-time compliance.
///      All state is stored in LibAppStorage — never in facet instance variables.
contract OracleFacet is IOracleFacet {

    // ============================================================
    // Constants
    // ============================================================

    uint256 private constant ORACLE_DATA_EXPIRY = 24 hours;
    uint256 private constant ORACLE_REQUEST_EXPIRY = 1 hours;
    uint256 private constant MAX_ORACLES_PER_TYPE = 5;

    // ============================================================
    // Errors
    // ============================================================

    error UnauthorizedOracle();
    error OracleAlreadyRegistered();
    error DataExpired();
    error InvalidSignature();
    error OracleLimitReached(uint8 dataType);
    error OracleNotRegistered();
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

    modifier onlyOracle() {
        LibRoles.checkRole(LibRoles.ORACLE_ROLE);
        _;
    }

    // ============================================================
    // Core Functions
    // ============================================================

    /// @inheritdoc IOracleFacet
    function registerOracle(
        address oracle,
        LibAppStorage.OracleDataType[] calldata authorizedTypes
    ) external whenNotPaused onlyAdmin {
        if (oracle == address(0)) revert ZeroAddress();
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        if (s.oracleActive[oracle]) revert OracleAlreadyRegistered();

        // Enforce per-type oracle limit
        for (uint256 i = 0; i < authorizedTypes.length; i++) {
            uint8 typeId = uint8(authorizedTypes[i]);
            if (s.oracleTypeCount[typeId] >= MAX_ORACLES_PER_TYPE) {
                revert OracleLimitReached(typeId);
            }
            s.oracleTypeCount[typeId]++;
        }

        LibRoles.grantRole(LibRoles.ORACLE_ROLE, oracle);
        s.oracleActive[oracle] = true;
        s.oracleAuthorizedTypes[oracle] = abi.encode(authorizedTypes);

        emit OracleRegistered(oracle, authorizedTypes, block.timestamp);
    }

    /// @inheritdoc IOracleFacet
    function revokeOracle(address oracle) external whenNotPaused onlyAdmin {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        if (!s.oracleActive[oracle]) revert OracleNotRegistered();

        // Decrement per-type counts before clearing authorizations
        bytes memory encoded = s.oracleAuthorizedTypes[oracle];
        if (encoded.length > 0) {
            LibAppStorage.OracleDataType[] memory types = abi.decode(encoded, (LibAppStorage.OracleDataType[]));
            for (uint256 i = 0; i < types.length; i++) {
                uint8 typeId = uint8(types[i]);
                if (s.oracleTypeCount[typeId] > 0) {
                    s.oracleTypeCount[typeId]--;
                }
            }
        }

        LibRoles.revokeRole(LibRoles.ORACLE_ROLE, oracle);
        s.oracleActive[oracle] = false;
        delete s.oracleAuthorizedTypes[oracle];
    }

    /// @inheritdoc IOracleFacet
    function submitOracleUpdate(
        LibAppStorage.OracleDataType dataType,
        bytes32 dataKey,
        bytes calldata dataValue,
        bytes calldata signature
    ) external whenNotPaused onlyOracle {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();

        if (!_isAuthorizedForType(s, msg.sender, dataType)) revert UnauthorizedOracle();

        // Nonce prevents replay attacks across blocks with the same timestamp
        uint256 nonce = s.oracleNonce[msg.sender];
        bytes32 messageHash = keccak256(abi.encodePacked(
            dataType, dataKey, dataValue, nonce, block.timestamp
        ));
        if (!_verifySignature(messageHash, signature, msg.sender)) revert InvalidSignature();

        // Increment nonce after successful signature verification
        s.oracleNonce[msg.sender] = nonce + 1;

        bytes32 typeKey = bytes32(uint256(dataType));
        s.oracleCachedData[typeKey][dataKey] = dataValue;
        s.oracleDataTimestamps[typeKey][dataKey] = block.timestamp;

        if (dataType == LibAppStorage.OracleDataType.SANCTIONS_LIST) {
            _processSanctionsUpdate(s, dataKey, dataValue);
        }

        bytes32 updateId = keccak256(abi.encodePacked(dataType, dataKey, block.timestamp));
        emit OracleDataUpdated(updateId, dataType, dataKey, msg.sender, block.timestamp);
    }

    /// @inheritdoc IOracleFacet
    function requestOracleData(
        LibAppStorage.OracleDataType dataType,
        bytes32 dataKey
    ) external whenNotPaused returns (bytes32 requestId) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        s.oracleRequestNonce++;

        requestId = keccak256(abi.encodePacked(
            dataType, dataKey, msg.sender, s.oracleRequestNonce, block.timestamp
        ));

        s.oracleRequests[requestId] = LibAppStorage.OracleRequest({
            requestId: requestId,
            dataType: dataType,
            dataKey: dataKey,
            requestTimestamp: block.timestamp,
            expirationTimestamp: block.timestamp + ORACLE_REQUEST_EXPIRY,
            requester: msg.sender,
            fulfilled: false
        });

        s.oracleRequestIds.push(requestId);
        s.oracleRequestIdsByType[uint8(dataType)].push(requestId);

        emit OracleDataUpdated(requestId, dataType, dataKey, msg.sender, block.timestamp);
        return requestId;
    }

    // ============================================================
    // View Functions
    // ============================================================

    /// @inheritdoc IOracleFacet
    function isAuthorizedOracle(address oracle) external view returns (bool) {
        return LibAppStorage.appStorage().oracleActive[oracle];
    }

    /// @inheritdoc IOracleFacet
    function getOracleAuthorizations(
        address oracle
    ) external view returns (LibAppStorage.OracleDataType[] memory types) {
        bytes memory encoded = LibAppStorage.appStorage().oracleAuthorizedTypes[oracle];
        if (encoded.length == 0) return new LibAppStorage.OracleDataType[](0);
        types = abi.decode(encoded, (LibAppStorage.OracleDataType[]));
    }

    /// @inheritdoc IOracleFacet
    function getPendingRequests(
        LibAppStorage.OracleDataType dataType
    ) external view returns (LibAppStorage.OracleRequest[] memory requests) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        bytes32[] storage ids = s.oracleRequestIdsByType[uint8(dataType)];

        uint256 count = 0;
        for (uint256 i = 0; i < ids.length; i++) {
            LibAppStorage.OracleRequest storage req = s.oracleRequests[ids[i]];
            if (!req.fulfilled && req.expirationTimestamp > block.timestamp) {
                count++;
            }
        }

        requests = new LibAppStorage.OracleRequest[](count);
        uint256 idx = 0;
        for (uint256 i = 0; i < ids.length; i++) {
            LibAppStorage.OracleRequest storage req = s.oracleRequests[ids[i]];
            if (!req.fulfilled && req.expirationTimestamp > block.timestamp) {
                requests[idx++] = req;
            }
        }
    }

    /// @inheritdoc IOracleFacet
    function getOracleData(
        LibAppStorage.OracleDataType dataType,
        bytes32 dataKey
    ) external view returns (bytes memory data, uint256 timestamp) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        bytes32 typeKey = bytes32(uint256(dataType));
        timestamp = s.oracleDataTimestamps[typeKey][dataKey];
        if (timestamp == 0 || block.timestamp > timestamp + ORACLE_DATA_EXPIRY) revert DataExpired();
        data = s.oracleCachedData[typeKey][dataKey];
    }

    // ============================================================
    // Internal
    // ============================================================

    function _isAuthorizedForType(
        LibAppStorage.AppStorage storage s,
        address oracle,
        LibAppStorage.OracleDataType dataType
    ) internal view returns (bool) {
        if (!s.oracleActive[oracle]) return false;
        bytes memory encoded = s.oracleAuthorizedTypes[oracle];
        if (encoded.length == 0) return false;
        LibAppStorage.OracleDataType[] memory types = abi.decode(encoded, (LibAppStorage.OracleDataType[]));
        for (uint256 i = 0; i < types.length; i++) {
            if (types[i] == dataType) return true;
        }
        return false;
    }

    function _processSanctionsUpdate(
        LibAppStorage.AppStorage storage s,
        bytes32 dataKey,
        bytes memory dataValue
    ) internal {
        bytes32 newRoot = abi.decode(dataValue, (bytes32));
        LibAppStorage.SanctionsList listType = LibAppStorage.SanctionsList(uint256(dataKey));
        s.sanctionsListRoots[listType] = newRoot;
        s.lastSanctionsUpdate[listType] = block.timestamp;
    }

    function _verifySignature(
        bytes32 messageHash,
        bytes memory signature,
        address expectedSigner
    ) internal pure returns (bool) {
        if (signature.length != 65) return false;

        bytes32 ethSignedMessageHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", messageHash)
        );

        bytes32 r;
        bytes32 sig_s;
        uint8 v;
        assembly {
            r     := mload(add(signature, 32))
            sig_s := mload(add(signature, 64))
            v     := byte(0, mload(add(signature, 96)))
        }
        if (v < 27) v += 27;

        address signer = ecrecover(ethSignedMessageHash, v, r, sig_s);
        return signer != address(0) && signer == expectedSigner;
    }
}
