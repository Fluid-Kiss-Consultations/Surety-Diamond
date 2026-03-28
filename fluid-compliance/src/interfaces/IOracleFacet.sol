// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "../libraries/LibAppStorage.sol";

/// @title IOracleFacet
/// @notice Interface for secure integration with external compliance data providers
interface IOracleFacet {

    event OracleRegistered(
        address indexed oracle,
        LibAppStorage.OracleDataType[] authorizedTypes,
        uint256 timestamp
    );
    event OracleDataUpdated(
        bytes32 indexed updateId,
        LibAppStorage.OracleDataType indexed dataType,
        bytes32 indexed dataKey,
        address oracle,
        uint256 timestamp
    );

    /// @notice Register a new oracle with authorized data types
    /// @param oracle Address of the oracle to register
    /// @param authorizedTypes Array of data types the oracle is permitted to submit
    function registerOracle(
        address oracle,
        LibAppStorage.OracleDataType[] calldata authorizedTypes
    ) external;

    /// @notice Revoke an oracle's authorization
    /// @param oracle Address of the oracle to revoke
    function revokeOracle(address oracle) external;

    /// @notice Submit an oracle data update with ECDSA signature verification
    /// @param dataType The type of data being submitted
    /// @param dataKey The key identifying the specific data entry
    /// @param dataValue The data payload
    /// @param signature ECDSA signature over the data for verification
    function submitOracleUpdate(
        LibAppStorage.OracleDataType dataType,
        bytes32 dataKey,
        bytes calldata dataValue,
        bytes calldata signature
    ) external;

    /// @notice Request oracle data for a specific type and key
    /// @param dataType The type of data requested
    /// @param dataKey The key identifying the specific data entry
    /// @return requestId Unique identifier for the data request
    function requestOracleData(
        LibAppStorage.OracleDataType dataType,
        bytes32 dataKey
    ) external returns (bytes32 requestId);

    /// @notice Check whether an address is a registered and authorized oracle
    /// @param oracle Address to check
    /// @return True if the oracle is currently authorized
    function isAuthorizedOracle(address oracle) external view returns (bool);

    /// @notice Get the list of data types an oracle is authorized to submit
    /// @param oracle Address of the oracle to query
    /// @return types Array of authorized data types
    function getOracleAuthorizations(
        address oracle
    ) external view returns (LibAppStorage.OracleDataType[] memory types);

    /// @notice Get pending oracle data requests for a given data type
    /// @param dataType The data type to query pending requests for
    /// @return requests Array of pending oracle requests
    function getPendingRequests(
        LibAppStorage.OracleDataType dataType
    ) external view returns (LibAppStorage.OracleRequest[] memory requests);

    /// @notice Retrieve cached oracle data, reverting if the data has expired
    /// @param dataType The type of oracle data to retrieve
    /// @param dataKey The key identifying the specific data entry
    /// @return data The cached bytes value
    /// @return timestamp The block.timestamp at which the data was last updated
    function getOracleData(
        LibAppStorage.OracleDataType dataType,
        bytes32 dataKey
    ) external view returns (bytes memory data, uint256 timestamp);
}
