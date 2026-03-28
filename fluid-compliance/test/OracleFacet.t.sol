// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondTestHelper} from "./helpers/DiamondTestHelper.sol";
import {LibAppStorage} from "../src/libraries/LibAppStorage.sol";
import {LibRoles} from "../src/libraries/LibRoles.sol";

contract OracleFacetTest is DiamondTestHelper {

    address internal oracleAddr;
    uint256 internal oraclePk;

    function setUp() public override {
        super.setUp();
        (oracleAddr, oraclePk) = makeAddrAndKey("oracle");
        oracle = oracleAddr;
    }

    function test_registerOracle_setsActive() public {
        LibAppStorage.OracleDataType[] memory types = _allTypes();
        vm.prank(owner);
        IOracleFacetTest(diamond).registerOracle(oracleAddr, types);

        assertTrue(IOracleFacetTest(diamond).isAuthorizedOracle(oracleAddr));
    }

    function test_registerOracle_revertsIfAlreadyRegistered() public {
        _registerOracle();
        vm.prank(owner);
        vm.expectRevert();
        IOracleFacetTest(diamond).registerOracle(oracleAddr, _allTypes());
    }

    function test_registerOracle_revertsIfNotAdmin() public {
        vm.prank(seller);
        vm.expectRevert();
        IOracleFacetTest(diamond).registerOracle(oracleAddr, _allTypes());
    }

    function test_registerOracle_revertsWhenLimitReached() public {
        LibAppStorage.OracleDataType[] memory sanctionsOnly = new LibAppStorage.OracleDataType[](1);
        sanctionsOnly[0] = LibAppStorage.OracleDataType.SANCTIONS_LIST;

        for (uint256 i = 0; i < 5; i++) {
            (address addr,) = makeAddrAndKey(string(abi.encodePacked("oracle-limit-", i)));
            vm.prank(owner);
            IOracleFacetTest(diamond).registerOracle(addr, sanctionsOnly);
        }

        (address sixth,) = makeAddrAndKey("oracle-limit-sixth");
        vm.prank(owner);
        vm.expectRevert();
        IOracleFacetTest(diamond).registerOracle(sixth, sanctionsOnly);
    }

    function test_revokeOracle_clearsActive() public {
        _registerOracle();
        vm.prank(owner);
        IOracleFacetTest(diamond).revokeOracle(oracleAddr);
        assertFalse(IOracleFacetTest(diamond).isAuthorizedOracle(oracleAddr));
    }

    function test_revokeOracle_revertsIfNotRegistered() public {
        vm.prank(owner);
        vm.expectRevert();
        IOracleFacetTest(diamond).revokeOracle(oracleAddr);
    }

    function test_getOracleAuthorizations_returnsTypes() public {
        _registerOracle();
        LibAppStorage.OracleDataType[] memory types = IOracleFacetTest(diamond).getOracleAuthorizations(oracleAddr);
        assertEq(types.length, 6);
    }

    function test_submitOracleUpdate_sanctionsListUpdate() public {
        _registerOracle();

        bytes32 newRoot = keccak256("new-ofac-root");
        bytes memory data = abi.encode(newRoot);
        bytes32 dataKey = bytes32(uint256(LibAppStorage.SanctionsList.OFAC_SDN));

        uint256 nonce = 0;
        bytes32 msgHash = keccak256(abi.encodePacked(
            LibAppStorage.OracleDataType.SANCTIONS_LIST, dataKey, data, nonce, block.timestamp
        ));
        bytes memory sig = _signOracle(msgHash);

        _grantRole(LibRoles.ORACLE_ROLE, oracleAddr);

        vm.prank(oracleAddr);
        IOracleFacetTest(diamond).submitOracleUpdate(
            LibAppStorage.OracleDataType.SANCTIONS_LIST, dataKey, data, sig
        );

        (bytes32 root,) = ISanctionsFacetMin(diamond).getSanctionsListRoot(LibAppStorage.SanctionsList.OFAC_SDN);
        assertEq(root, newRoot);
    }

    function test_submitOracleUpdate_revertsWithInvalidSig() public {
        _registerOracle();
        _grantRole(LibRoles.ORACLE_ROLE, oracleAddr);

        bytes memory data = abi.encode(keccak256("root"));
        bytes32 dataKey = bytes32(uint256(0));
        bytes memory badSig = new bytes(65);

        vm.prank(oracleAddr);
        vm.expectRevert();
        IOracleFacetTest(diamond).submitOracleUpdate(
            LibAppStorage.OracleDataType.SANCTIONS_LIST, dataKey, data, badSig
        );
    }

    function test_requestOracleData_returnsRequestId() public {
        vm.prank(seller);
        bytes32 reqId = IOracleFacetTest(diamond).requestOracleData(
            LibAppStorage.OracleDataType.RISK_SCORE, keccak256("entity-key")
        );
        assertNotEq(reqId, bytes32(0));
    }

    function _registerOracle() internal {
        vm.prank(owner);
        IOracleFacetTest(diamond).registerOracle(oracleAddr, _allTypes());
    }

    function _allTypes() internal pure returns (LibAppStorage.OracleDataType[] memory types) {
        types = new LibAppStorage.OracleDataType[](6);
        types[0] = LibAppStorage.OracleDataType.SANCTIONS_LIST;
        types[1] = LibAppStorage.OracleDataType.PEP_LIST;
        types[2] = LibAppStorage.OracleDataType.EXCHANGE_RATE;
        types[3] = LibAppStorage.OracleDataType.RISK_SCORE;
        types[4] = LibAppStorage.OracleDataType.KYC_VERIFICATION;
        types[5] = LibAppStorage.OracleDataType.CREDIT_SCORE;
    }

    function _signOracle(bytes32 msgHash) internal view returns (bytes memory sig) {
        bytes32 prefixed = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(oraclePk, prefixed);
        sig = abi.encodePacked(r, s_, v);
    }
}

interface IOracleFacetTest {
    function registerOracle(address oracle, LibAppStorage.OracleDataType[] calldata authorizedTypes) external;
    function revokeOracle(address oracle) external;
    function submitOracleUpdate(LibAppStorage.OracleDataType, bytes32, bytes calldata, bytes calldata) external;
    function requestOracleData(LibAppStorage.OracleDataType, bytes32) external returns (bytes32);
    function isAuthorizedOracle(address oracle) external view returns (bool);
    function getOracleAuthorizations(address oracle) external view returns (LibAppStorage.OracleDataType[] memory);
}

interface ISanctionsFacetMin {
    function getSanctionsListRoot(LibAppStorage.SanctionsList listType) external view returns (bytes32, uint256);
}
