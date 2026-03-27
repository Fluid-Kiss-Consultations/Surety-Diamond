// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {LibAppStorage} from "./LibAppStorage.sol";

/// @title LibRoles
/// @notice Role-based access control for Surety compliance system
/// @dev Implements hierarchical roles with admin capabilities
library LibRoles {

    // ============ Role Definitions ============

    // Core administrative roles
    bytes32 internal constant DEFAULT_ADMIN_ROLE      = 0x00;
    bytes32 internal constant COMPLIANCE_OFFICER_ROLE = keccak256("COMPLIANCE_OFFICER_ROLE");
    bytes32 internal constant KYC_VERIFIER_ROLE       = keccak256("KYC_VERIFIER_ROLE");
    bytes32 internal constant AML_ANALYST_ROLE        = keccak256("AML_ANALYST_ROLE");
    bytes32 internal constant SANCTIONS_MANAGER_ROLE  = keccak256("SANCTIONS_MANAGER_ROLE");

    // Operational roles
    bytes32 internal constant ORACLE_ROLE  = keccak256("ORACLE_ROLE");
    bytes32 internal constant FACTOR_ROLE  = keccak256("FACTOR_ROLE");
    bytes32 internal constant SELLER_ROLE  = keccak256("SELLER_ROLE");
    bytes32 internal constant BUYER_ROLE   = keccak256("BUYER_ROLE");

    // Emergency roles
    bytes32 internal constant EMERGENCY_ADMIN_ROLE = keccak256("EMERGENCY_ADMIN_ROLE");
    bytes32 internal constant PAUSER_ROLE          = keccak256("PAUSER_ROLE");

    // ============ Events ============

    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    // ============ Errors ============

    error AccessControlUnauthorized(address account, bytes32 role);
    error AccessControlBadConfirmation();

    // ============ Functions ============

    /// @notice Check if account has role
    function hasRole(address account, bytes32 role) internal view returns (bool) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        return s.roleMembers[role][account];
    }

    /// @notice Grant role to account
    function grantRole(bytes32 role, address account) internal {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        if (!s.roleMembers[role][account]) {
            s.roleMembers[role][account] = true;
            emit RoleGranted(role, account, msg.sender);
        }
    }

    /// @notice Revoke role from account
    function revokeRole(bytes32 role, address account) internal {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        if (s.roleMembers[role][account]) {
            s.roleMembers[role][account] = false;
            emit RoleRevoked(role, account, msg.sender);
        }
    }

    /// @notice Check role and revert if not granted
    function checkRole(bytes32 role) internal view {
        checkRole(role, msg.sender);
    }

    /// @notice Check role for specific account and revert if not granted
    function checkRole(bytes32 role, address account) internal view {
        if (!hasRole(account, role)) {
            revert AccessControlUnauthorized(account, role);
        }
    }

    /// @notice Get the admin role for a given role
    function getRoleAdmin(bytes32 role) internal view returns (bytes32 adminRole) {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        adminRole = s.roleAdmins[role];
        if (adminRole == bytes32(0)) {
            return DEFAULT_ADMIN_ROLE;
        }
        return adminRole;
    }

    /// @notice Set admin role for a given role
    function setRoleAdmin(bytes32 role, bytes32 adminRole) internal {
        LibAppStorage.AppStorage storage s = LibAppStorage.appStorage();
        bytes32 previousAdminRole = getRoleAdmin(role);
        s.roleAdmins[role] = adminRole;
        emit RoleAdminChanged(role, previousAdminRole, adminRole);
    }
}
