// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {SuretyDiamond} from "../../src/diamond/SuretyDiamond.sol";
import {DiamondInit} from "../../src/diamond/DiamondInit.sol";
import {DiamondCutFacet} from "../../src/facets/DiamondCutFacet.sol";
import {DiamondLoupeFacet} from "../../src/facets/DiamondLoupeFacet.sol";
import {KYCFacet} from "../../src/facets/KYCFacet.sol";
import {AMLFacet} from "../../src/facets/AMLFacet.sol";
import {SanctionsFacet} from "../../src/facets/SanctionsFacet.sol";
import {InvoiceRegistryFacet} from "../../src/facets/InvoiceRegistryFacet.sol";
import {FATCACRSFacet} from "../../src/facets/FATCACRSFacet.sol";
import {JurisdictionFacet} from "../../src/facets/JurisdictionFacet.sol";
import {AuditFacet} from "../../src/facets/AuditFacet.sol";
import {EmergencyFacet} from "../../src/facets/EmergencyFacet.sol";
import {OracleFacet} from "../../src/facets/OracleFacet.sol";

import {IDiamondCut} from "../../src/interfaces/IDiamondCut.sol";
import {IKYCFacet} from "../../src/interfaces/IKYCFacet.sol";
import {IAMLFacet} from "../../src/interfaces/IAMLFacet.sol";
import {ISanctionsFacet} from "../../src/interfaces/ISanctionsFacet.sol";
import {IInvoiceRegistryFacet} from "../../src/interfaces/IInvoiceRegistryFacet.sol";
import {IFATCACRSFacet} from "../../src/interfaces/IFATCACRSFacet.sol";
import {IJurisdictionFacet} from "../../src/interfaces/IJurisdictionFacet.sol";
import {IAuditFacet} from "../../src/interfaces/IAuditFacet.sol";
import {IOracleFacet} from "../../src/interfaces/IOracleFacet.sol";
import {IDiamondLoupe} from "../../src/interfaces/IDiamondLoupe.sol";
import {IERC165} from "../../src/interfaces/IERC165.sol";
import {LibAppStorage} from "../../src/libraries/LibAppStorage.sol";
import {LibRoles} from "../../src/libraries/LibRoles.sol";

/// @notice Shared base for all Surety diamond tests.
///         Deploys the full diamond with all 11 facets and sets up test roles.
abstract contract DiamondTestHelper is Test {

    // ============================================================
    // Test Accounts
    // ============================================================

    address internal owner   = makeAddr("owner");
    address internal treasury = makeAddr("treasury");
    address internal verifier = makeAddr("verifier");
    address internal analyst  = makeAddr("analyst");
    address internal officer  = makeAddr("complianceOfficer");
    address internal seller   = makeAddr("seller");
    address internal buyer    = makeAddr("buyer");
    address internal factor   = makeAddr("factor");
    address internal sanctionsMgr = makeAddr("sanctionsMgr");
    address internal auditor  = makeAddr("auditor");
    address internal oracle   = makeAddr("oracle");
    address internal pauser   = makeAddr("pauser");

    // ============================================================
    // Diamond proxy address (cast to each interface as needed)
    // ============================================================

    address internal diamond;

    // ============================================================
    // Setup
    // ============================================================

    function setUp() public virtual {
        diamond = _deployFullDiamond();
        _grantTestRoles();
    }

    // ============================================================
    // Interface accessors
    // ============================================================

    function kyc()          internal view returns (IKYCFacet)             { return IKYCFacet(diamond); }
    function aml()          internal view returns (IAMLFacet)             { return IAMLFacet(diamond); }
    function sanctions()    internal view returns (ISanctionsFacet)       { return ISanctionsFacet(diamond); }
    function invoice()      internal view returns (IInvoiceRegistryFacet) { return IInvoiceRegistryFacet(diamond); }
    function fatca()        internal view returns (IFATCACRSFacet)        { return IFATCACRSFacet(diamond); }
    function jurisdiction() internal view returns (IJurisdictionFacet)    { return IJurisdictionFacet(diamond); }
    function audit()        internal view returns (IAuditFacet)           { return IAuditFacet(diamond); }
    function loupe()        internal view returns (IDiamondLoupe)         { return IDiamondLoupe(diamond); }

    // ============================================================
    // Internal: full diamond deployment
    // ============================================================

    function _deployFullDiamond() internal returns (address diamondAddr) {
        // Deploy facets
        DiamondCutFacet       cutFacet          = new DiamondCutFacet();
        DiamondLoupeFacet     loupeFacet        = new DiamondLoupeFacet();
        KYCFacet              kycFacet          = new KYCFacet();
        AMLFacet              amlFacet          = new AMLFacet();
        SanctionsFacet        sanctionsFacet    = new SanctionsFacet();
        InvoiceRegistryFacet  invoiceFacet      = new InvoiceRegistryFacet();
        FATCACRSFacet         fatcaFacet        = new FATCACRSFacet();
        JurisdictionFacet     jurisdictionFacet = new JurisdictionFacet();
        AuditFacet            auditFacet        = new AuditFacet();
        EmergencyFacet        emergencyFacet    = new EmergencyFacet();
        OracleFacet           oracleFacet       = new OracleFacet();
        DiamondInit           diamondInit       = new DiamondInit();

        // Build FacetCut array
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](11);
        cuts[0]  = _cut(address(cutFacet),          _cutSelectors());
        cuts[1]  = _cut(address(loupeFacet),         _loupeSelectors());
        cuts[2]  = _cut(address(kycFacet),           _kycSelectors());
        cuts[3]  = _cut(address(amlFacet),           _amlSelectors());
        cuts[4]  = _cut(address(sanctionsFacet),     _sanctionsSelectors());
        cuts[5]  = _cut(address(invoiceFacet),       _invoiceSelectors());
        cuts[6]  = _cut(address(fatcaFacet),         _fatcaSelectors());
        cuts[7]  = _cut(address(jurisdictionFacet),  _jurisdictionSelectors());
        cuts[8]  = _cut(address(auditFacet),         _auditSelectors());
        cuts[9]  = _cut(address(emergencyFacet),     _emergencySelectors());
        cuts[10] = _cut(address(oracleFacet),        _oracleSelectors());

        bytes memory initData = abi.encodeCall(
            DiamondInit.init,
            (DiamondInit.InitArgs({
                owner:              owner,
                treasury:           treasury,
                timelockDuration:   48 hours,
                reportingThreshold: 10_000 * 1e18
            }))
        );

        // Pass cuts directly to constructor — bootstraps the routing table without going through fallback
        SuretyDiamond d = new SuretyDiamond(owner, 48 hours, cuts, address(diamondInit), initData);
        diamondAddr = address(d);
    }

    // ============================================================
    // Internal: grant roles to test accounts
    // ============================================================

    function _grantTestRoles() internal {
        // All role grants go through the diamond's AppStorage — use vm.store would be
        // complex, so we rely on the owner having DEFAULT_ADMIN_ROLE and calling via
        // a helper that directly writes roleMembers via vm.store slot calculation.
        // For simplicity in tests we use vm.prank and a raw call to grant roles via
        // LibRoles internals are not externally callable, so we expose a small cheat:

        // Compute AppStorage slot: keccak256("surety.compliance.diamond.storage")
        bytes32 storageSlot = keccak256("surety.compliance.diamond.storage");

        // roleMembers is at position 17 in AppStorage (0-indexed)
        // The exact slot calculation for nested mappings:
        //   mapping(bytes32 => mapping(address => bool)) roleMembers;
        //   slot = keccak256(abi.encode(address, keccak256(abi.encode(role, baseSlot))))

        _grantRole(LibRoles.KYC_VERIFIER_ROLE,       verifier);
        _grantRole(LibRoles.AML_ANALYST_ROLE,         analyst);
        _grantRole(LibRoles.COMPLIANCE_OFFICER_ROLE,  officer);
        _grantRole(LibRoles.SELLER_ROLE,              seller);
        _grantRole(LibRoles.BUYER_ROLE,               buyer);
        _grantRole(LibRoles.FACTOR_ROLE,              factor);
        _grantRole(LibRoles.SANCTIONS_MANAGER_ROLE,   sanctionsMgr);
        _grantRole(LibRoles.AUDITOR_ROLE,             auditor);
        _grantRole(LibRoles.ORACLE_ROLE,              oracle);
        _grantRole(LibRoles.PAUSER_ROLE,              pauser);
        _grantRole(keccak256("TAX_OFFICER_ROLE"),     officer);
    }

    /// @dev Writes to roleMembers[role][account] = true via vm.store
    function _grantRole(bytes32 role, address account) internal {
        // AppStorage base slot: keccak256("surety.compliance.diamond.storage")
        bytes32 base = keccak256("surety.compliance.diamond.storage");
        // roleMembers is field index 32 in AppStorage (all 32 preceding fields are mappings, each 1 slot)
        // slot of outer mapping entry for roleMembers[role]:
        //   keccak256(abi.encode(role, uint256(base) + 32))
        bytes32 outerSlot = keccak256(abi.encode(role, bytes32(uint256(base) + 32)));
        // slot of inner bool: keccak256(abi.encode(account, outerSlot))
        bytes32 innerSlot = keccak256(abi.encode(account, outerSlot));
        vm.store(diamond, innerSlot, bytes32(uint256(1)));
    }

    // ============================================================
    // Selector arrays (mirrors Deploy.s.sol)
    // ============================================================

    function _cut(address facetAddr, bytes4[] memory sel)
        internal pure returns (IDiamondCut.FacetCut memory)
    {
        return IDiamondCut.FacetCut({
            facetAddress:      facetAddr,
            action:            IDiamondCut.FacetCutAction.Add,
            functionSelectors: sel
        });
    }

    function _cutSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](3);
        s[0] = DiamondCutFacet.scheduleDiamondCut.selector;
        s[1] = DiamondCutFacet.executeDiamondCut.selector;
        s[2] = IDiamondCut.diamondCut.selector;
    }

    function _loupeSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](5);
        s[0] = IDiamondLoupe.facets.selector;
        s[1] = IDiamondLoupe.facetFunctionSelectors.selector;
        s[2] = IDiamondLoupe.facetAddresses.selector;
        s[3] = IDiamondLoupe.facetAddress.selector;
        s[4] = IERC165.supportsInterface.selector;
    }

    function _kycSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](7);
        s[0] = IKYCFacet.initiateKYC.selector;
        s[1] = IKYCFacet.approveKYC.selector;
        s[2] = IKYCFacet.rejectKYC.selector;
        s[3] = IKYCFacet.updateKYCStatus.selector;
        s[4] = IKYCFacet.isKYCCompliant.selector;
        s[5] = IKYCFacet.getKYCRecord.selector;
        s[6] = IKYCFacet.verifyDocument.selector;
    }

    function _amlSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](6);
        s[0] = IAMLFacet.assessTransaction.selector;
        s[1] = IAMLFacet.setEntityRiskScore.selector;
        s[2] = IAMLFacet.flagSuspiciousActivity.selector;
        s[3] = IAMLFacet.fileSAR.selector;
        s[4] = IAMLFacet.getEntityRiskProfile.selector;
        s[5] = IAMLFacet.isHighRisk.selector;
    }

    function _sanctionsSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](9);
        s[0] = ISanctionsFacet.screenEntity.selector;
        s[1] = ISanctionsFacet.verifyAgainstList.selector;
        s[2] = ISanctionsFacet.updateSanctionsList.selector;
        s[3] = ISanctionsFacet.addToSanctionsList.selector;
        s[4] = ISanctionsFacet.removeFromSanctionsList.selector;
        s[5] = ISanctionsFacet.clearFalsePositive.selector;
        s[6] = ISanctionsFacet.isSanctioned.selector;
        s[7] = ISanctionsFacet.getSanctionRecord.selector;
        s[8] = ISanctionsFacet.getSanctionsListRoot.selector;
    }

    function _invoiceSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](9);
        s[0] = IInvoiceRegistryFacet.registerInvoice.selector;
        s[1] = IInvoiceRegistryFacet.verifyInvoice.selector;
        s[2] = IInvoiceRegistryFacet.canFactor.selector;
        s[3] = IInvoiceRegistryFacet.createFactoringAgreement.selector;
        s[4] = IInvoiceRegistryFacet.recordPayment.selector;
        s[5] = IInvoiceRegistryFacet.raiseDispute.selector;
        s[6] = IInvoiceRegistryFacet.getInvoice.selector;
        s[7] = IInvoiceRegistryFacet.getFactoringStatus.selector;
        s[8] = IInvoiceRegistryFacet.isInvoiceHashUsed.selector;
    }

    function _fatcaSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](8);
        s[0] = IFATCACRSFacet.setTaxClassification.selector;
        s[1] = IFATCACRSFacet.recordTaxForm.selector;
        s[2] = IFATCACRSFacet.assessReportingRequirement.selector;
        s[3] = IFATCACRSFacet.createReportingObligation.selector;
        s[4] = IFATCACRSFacet.markAsReported.selector;
        s[5] = IFATCACRSFacet.getTaxClassification.selector;
        s[6] = IFATCACRSFacet.checkWithholding.selector;
        s[7] = IFATCACRSFacet.getPendingObligations.selector;
    }

    function _jurisdictionSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](9);
        s[0] = IJurisdictionFacet.configureJurisdiction.selector;
        s[1] = IJurisdictionFacet.assignEntityJurisdiction.selector;
        s[2] = IJurisdictionFacet.assessCrossBorder.selector;
        s[3] = IJurisdictionFacet.blockJurisdictionOperation.selector;
        s[4] = IJurisdictionFacet.blockCounterpartyPair.selector;
        s[5] = IJurisdictionFacet.getJurisdiction.selector;
        s[6] = IJurisdictionFacet.getEntityJurisdiction.selector;
        s[7] = IJurisdictionFacet.isTransactionPermitted.selector;
        s[8] = IJurisdictionFacet.getMinimumKYCLevel.selector;
    }

    function _auditSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](9);
        s[0] = IAuditFacet.logAudit.selector;
        s[1] = IAuditFacet.verifyAuditChain.selector;
        s[2] = IAuditFacet.getAuditEntry.selector;
        s[3] = IAuditFacet.getEntityAuditTrail.selector;
        s[4] = IAuditFacet.getLatestAuditHash.selector;
        s[5] = IAuditFacet.getAuditStats.selector;
        s[6] = IAuditFacet.logKYCEvent.selector;
        s[7] = IAuditFacet.logAMLEvent.selector;
        s[8] = IAuditFacet.logSanctionsEvent.selector;
    }

    function _emergencySelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](4);
        s[0] = EmergencyFacet.emergencyPause.selector;
        s[1] = EmergencyFacet.emergencyUnpause.selector;
        s[2] = EmergencyFacet.emergencyWithdraw.selector;
        s[3] = EmergencyFacet.scheduleEmergencyUpgrade.selector;
    }

    function _oracleSelectors() internal pure returns (bytes4[] memory s) {
        s = new bytes4[](8);
        s[0] = IOracleFacet.registerOracle.selector;
        s[1] = IOracleFacet.revokeOracle.selector;
        s[2] = IOracleFacet.submitOracleUpdate.selector;
        s[3] = IOracleFacet.requestOracleData.selector;
        s[4] = IOracleFacet.isAuthorizedOracle.selector;
        s[5] = IOracleFacet.getOracleAuthorizations.selector;
        s[6] = IOracleFacet.getPendingRequests.selector;
        s[7] = IOracleFacet.getOracleData.selector;
    }

    // ============================================================
    // Helpers
    // ============================================================

    /// @dev Sign a bytes32 hash with a private key derived from a name
    function _signAs(string memory name, bytes32 hash) internal returns (bytes memory sig) {
        (address addr, uint256 pk) = makeAddrAndKey(name);
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(pk, keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)));
        sig = abi.encodePacked(r, s_, v);
        return sig;
    }

    /// @dev Build a minimal KYC record for use in tests
    function _buildInvoice(
        address _seller,
        address _buyer,
        uint256 amount
    ) internal view returns (LibAppStorage.InvoiceRecord memory) {
        return LibAppStorage.InvoiceRecord({
            invoiceHash:      bytes32(0),
            seller:           _seller,
            buyer:            _buyer,
            amount:           amount,
            currency:         keccak256("USD"),
            issueDate:        block.timestamp,
            dueDate:          block.timestamp + 30 days,
            status:           LibAppStorage.InvoiceStatus.REGISTERED,
            purchaseOrderRef: keccak256("PO-001"),
            registrationTime: 0,
            registeredBy:     address(0)
        });
    }
}
