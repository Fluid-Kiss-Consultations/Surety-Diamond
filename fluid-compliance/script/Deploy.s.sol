// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";

import {SuretyDiamond} from "../src/diamond/SuretyDiamond.sol";
import {DiamondInit} from "../src/diamond/DiamondInit.sol";
import {DiamondCutFacet} from "../src/facets/DiamondCutFacet.sol";
import {DiamondLoupeFacet} from "../src/facets/DiamondLoupeFacet.sol";
import {KYCFacet} from "../src/facets/KYCFacet.sol";
import {AMLFacet} from "../src/facets/AMLFacet.sol";
import {SanctionsFacet} from "../src/facets/SanctionsFacet.sol";
import {InvoiceRegistryFacet} from "../src/facets/InvoiceRegistryFacet.sol";
import {FATCACRSFacet} from "../src/facets/FATCACRSFacet.sol";
import {JurisdictionFacet} from "../src/facets/JurisdictionFacet.sol";
import {AuditFacet} from "../src/facets/AuditFacet.sol";
import {EmergencyFacet} from "../src/facets/EmergencyFacet.sol";
import {OracleFacet} from "../src/facets/OracleFacet.sol";

import {IDiamondCut} from "../src/interfaces/IDiamondCut.sol";
import {IKYCFacet} from "../src/interfaces/IKYCFacet.sol";
import {IAMLFacet} from "../src/interfaces/IAMLFacet.sol";
import {ISanctionsFacet} from "../src/interfaces/ISanctionsFacet.sol";
import {IInvoiceRegistryFacet} from "../src/interfaces/IInvoiceRegistryFacet.sol";
import {IFATCACRSFacet} from "../src/interfaces/IFATCACRSFacet.sol";
import {IJurisdictionFacet} from "../src/interfaces/IJurisdictionFacet.sol";
import {IAuditFacet} from "../src/interfaces/IAuditFacet.sol";
import {IOracleFacet} from "../src/interfaces/IOracleFacet.sol";
import {IDiamondLoupe} from "../src/interfaces/IDiamondLoupe.sol";
import {IERC165} from "../src/interfaces/IERC165.sol";
import {LibAppStorage} from "../src/libraries/LibAppStorage.sol";

/// @title DeploySurety
/// @notice Deploys the full Surety compliance diamond with all 10 facets
/// @dev Run with:
///   forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
contract DeploySurety is Script {

    // ============================================================
    // Configuration
    // ============================================================

    uint256 constant TIMELOCK_DURATION = 48 hours;
    uint256 constant REPORTING_THRESHOLD = 10_000 * 1e18; // $10,000

    // ============================================================
    // Deployment state
    // ============================================================

    SuretyDiamond public diamond;
    DiamondInit   public diamondInit;

    DiamondCutFacet       public cutFacet;
    DiamondLoupeFacet     public loupeFacet;
    KYCFacet              public kycFacet;
    AMLFacet              public amlFacet;
    SanctionsFacet        public sanctionsFacet;
    InvoiceRegistryFacet  public invoiceFacet;
    FATCACRSFacet         public fatcaFacet;
    JurisdictionFacet     public jurisdictionFacet;
    AuditFacet            public auditFacet;
    EmergencyFacet        public emergencyFacet;
    OracleFacet           public oracleFacet;

    // ============================================================
    // Entry point
    // ============================================================

    function run() external {
        address owner   = vm.envAddress("OWNER_ADDRESS");
        address treasury = vm.envOr("TREASURY_ADDRESS", owner);
        uint256 pk      = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(pk);

        _deployFacets();
        _deployDiamond(owner);
        _cutAllFacets(owner, treasury);

        vm.stopBroadcast();

        _logAddresses();
    }

    // ============================================================
    // Internal: deploy each facet contract
    // ============================================================

    function _deployFacets() internal {
        cutFacet          = new DiamondCutFacet();
        loupeFacet        = new DiamondLoupeFacet();
        kycFacet          = new KYCFacet();
        amlFacet          = new AMLFacet();
        sanctionsFacet    = new SanctionsFacet();
        invoiceFacet      = new InvoiceRegistryFacet();
        fatcaFacet        = new FATCACRSFacet();
        jurisdictionFacet = new JurisdictionFacet();
        auditFacet        = new AuditFacet();
        emergencyFacet    = new EmergencyFacet();
        oracleFacet       = new OracleFacet();
    }

    // ============================================================
    // Internal: deploy diamond proxy
    // ============================================================

    function _deployDiamond(address owner) internal {
        diamondInit = new DiamondInit();
    }

    // ============================================================
    // Internal: build FacetCut array and execute initial diamond cut
    // ============================================================

    function _cutAllFacets(address owner, address treasury) internal {
        IDiamondCut.FacetCut[] memory cuts = new IDiamondCut.FacetCut[](11);

        cuts[0]  = _makeCut(address(cutFacet),          _cutSelectors());
        cuts[1]  = _makeCut(address(loupeFacet),         _loupeSelectors());
        cuts[2]  = _makeCut(address(kycFacet),           _kycSelectors());
        cuts[3]  = _makeCut(address(amlFacet),           _amlSelectors());
        cuts[4]  = _makeCut(address(sanctionsFacet),     _sanctionsSelectors());
        cuts[5]  = _makeCut(address(invoiceFacet),       _invoiceSelectors());
        cuts[6]  = _makeCut(address(fatcaFacet),         _fatcaSelectors());
        cuts[7]  = _makeCut(address(jurisdictionFacet),  _jurisdictionSelectors());
        cuts[8]  = _makeCut(address(auditFacet),         _auditSelectors());
        cuts[9]  = _makeCut(address(emergencyFacet),     _emergencySelectors());
        cuts[10] = _makeCut(address(oracleFacet),        _oracleSelectors());

        bytes memory initData = abi.encodeCall(
            DiamondInit.init,
            (DiamondInit.InitArgs({
                owner:              owner,
                treasury:           treasury,
                timelockDuration:   TIMELOCK_DURATION,
                reportingThreshold: REPORTING_THRESHOLD
            }))
        );

        // Deploy diamond with all cuts in constructor — bootstraps routing table directly
        diamond = new SuretyDiamond(owner, TIMELOCK_DURATION, cuts, address(diamondInit), initData);
    }

    // ============================================================
    // Selector helpers
    // ============================================================

    function _makeCut(
        address facetAddr,
        bytes4[] memory selectors
    ) internal pure returns (IDiamondCut.FacetCut memory) {
        return IDiamondCut.FacetCut({
            facetAddress:      facetAddr,
            action:            IDiamondCut.FacetCutAction.Add,
            functionSelectors: selectors
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
    // Logging
    // ============================================================

    function _logAddresses() internal view {
        console.log("=== Surety Diamond Deployment ===");
        console.log("Diamond:          ", address(diamond));
        console.log("DiamondInit:      ", address(diamondInit));
        console.log("--- Facets ---");
        console.log("DiamondCut:       ", address(cutFacet));
        console.log("DiamondLoupe:     ", address(loupeFacet));
        console.log("KYCFacet:         ", address(kycFacet));
        console.log("AMLFacet:         ", address(amlFacet));
        console.log("SanctionsFacet:   ", address(sanctionsFacet));
        console.log("InvoiceFacet:     ", address(invoiceFacet));
        console.log("FATCACRSFacet:    ", address(fatcaFacet));
        console.log("JurisdictionFacet:", address(jurisdictionFacet));
        console.log("AuditFacet:       ", address(auditFacet));
        console.log("EmergencyFacet:   ", address(emergencyFacet));
        console.log("OracleFacet:      ", address(oracleFacet));
    }
}
