// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DiamondTestHelper} from "./helpers/DiamondTestHelper.sol";
import {IDiamondLoupe} from "../src/interfaces/IDiamondLoupe.sol";
import {IKYCFacet} from "../src/interfaces/IKYCFacet.sol";
import {IAMLFacet} from "../src/interfaces/IAMLFacet.sol";
import {ISanctionsFacet} from "../src/interfaces/ISanctionsFacet.sol";
import {IInvoiceRegistryFacet} from "../src/interfaces/IInvoiceRegistryFacet.sol";
import {IFATCACRSFacet} from "../src/interfaces/IFATCACRSFacet.sol";
import {IJurisdictionFacet} from "../src/interfaces/IJurisdictionFacet.sol";
import {IAuditFacet} from "../src/interfaces/IAuditFacet.sol";
import {IOracleFacet} from "../src/interfaces/IOracleFacet.sol";
import {IDiamondCut} from "../src/interfaces/IDiamondCut.sol";
import {IERC165} from "../src/interfaces/IERC165.sol";
import {DiamondCutFacet} from "../src/facets/DiamondCutFacet.sol";
import {EmergencyFacet} from "../src/facets/EmergencyFacet.sol";
import {IUpgradeManagerFacet} from "../src/interfaces/IUpgradeManagerFacet.sol";
import {ISecurityGuardFacet} from "../src/interfaces/ISecurityGuardFacet.sol";

/// @notice Verifies that every interface selector is routed in the deployed diamond.
contract DeploySelectorsTest is DiamondTestHelper {

    function test_allSelectorsRouted() public view {
        IDiamondLoupe l = loupe();

        // DiamondCut
        assertNotEq(l.facetAddress(DiamondCutFacet.scheduleDiamondCut.selector), address(0));
        assertNotEq(l.facetAddress(DiamondCutFacet.executeDiamondCut.selector), address(0));
        assertNotEq(l.facetAddress(IDiamondCut.diamondCut.selector), address(0));

        // DiamondLoupe + ERC165
        assertNotEq(l.facetAddress(IDiamondLoupe.facets.selector), address(0));
        assertNotEq(l.facetAddress(IDiamondLoupe.facetFunctionSelectors.selector), address(0));
        assertNotEq(l.facetAddress(IDiamondLoupe.facetAddresses.selector), address(0));
        assertNotEq(l.facetAddress(IDiamondLoupe.facetAddress.selector), address(0));
        assertNotEq(l.facetAddress(IERC165.supportsInterface.selector), address(0));

        // KYC
        assertNotEq(l.facetAddress(IKYCFacet.initiateKYC.selector), address(0));
        assertNotEq(l.facetAddress(IKYCFacet.approveKYC.selector), address(0));
        assertNotEq(l.facetAddress(IKYCFacet.rejectKYC.selector), address(0));
        assertNotEq(l.facetAddress(IKYCFacet.updateKYCStatus.selector), address(0));
        assertNotEq(l.facetAddress(IKYCFacet.isKYCCompliant.selector), address(0));
        assertNotEq(l.facetAddress(IKYCFacet.getKYCRecord.selector), address(0));
        assertNotEq(l.facetAddress(IKYCFacet.verifyDocument.selector), address(0));

        // AML
        assertNotEq(l.facetAddress(IAMLFacet.assessTransaction.selector), address(0));
        assertNotEq(l.facetAddress(IAMLFacet.setEntityRiskScore.selector), address(0));
        assertNotEq(l.facetAddress(IAMLFacet.flagSuspiciousActivity.selector), address(0));
        assertNotEq(l.facetAddress(IAMLFacet.fileSAR.selector), address(0));
        assertNotEq(l.facetAddress(IAMLFacet.getEntityRiskProfile.selector), address(0));
        assertNotEq(l.facetAddress(IAMLFacet.isHighRisk.selector), address(0));

        // Sanctions
        assertNotEq(l.facetAddress(ISanctionsFacet.screenEntity.selector), address(0));
        assertNotEq(l.facetAddress(ISanctionsFacet.verifyAgainstList.selector), address(0));
        assertNotEq(l.facetAddress(ISanctionsFacet.updateSanctionsList.selector), address(0));
        assertNotEq(l.facetAddress(ISanctionsFacet.addToSanctionsList.selector), address(0));
        assertNotEq(l.facetAddress(ISanctionsFacet.removeFromSanctionsList.selector), address(0));
        assertNotEq(l.facetAddress(ISanctionsFacet.clearFalsePositive.selector), address(0));
        assertNotEq(l.facetAddress(ISanctionsFacet.isSanctioned.selector), address(0));
        assertNotEq(l.facetAddress(ISanctionsFacet.getSanctionRecord.selector), address(0));
        assertNotEq(l.facetAddress(ISanctionsFacet.getSanctionsListRoot.selector), address(0));

        // Invoice
        assertNotEq(l.facetAddress(IInvoiceRegistryFacet.registerInvoice.selector), address(0));
        assertNotEq(l.facetAddress(IInvoiceRegistryFacet.verifyInvoice.selector), address(0));
        assertNotEq(l.facetAddress(IInvoiceRegistryFacet.canFactor.selector), address(0));
        assertNotEq(l.facetAddress(IInvoiceRegistryFacet.createFactoringAgreement.selector), address(0));
        assertNotEq(l.facetAddress(IInvoiceRegistryFacet.recordPayment.selector), address(0));
        assertNotEq(l.facetAddress(IInvoiceRegistryFacet.raiseDispute.selector), address(0));
        assertNotEq(l.facetAddress(IInvoiceRegistryFacet.getInvoice.selector), address(0));
        assertNotEq(l.facetAddress(IInvoiceRegistryFacet.getFactoringStatus.selector), address(0));
        assertNotEq(l.facetAddress(IInvoiceRegistryFacet.isInvoiceHashUsed.selector), address(0));

        // FATCA/CRS
        assertNotEq(l.facetAddress(IFATCACRSFacet.setTaxClassification.selector), address(0));
        assertNotEq(l.facetAddress(IFATCACRSFacet.recordTaxForm.selector), address(0));
        assertNotEq(l.facetAddress(IFATCACRSFacet.assessReportingRequirement.selector), address(0));
        assertNotEq(l.facetAddress(IFATCACRSFacet.createReportingObligation.selector), address(0));
        assertNotEq(l.facetAddress(IFATCACRSFacet.markAsReported.selector), address(0));
        assertNotEq(l.facetAddress(IFATCACRSFacet.getTaxClassification.selector), address(0));
        assertNotEq(l.facetAddress(IFATCACRSFacet.checkWithholding.selector), address(0));
        assertNotEq(l.facetAddress(IFATCACRSFacet.getPendingObligations.selector), address(0));

        // Jurisdiction
        assertNotEq(l.facetAddress(IJurisdictionFacet.configureJurisdiction.selector), address(0));
        assertNotEq(l.facetAddress(IJurisdictionFacet.assignEntityJurisdiction.selector), address(0));
        assertNotEq(l.facetAddress(IJurisdictionFacet.assessCrossBorder.selector), address(0));
        assertNotEq(l.facetAddress(IJurisdictionFacet.blockJurisdictionOperation.selector), address(0));
        assertNotEq(l.facetAddress(IJurisdictionFacet.blockCounterpartyPair.selector), address(0));
        assertNotEq(l.facetAddress(IJurisdictionFacet.getJurisdiction.selector), address(0));
        assertNotEq(l.facetAddress(IJurisdictionFacet.getEntityJurisdiction.selector), address(0));
        assertNotEq(l.facetAddress(IJurisdictionFacet.isTransactionPermitted.selector), address(0));
        assertNotEq(l.facetAddress(IJurisdictionFacet.getMinimumKYCLevel.selector), address(0));

        // Audit
        assertNotEq(l.facetAddress(IAuditFacet.logAudit.selector), address(0));
        assertNotEq(l.facetAddress(IAuditFacet.verifyAuditChain.selector), address(0));
        assertNotEq(l.facetAddress(IAuditFacet.getAuditEntry.selector), address(0));
        assertNotEq(l.facetAddress(IAuditFacet.getEntityAuditTrail.selector), address(0));
        assertNotEq(l.facetAddress(IAuditFacet.getLatestAuditHash.selector), address(0));
        assertNotEq(l.facetAddress(IAuditFacet.getAuditStats.selector), address(0));
        assertNotEq(l.facetAddress(IAuditFacet.logKYCEvent.selector), address(0));
        assertNotEq(l.facetAddress(IAuditFacet.logAMLEvent.selector), address(0));
        assertNotEq(l.facetAddress(IAuditFacet.logSanctionsEvent.selector), address(0));

        // Emergency
        assertNotEq(l.facetAddress(EmergencyFacet.emergencyPause.selector), address(0));
        assertNotEq(l.facetAddress(EmergencyFacet.emergencyUnpause.selector), address(0));
        assertNotEq(l.facetAddress(EmergencyFacet.emergencyWithdraw.selector), address(0));
        assertNotEq(l.facetAddress(EmergencyFacet.scheduleEmergencyUpgrade.selector), address(0));

        // Oracle
        assertNotEq(l.facetAddress(IOracleFacet.registerOracle.selector), address(0));
        assertNotEq(l.facetAddress(IOracleFacet.revokeOracle.selector), address(0));
        assertNotEq(l.facetAddress(IOracleFacet.submitOracleUpdate.selector), address(0));
        assertNotEq(l.facetAddress(IOracleFacet.requestOracleData.selector), address(0));
        assertNotEq(l.facetAddress(IOracleFacet.isAuthorizedOracle.selector), address(0));
        assertNotEq(l.facetAddress(IOracleFacet.getOracleAuthorizations.selector), address(0));
        assertNotEq(l.facetAddress(IOracleFacet.getPendingRequests.selector), address(0));
        assertNotEq(l.facetAddress(IOracleFacet.getOracleData.selector), address(0));

        // UpgradeManager
        assertNotEq(l.facetAddress(IUpgradeManagerFacet.registerStorageLayout.selector), address(0));
        assertNotEq(l.facetAddress(IUpgradeManagerFacet.validateStorageLayout.selector), address(0));
        assertNotEq(l.facetAddress(IUpgradeManagerFacet.getStorageLayout.selector), address(0));
        assertNotEq(l.facetAddress(IUpgradeManagerFacet.proposeUpgrade.selector), address(0));
        assertNotEq(l.facetAddress(IUpgradeManagerFacet.approveUpgrade.selector), address(0));
        assertNotEq(l.facetAddress(IUpgradeManagerFacet.cancelUpgrade.selector), address(0));
        assertNotEq(l.facetAddress(IUpgradeManagerFacet.getUpgradeProposal.selector), address(0));
        assertNotEq(l.facetAddress(IUpgradeManagerFacet.setRequiredApprovals.selector), address(0));
        assertNotEq(l.facetAddress(IUpgradeManagerFacet.getUpgradeHistory.selector), address(0));
        assertNotEq(l.facetAddress(IUpgradeManagerFacet.recordUpgrade.selector), address(0));
        assertNotEq(l.facetAddress(IUpgradeManagerFacet.getPreUpgradeSnapshot.selector), address(0));

        // SecurityGuard
        assertNotEq(l.facetAddress(ISecurityGuardFacet.setRateLimit.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.removeRateLimit.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.checkRateLimit.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.recordActivity.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.setCircuitBreakerConfig.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.getCircuitBreakerStatus.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.registerThreatIndicator.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.deactivateThreatIndicator.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.getThreatIndicator.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.reportSecurityIncident.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.getSecurityIncidents.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.blockAddress.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.unblockAddress.selector), address(0));
        assertNotEq(l.facetAddress(ISecurityGuardFacet.isAddressBlocked.selector), address(0));
    }

    function test_totalSelectorCount() public view {
        IDiamondLoupe.Facet[] memory allFacets = loupe().facets();
        uint256 totalSelectors = 0;
        for (uint256 i = 0; i < allFacets.length; i++) {
            totalSelectors += allFacets[i].functionSelectors.length;
        }
        // 3 + 5 + 7 + 6 + 9 + 9 + 8 + 9 + 9 + 4 + 8 + 11 + 14 = 102 selectors across 13 facets
        assertEq(totalSelectors, 102);
    }
}
