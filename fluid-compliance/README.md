# Surety — On-Chain Compliance Diamond

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](../LICENSE)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.24-blue.svg)](https://soliditylang.org)
[![EIP-2535](https://img.shields.io/badge/EIP--2535-Diamond-purple.svg)](https://eips.ethereum.org/EIPS/eip-2535)

Surety is a production-grade compliance engine for enterprise supply chain finance (SCF) platforms operating across multiple jurisdictions. It implements the **EIP-2535 Diamond Standard** to deliver modular, upgradeable on-chain KYC, AML, sanctions screening, invoice registry, FATCA/CRS reporting, and multi-jurisdiction routing.

---

## Quick Start

```bash
# Install Foundry (https://getfoundry.sh)
curl -L https://foundry.paradigm.xyz | bash
foundryup

# Build
forge build

# Test
forge test -vvv

# Coverage
forge coverage
```

> **Requirements:** Foundry ≥ 0.2, Solidity ^0.8.24, Node ≥ 18 (optional, tooling only)

---

## Architecture

All logic lives in **facets** — independent contracts whose functions are `delegatecall`'d through a single `SuretyDiamond` proxy. Every facet reads/writes shared state through a single deterministic storage slot (`LibAppStorage`).

```
User / Protocol
      │
      ▼
SuretyDiamond (EIP-2535 proxy)
      │  delegatecall  (selector → facet via LibDiamond routing table)
      ├─── KYCFacet
      ├─── AMLFacet
      ├─── SanctionsFacet
      ├─── InvoiceRegistryFacet
      ├─── FATCACRSFacet
      ├─── JurisdictionFacet
      ├─── AuditFacet
      ├─── EmergencyFacet
      ├─── OracleFacet
      ├─── UpgradeManagerFacet (storage validation, multi-sig, rollback)
      ├─── SecurityGuardFacet  (rate limiting, circuit breaker, threats)
      ├─── DiamondCutFacet   (upgrades, 48-hour timelock)
      └─── DiamondLoupeFacet (EIP-2535 introspection)
              │
              ▼  (all share)
      LibAppStorage (slot keccak256("surety.compliance.diamond.storage"))
```

**Key invariant:** Facets never declare instance variables. All state goes through `LibAppStorage.appStorage()`.

---

## Source Layout

```
src/
├── diamond/
│   ├── SuretyDiamond.sol       EIP-2535 proxy with 48-hour upgrade timelock
│   └── DiamondInit.sol         One-time initializer (owner, treasury, roles)
├── facets/                     13 facets (9 compliance + 2 infrastructure + 1 oracle + 1 diamond)
│   ├── KYCFacet.sol            FATF-compliant KYC, document Merkle proofs, PEP flag
│   ├── AMLFacet.sol            Risk scoring (0-1000), SAR filing, entity profiling
│   ├── SanctionsFacet.sol      OFAC/UN/EU Merkle-tree screening
│   ├── InvoiceRegistryFacet.sol Invoice registry, double-factoring prevention
│   ├── FATCACRSFacet.sol       FATCA/CRS classification, withholding, obligations
│   ├── JurisdictionFacet.sol   Cross-border routing, jurisdiction configuration
│   ├── AuditFacet.sol          Hash-chained immutable audit trail
│   ├── EmergencyFacet.sol      Pause/unpause, emergency upgrade scheduling
│   ├── OracleFacet.sol         Oracle registration, ECDSA-verified data feeds
│   ├── UpgradeManagerFacet.sol Storage layout validation, multi-sig proposals, rollback
│   ├── SecurityGuardFacet.sol  Rate limiting, circuit breaker, threat registry
│   ├── DiamondCutFacet.sol     Scheduled upgrades (schedule → wait 48h → execute)
│   └── DiamondLoupeFacet.sol   EIP-2535 loupe + ERC-165
├── interfaces/                 14 Solidity interfaces (I*.sol)
└── libraries/
    ├── LibAppStorage.sol       Shared storage: all structs, enums, AppStorage struct
    ├── LibDiamond.sol          EIP-2535 mechanics: selector routing, cut/add/remove
    └── LibRoles.sol            Role constants and RBAC helpers
```

---

## Facet Reference

| Facet | Key Functions | Required Role |
|-------|--------------|---------------|
| `KYCFacet` | `initiateKYC`, `approveKYC`, `rejectKYC`, `isKYCCompliant` | `KYC_VERIFIER_ROLE` |
| `AMLFacet` | `assessTransaction`, `setEntityRiskScore`, `fileSAR` | `AML_ANALYST_ROLE` |
| `SanctionsFacet` | `screenEntity`, `verifyAgainstList`, `updateSanctionsList` | `SANCTIONS_MANAGER_ROLE` / `ORACLE_ROLE` |
| `InvoiceRegistryFacet` | `registerInvoice`, `verifyInvoice`, `createFactoringAgreement` | `SELLER_ROLE` / `FACTOR_ROLE` |
| `FATCACRSFacet` | `setTaxClassification`, `assessReportingRequirement`, `checkWithholding` | `TAX_OFFICER_ROLE` |
| `JurisdictionFacet` | `configureJurisdiction`, `assessCrossBorder`, `blockCounterpartyPair` | `DEFAULT_ADMIN_ROLE` / `COMPLIANCE_OFFICER_ROLE` |
| `AuditFacet` | `logAudit`, `getAuditEntry`, `getEntityAuditTrail`, `verifyAuditChain` | `AUDITOR_ROLE` |
| `EmergencyFacet` | `emergencyPause`, `emergencyUnpause`, `scheduleEmergencyUpgrade` | `PAUSER_ROLE` / `EMERGENCY_ADMIN_ROLE` |
| `OracleFacet` | `registerOracle`, `submitOracleUpdate`, `requestOracleData` | `DEFAULT_ADMIN_ROLE` / `ORACLE_ROLE` |
| `UpgradeManagerFacet` | `registerStorageLayout`, `proposeUpgrade`, `approveUpgrade`, `recordUpgrade` | `UPGRADE_MANAGER_ROLE` |
| `SecurityGuardFacet` | `setRateLimit`, `reportSecurityIncident`, `blockAddress`, `setCircuitBreakerConfig` | `SECURITY_ADMIN_ROLE` |
| `DiamondCutFacet` | `scheduleDiamondCut`, `executeDiamondCut`, `diamondCut` | Contract owner |
| `DiamondLoupeFacet` | `facets`, `facetAddresses`, `supportsInterface` | — (view only) |

---

## Roles

Defined in `LibRoles.sol`:

| Constant | Purpose |
|----------|---------|
| `DEFAULT_ADMIN_ROLE` | Full admin (owns diamond, grants roles) |
| `COMPLIANCE_OFFICER_ROLE` | Jurisdiction assignment, obligation management |
| `KYC_VERIFIER_ROLE` | Approve/reject KYC records |
| `AML_ANALYST_ROLE` | Risk scoring, suspicious activity flagging |
| `SANCTIONS_MANAGER_ROLE` | Add/remove sanctions list entries |
| `AUDITOR_ROLE` | Write to audit trail |
| `ORACLE_ROLE` | Submit verified data feeds |
| `FACTOR_ROLE` | Create factoring agreements |
| `SELLER_ROLE` | Register invoices |
| `BUYER_ROLE` | Verify invoices |
| `EMERGENCY_ADMIN_ROLE` | Unpause system, schedule emergency upgrades |
| `PAUSER_ROLE` | Trigger emergency pause |
| `UPGRADE_MANAGER_ROLE` | Propose/approve upgrades, register storage layouts |
| `SECURITY_ADMIN_ROLE` | Rate limiting, threat indicators, incident reporting |

---

## Deployment

```bash
# Copy and fill in environment variables
cp .env.example .env

# Deploy to a local fork
forge script script/Deploy.s.sol \
  --rpc-url $RPC_URL \
  --private-key $PRIVATE_KEY \
  --broadcast \
  -vvvv
```

Required environment variables:

```
PRIVATE_KEY=<deployer-private-key>
OWNER_ADDRESS=<initial-owner-address>
RPC_URL=<ethereum-rpc-endpoint>
TREASURY_ADDRESS=<treasury-address>          # optional, defaults to OWNER_ADDRESS
ETHERSCAN_API_KEY=<for-contract-verification> # optional
```

---

## Testing

Tests are in `test/` and use [forge-std](https://github.com/foundry-rs/forge-std). Each facet has a dedicated test file plus an integration test.

```bash
forge test -vvv                       # run all tests with traces
forge test --match-test test_double   # run specific tests
forge coverage --report lcov          # coverage report
```

Key test files:

| File | Coverage focus |
|------|---------------|
| `test/InvoiceRegistryFacet.t.sol` | Double-factoring prevention (critical path) |
| `test/KYCFacet.t.sol` | KYC lifecycle, Merkle proof verification |
| `test/AMLFacet.t.sol` | Risk scoring, SAR auto-filing |
| `test/SanctionsFacet.t.sol` | Merkle-proof sanctions screening |
| `test/JurisdictionFacet.t.sol` | Cross-border assessment, blocked pairs |
| `test/FATCACRSFacet.t.sol` | Withholding, reporting obligations |
| `test/AuditFacet.t.sol` | Hash-chain integrity, typed event guards |
| `test/OracleFacet.t.sol` | Oracle registration, ECDSA signature verification |
| `test/EmergencyFacet.t.sol` | Pause/unpause, upgrade scheduling |
| `test/UpgradeManagerFacet.t.sol` | Storage layout, multi-sig proposals, upgrade history |
| `test/SecurityGuardFacet.t.sol` | Rate limiting, circuit breaker, threat registry, blocking |
| `test/Diamond.t.sol` | Loupe, timelock enforcement, ERC-165 |
| `test/Integration.t.sol` | End-to-end: KYC → AML → Sanctions → Invoice → Factor → Audit |
| `test/DeploySelectors.t.sol` | Validates all 102 selectors routed in diamond |
| `test/fuzz/FuzzAMLFacet.t.sol` | AML risk scoring bounds and escalation |
| `test/fuzz/FuzzInvoiceRegistryFacet.t.sol` | Invoice amount/rate bounds, payment transitions |

---

## Regulatory Context

| Region | Frameworks |
|--------|-----------|
| USA | BSA, USA PATRIOT Act §312/§319, OFAC SDN, FATCA |
| EU | MiCA, 6AMLD, GDPR |
| Global | FATF Recommendations, UN Security Council sanctions, Basel III/IV |

**Sanctions lists supported:** `OFAC_SDN`, `OFAC_CONS`, `UN_SC`, `EU_CONS`, `UK_HMT`, `CUSTOM`

**KYC levels:** `NONE` → `BASIC` → `STANDARD` → `ENHANCED` → `INSTITUTIONAL`

---

## Post-Deployment Configuration

```solidity
// 1. Grant initial roles
diamond.grantRole(COMPLIANCE_OFFICER_ROLE, complianceOfficer);
diamond.grantRole(KYC_VERIFIER_ROLE, kycVerifier);
diamond.grantRole(AML_ANALYST_ROLE, amlAnalyst);

// 2. Configure jurisdictions
diamond.configureJurisdiction(usConfig);
diamond.configureJurisdiction(euConfig);

// 3. Register oracles
diamond.registerOracle(chainlinkOracle, [SANCTIONS_LIST, EXCHANGE_RATE]);

// 4. Set thresholds
diamond.setReportingThreshold(10000 * 1e18); // $10,000

// 5. Configure upgrade governance (UpgradeManagerFacet)
diamond.setRequiredApprovals(2); // Require 2 UPGRADE_MANAGER_ROLE holders to approve

// 6. Configure security (SecurityGuardFacet)
diamond.setCircuitBreakerConfig(5, 1 hours); // Auto-pause after 5 incidents/hour
diamond.setRateLimit(KYCFacet.initiateKYC.selector, 100, 1 hours); // 100 KYC/hr max
```

---

## Upgrade Procedures

All facet upgrades follow a timelocked, multi-sig governance process:

```solidity
// 1. Register storage layout for the new facet (UpgradeManagerFacet)
StorageSlotDescriptor[] memory layout = new StorageSlotDescriptor[](2);
layout[0] = StorageSlotDescriptor(0, 32, keccak256("field1"), keccak256("bytes32"));
layout[1] = StorageSlotDescriptor(32, 32, keccak256("field2"), keccak256("uint256"));
diamond.registerStorageLayout(newFacetAddress, layout);

// 2. Prepare facet cut
FacetCut[] memory cut = new FacetCut[](1);
cut[0] = FacetCut({
    facetAddress: newFacetAddress,
    action: FacetCutAction.Replace,
    functionSelectors: selectors
});

// 3. Schedule upgrade (48-hour timelock via DiamondCutFacet)
bytes32 upgradeId = diamond.scheduleDiamondCut(cut, initAddress, initData, 48 hours);

// 4. Propose and collect multi-sig approvals (UpgradeManagerFacet)
diamond.proposeUpgrade(upgradeId, "Upgrade description", storageLayoutHash);
diamond.approveUpgrade(upgradeId); // Each UPGRADE_MANAGER_ROLE holder approves

// 5. Execute after timelock expires
diamond.executeDiamondCut(upgradeId);

// 6. Record upgrade in history (UpgradeManagerFacet)
diamond.recordUpgrade(upgradeId, facetsChanged, added, replaced, removed);
```

Pre-upgrade snapshots are automatically captured when proposals are created, enabling rollback reference via `getPreUpgradeSnapshot(upgradeId)`.

---

## Security

### Access Control Matrix

| Role | Critical Functions | Risk Level |
|------|-------------------|------------|
| `DEFAULT_ADMIN_ROLE` | Diamond upgrades, role management | CRITICAL |
| `COMPLIANCE_OFFICER_ROLE` | SAR submission, jurisdiction config | HIGH |
| `KYC_VERIFIER_ROLE` | Identity verification | HIGH |
| `AML_ANALYST_ROLE` | Risk scoring, transaction monitoring | MEDIUM |
| `SANCTIONS_MANAGER_ROLE` | Sanctions list management | HIGH |
| `ORACLE_ROLE` | External data updates | MEDIUM |
| `EMERGENCY_ADMIN_ROLE` | System pause, emergency withdraw | CRITICAL |
| `UPGRADE_MANAGER_ROLE` | Propose/approve upgrades, storage validation | HIGH |
| `SECURITY_ADMIN_ROLE` | Rate limiting, threat management, incident response | HIGH |

### Security Features

1. **48-hour Timelock** — All diamond upgrades
2. **Reentrancy Guards** — State-changing functions
3. **Custom Errors** — Gas-efficient error handling
4. **Pausability** — Emergency stop mechanism
5. **Audit Trail** — Immutable, hash-chained logging
6. **Storage Layout Validation** — On-chain storage slot descriptors per facet, hash-based collision detection before upgrades (UpgradeManagerFacet)
7. **Multi-sig Upgrade Governance** — Configurable approval threshold for upgrade proposals, preventing unilateral upgrades (UpgradeManagerFacet)
8. **Rate Limiting** — Per-selector, per-address sliding window rate limits for sensitive operations (SecurityGuardFacet)
9. **Circuit Breaker** — Auto-pause when security incident count exceeds threshold within a time window (SecurityGuardFacet)
10. **Threat Registry** — Known threat indicator tracking with severity levels for pattern detection (SecurityGuardFacet)
11. **Address Blocking** — CRITICAL incidents auto-block offending addresses; manual block/unblock by security admin (SecurityGuardFacet)

### Known Limitations

1. **Storage Layout** — Must maintain consistency across upgrades; UpgradeManagerFacet provides on-chain validation but requires manual layout registration
2. **Function Selectors** — Manual collision prevention required
3. **Oracle Trust** — Relies on trusted external data providers
4. **Gas Costs** — Complex operations may exceed block limits; SecurityGuardFacet incident queries iterate all incidents (consider pagination for high-volume systems)

---

## Known Gaps / Next Steps

- `script/Deploy.s.sol` needs selector array verification against `forge inspect` output before mainnet use
- Test coverage target is ≥90% per facet — run `forge coverage` to check current status
- `DiamondInit.init` can only be called once; post-init role grants require an owner transaction via `LibRoles` internals or a dedicated admin facet
- `JurisdictionFacet.blockJurisdictionOperation` currently only handles `FACTORING`; extend for other operation types as needed
- Add fuzzing tests for risk scoring and invoice validation edge cases
- UpgradeManagerFacet storage layout registration is manual; consider automated layout extraction from `forge inspect` output
- SecurityGuardFacet `getSecurityIncidents` iterates all incidents linearly; add indexed pagination for production deployments with high incident volume
- Consider integrating `SecurityGuardFacet.recordActivity()` calls into existing facet modifiers for transparent rate limiting

---

## References

- [`compliance-facets-specification.md`](../compliance-facets-specification.md) — Complete feature specification (52KB)
- [EIP-2535 Diamond Standard](https://eips.ethereum.org/EIPS/eip-2535)

---

## Custom EIP-2535 Diamond Contracts

Available for consultation, architecture, creation, testing, and implementation (onboarding) of custom EIP-2535 Diamond Standard contract systems.

**Contact:** fluidkiss1337@gmail.com
