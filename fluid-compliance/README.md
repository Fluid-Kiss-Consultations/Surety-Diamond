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
├── facets/                     11 facets (9 compliance + 1 oracle + 1 diamond management)
│   ├── KYCFacet.sol            FATF-compliant KYC, document Merkle proofs, PEP flag
│   ├── AMLFacet.sol            Risk scoring (0-1000), SAR filing, entity profiling
│   ├── SanctionsFacet.sol      OFAC/UN/EU Merkle-tree screening
│   ├── InvoiceRegistryFacet.sol Invoice registry, double-factoring prevention
│   ├── FATCACRSFacet.sol       FATCA/CRS classification, withholding, obligations
│   ├── JurisdictionFacet.sol   Cross-border routing, jurisdiction configuration
│   ├── AuditFacet.sol          Hash-chained immutable audit trail
│   ├── EmergencyFacet.sol      Pause/unpause, emergency upgrade scheduling
│   ├── OracleFacet.sol         Oracle registration, ECDSA-verified data feeds
│   ├── DiamondCutFacet.sol     Scheduled upgrades (schedule → wait 48h → execute)
│   └── DiamondLoupeFacet.sol   EIP-2535 loupe + ERC-165
├── interfaces/                 12 Solidity interfaces (I*.sol)
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
| `test/Diamond.t.sol` | Loupe, timelock enforcement, ERC-165 |
| `test/Integration.t.sol` | End-to-end: KYC → AML → Sanctions → Invoice → Factor → Audit |

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
```

---

## Upgrade Procedures

All facet upgrades follow a three-step timelocked process:

```solidity
// 1. Prepare facet cut
FacetCut[] memory cut = new FacetCut[](1);
cut[0] = FacetCut({
    facetAddress: newFacetAddress,
    action: FacetCutAction.Replace,
    functionSelectors: selectors
});

// 2. Schedule upgrade (48-hour timelock)
diamond.scheduleUpgrade(cut, initAddress, initData);

// 3. Execute after timelock expires
diamond.executeUpgrade(upgradeId);
```

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

### Security Features

1. **48-hour Timelock** — All diamond upgrades
2. **Reentrancy Guards** — State-changing functions
3. **Custom Errors** — Gas-efficient error handling
4. **Pausability** — Emergency stop mechanism
5. **Audit Trail** — Immutable, hash-chained logging

### Known Limitations

1. **Storage Layout** — Must maintain consistency across upgrades
2. **Function Selectors** — Manual collision prevention required
3. **Oracle Trust** — Relies on trusted external data providers
4. **Gas Costs** — Complex operations may exceed block limits

---

## Known Gaps / Next Steps

- `script/Deploy.s.sol` needs selector array verification against `forge inspect` output before mainnet use
- Test coverage target is ≥90% per facet — run `forge coverage` to check current status
- `DiamondInit.init` can only be called once; post-init role grants require an owner transaction via `LibRoles` internals or a dedicated admin facet
- `JurisdictionFacet.blockJurisdictionOperation` currently only handles `FACTORING`; extend for other operation types as needed
- Add fuzzing tests for risk scoring and invoice validation edge cases

---

## References

- [`compliance-facets-specification.md`](../compliance-facets-specification.md) — Complete feature specification (52KB)
- [EIP-2535 Diamond Standard](https://eips.ethereum.org/EIPS/eip-2535)

---

## Custom EIP-2535 Diamond Contracts

Available for consultation, architecture, creation, testing, and implementation (onboarding) of custom EIP-2535 Diamond Standard contract systems.

**Contact:** fluidkiss1337@gmail.com
