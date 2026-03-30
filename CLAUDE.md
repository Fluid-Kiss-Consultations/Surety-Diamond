# CLAUDE.md — AI Assistant Guide for Surety-Diamond

This file provides context for AI assistants (Claude and others) working in this repository.

---

## Project Overview

**Surety-Diamond** is a modular, upgradeable smart contract system implementing EIP-2535 Diamond Standard for financial compliance. It is designed for enterprise supply chain finance (SCF) platforms operating across multiple jurisdictions with high-volume payment flows.

The system provides on-chain compliance infrastructure: KYC, AML, sanctions screening, invoice registry, FATCA/CRS reporting, multi-jurisdiction routing, and audit logging.

---

## Repository Layout

```
Surety-Diamond/
├── fluid-compliance/           # Main Solidity project (Foundry)
│   ├── src/
│   │   ├── diamond/            # EIP-2535 Diamond proxy and init
│   │   ├── facets/             # 13 facet contracts (compliance + infrastructure)
│   │   ├── interfaces/         # 14 Solidity interfaces (I*.sol)
│   │   └── libraries/          # Shared storage and utilities
│   ├── test/                   # Foundry test suite
│   ├── script/                 # Deployment scripts
│   └── README.md               # Technical reference and API docs
├── compliance-facets-specification.md  # Full feature specification (52KB)
├── README.md                   # Project overview
└── CLAUDE.md                   # This file
```

### Key Source Files

| File | Purpose |
|------|--------|
| `src/diamond/SuretyDiamond.sol` | Main EIP-2535 proxy with 48-hour upgrade timelock |
| `src/diamond/DiamondInit.sol` | One-time initialization logic |
| `src/libraries/LibAppStorage.sol` | Central shared storage struct for all facets |
| `src/libraries/LibRoles.sol` | Role-based access control definitions |
| `src/libraries/LibDiamond.sol` | EIP-2535 diamond mechanics (routing table, ownership) |
| `src/facets/DiamondCutFacet.sol` | Facet management (add/replace/remove) with timelock |
| `src/facets/DiamondLoupeFacet.sol` | Facet enumeration (EIP-2535 loupe interface) |

---

## Architecture

### Diamond Standard (EIP-2535)

All logic lives in **facets** — independent contracts whose functions are delegatecalled through a single `SuretyDiamond` proxy. Storage is shared via `LibAppStorage` using a deterministic storage slot (`keccak256("surety.compliance.diamond.storage")`).

```
User/Protocol
     │
     ▼
SuretyDiamond (proxy)
     │  delegatecall
     ▼
[KYCFacet | AMLFacet | SanctionsFacet | InvoiceRegistryFacet | ...]
     │
     ▼  (all share)
LibAppStorage (single storage slot)
```

**Key principle:** Never add instance variables to facets. All state must go through `LibAppStorage.appStorage()`.

### Design Rationale

See `fluid-compliance/README.md` § "Why Diamond Standard" for the architectural rationale (upgradeability, storage efficiency, size limits, granular access control).

### Facets (13 implemented)

| Facet | Responsibility |
|-------|---------------|
| `KYCFacet` | FATF-compliant KYC verification, Merkle document proofs, PEP detection |
| `AMLFacet` | AML risk scoring (0–1000 scale), SAR filing, transaction monitoring |
| `SanctionsFacet` | OFAC/UN/EU sanctions screening via Merkle proofs |
| `InvoiceRegistryFacet` | Invoice registration, double-factoring prevention, factoring agreements |
| `FATCACRSFacet` | FATCA/CRS tax compliance, withholding calculation |
| `JurisdictionFacet` | Multi-jurisdiction regulatory routing |
| `AuditFacet` | Hash-chained immutable audit trail |
| `EmergencyFacet` | System pause/unpause, timelocked emergency upgrade scheduling |
| `OracleFacet` | Oracle registration, ECDSA-verified external data feeds |
| `UpgradeManagerFacet` | Storage layout validation, multi-sig upgrade proposals, upgrade history, rollback snapshots |
| `SecurityGuardFacet` | Rate limiting, circuit breaker auto-pause, threat registry, incident reporting, address blocking |
| `DiamondCutFacet` | Facet upgrades with 48-hour timelock |
| `DiamondLoupeFacet` | Facet and function enumeration, ERC-165 interface detection |

### Storage Layout

`LibAppStorage.sol` defines the single `AppStorage` struct used by all facets:
- KYC records (mapping by address)
- AML risk scores and SARs
- Sanctions lists (Merkle roots, 5 list types)
- Invoice registry (mapping by invoice hash)
- Jurisdiction configurations
- FATCA/CRS classifications
- Audit trail (hash-chained)
- Role assignments
- Upgrade manager (storage layouts, proposals, history, snapshots)
- Security guard (rate limits, circuit breaker, threat indicators, incidents, blocked addresses)

---

## Development Environment

### Prerequisites

- **Foundry** (latest) — `forge`, `cast`, `anvil`
- **Node.js** >= 18.0.0
- **Git**
- **Solidity** ^0.8.24

### Config Files

Both `fluid-compliance/foundry.toml` and `fluid-compliance/remappings.txt` exist and are configured. `forge build` and `forge test` run cleanly from `fluid-compliance/`.

### Build & Test Commands

```bash
# From fluid-compliance/
forge build
forge test
forge test -vvv           # verbose output
forge coverage            # code coverage
forge fmt                 # format Solidity files
```

### Environment Variables

Required for deployment:
```
PRIVATE_KEY=<deployer-private-key>
OWNER_ADDRESS=<initial-owner-address>
RPC_URL=<ethereum-rpc-endpoint>
ETHERSCAN_API_KEY=<for-contract-verification>
```

See `fluid-compliance/.env.example` for required deployment variables. Copy to `.env` and fill in values before deploying.

---

## Coding Conventions

### Solidity Style

- **SPDX header:** `// SPDX-License-Identifier: MIT`
- **Pragma:** `pragma solidity ^0.8.24;`
- **Custom errors** — never use string revert messages (gas efficiency)
- **NatSpec** on all `public`/`external` functions (`@notice`, `@param`, `@return`)
- **Section dividers:** `// ============================================================`

### Naming

| Item | Convention |
|------|----------|
| Facets | `PascalCaseFacet` |
| Interfaces | `IPascalCase` (I prefix) |
| Libraries | `LibPascalCase` (Lib prefix) |
| Constants | `SCREAMING_SNAKE_CASE` |
| Roles | `keccak256("ROLE_NAME_ROLE")` bytes32 constants (always `_ROLE` suffix) |
| Events | Past tense: `KYCApproved`, `SARFiled`, `InvoiceRegistered` |

### Access Control

Always guard with role checks. Pattern:
```solidity
LibRoles.checkRole(LibRoles.COMPLIANCE_OFFICER_ROLE);
```

Role constants defined in `LibRoles.sol`:
- `DEFAULT_ADMIN_ROLE`, `COMPLIANCE_OFFICER_ROLE`, `KYC_VERIFIER_ROLE`, `AML_ANALYST_ROLE`, `SANCTIONS_MANAGER_ROLE`
- `ORACLE_ROLE`, `FACTOR_ROLE`, `SELLER_ROLE`, `BUYER_ROLE`
- `TAX_OFFICER_ROLE`, `AUDITOR_ROLE`
- `EMERGENCY_ADMIN_ROLE`, `PAUSER_ROLE`
- `UPGRADE_MANAGER_ROLE`, `SECURITY_ADMIN_ROLE`

### Storage Access

Facets access storage via the library helper — never directly:
```solidity
AppStorage storage s = LibAppStorage.appStorage();
```

### Events

Every state-changing operation must emit an event. Events must have indexed fields for the primary entity (address, invoiceHash, etc.) and a timestamp.

### System Constants

```
MIN_RISK_SCORE = 0
MAX_RISK_SCORE = 1000
HIGH_RISK_THRESHOLD = 750
MEDIUM_RISK_THRESHOLD = 400
SAR_FILING_THRESHOLD = 10000 * 1e18   // $10,000
MIN_TIMELOCK = 48 hours
```

---

## Regulatory Context

The system targets these compliance frameworks:

| Region | Frameworks |
|--------|----------|
| USA | BSA, USA PATRIOT Act §312/§319, OFAC, FATCA |
| EU | MiCA, 6th AML Directive (6AMLD), GDPR |
| Global | FATF Recommendations, UN Security Council sanctions, Basel III/IV |
| UK | Financial Sanctions (HMT) |

**KYC Levels:** NONE → BASIC → STANDARD → ENHANCED → INSTITUTIONAL

**Sanctions Lists:** OFAC_SDN, OFAC_CONS, UN_SC, EU_CONS, UK_HMT

---

## Current State

As of 2026-03-30:

### Completed
- All 13 facets implemented and wired into `SuretyDiamond` constructor via `DiamondTestHelper`
- `LibDiamond.sol` — full EIP-2535 implementation
- `LibAppStorage.sol` — shared storage struct with 8 domain sections + upgrade manager + security guard storage
- `LibRoles.sol` — role-based access control with 15 role constants (`_ROLE` suffix convention)
- `foundry.toml` + `remappings.txt` — configured, `forge build` passes
- `script/Deploy.s.sol` — deployment script (13 facets, 102 selectors)
- `.env.example` — deployment environment template
- Test suite — all tests passing across 13 facets + integration suite (CI verified)
- Security remediations — all 14 findings (2 CRITICAL, 4 HIGH, 3 MEDIUM, 4 LOW) resolved and merged
- `fluid-compliance/README.md` — technical reference and API docs
- Fuzzing tests — `test/fuzz/FuzzAMLFacet.t.sol` and `test/fuzz/FuzzInvoiceRegistryFacet.t.sol`
- Deploy.s.sol selector verification — `test/DeploySelectors.t.sol` validates all 102 selectors are routed
- Stub function implementations — `getPendingRequests` (dataType filtering), `getFactoringStatus` (actual factor address), `getAuditStats` (eventType/period filtering)
- Unused parameter logic — `narrative` stored in `sarNarratives`, `paymentReference` stored and emitted via `PaymentRecorded`, `reason`/`clearanceReason` stored in `sanctionsClearanceReasons`
- SanctionsFacet event enrichment — `addToSanctionsList` and `removeFromSanctionsList` now accept `address entity` parameter, eliminating `address(0)` in events
- **UpgradeManagerFacet** — storage layout registration/validation, multi-sig upgrade proposals, upgrade history tracking, pre-upgrade facet snapshots for rollback reference (11 selectors)
- **SecurityGuardFacet** — per-selector rate limiting with sliding windows, circuit breaker auto-pause on incident threshold, threat indicator registry, security incident reporting with auto-block on CRITICAL, address blocking (14 selectors)

### Remaining
- None — all planned items complete. Ready for mainnet deployment preparation.

---

## Git Workflow

- **Main branch:** `main`
- **Remote:** `fluidkiss1337-creator/Surety-Diamond`
- All completed work should be merged into `main`
- Commit messages follow conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`
- One logical change per commit
- Never commit private keys or `.env` files

---

## Documentation References

- `compliance-facets-specification.md` — Complete feature spec with business context (52KB)
- `fluid-compliance/README.md` — Technical reference, API docs, deployment, and security

---

## Contact

For custom EIP-2535 Diamond contract work (consultation, architecture, creation, testing, implementation): **fluidkiss1337@gmail.com**
