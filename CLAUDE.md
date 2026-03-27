# CLAUDE.md — AI Assistant Guide for Fluid-Innovation

This file provides context for AI assistants (Claude and others) working in this repository.

---

## Project Overview

**Fluid-Innovation / Surety** is a modular, upgradeable smart contract system implementing EIP-2535 Diamond Standard for financial compliance. It is built for **PrimeRevenue**, a global supply chain finance platform operating across 80+ countries with ~$300B annual payment volume.

The system provides on-chain compliance infrastructure: KYC, AML, sanctions screening, invoice registry, FATCA/CRS reporting, multi-jurisdiction routing, and audit logging.

---

## Repository Layout

```
Fluid-Innovation/
├── fluid-compliance/           # Main Solidity project (Foundry)
│   ├── src/
│   │   ├── diamond/            # EIP-2535 Diamond proxy and init
│   │   ├── facets/             # 10 compliance facet contracts
│   │   ├── interfaces/         # 12 Solidity interfaces (I*.sol)
│   │   └── libraries/          # Shared storage and utilities
│   └── [root loose files]      # Old drafts — superseded by src/, should be deleted
├── docs/
│   └── Surety-current-state.md # Latest handoff / state-of-the-world document
├── compliance-facets-specification.md  # Full feature specification (52KB)
├── README.md
└── CLAUDE.md                   # This file
```

### Key Source Files

| File | Purpose |
|------|---------|
| `src/diamond/SuretyDiamond.sol` | Main EIP-2535 proxy with 48-hour upgrade timelock |
| `src/diamond/DiamondInit.sol` | One-time initialization logic |
| `src/libraries/LibAppStorage.sol` | Central shared storage struct for all facets |
| `src/libraries/LibRoles.sol` | Role-based access control definitions |
| `src/libraries/LibDiamond.sol` | EIP-2535 diamond mechanics (INCOMPLETE — has TODOs) |
| `src/facets/DiamondCutFacet.sol` | Facet management (add/replace/remove) with timelock |
| `src/facets/DiamondLoupeFacet.sol` | Facet enumeration (EIP-2535 loupe interface) |

---

## Architecture

### Diamond Standard (EIP-2535)

All logic lives in **facets** — independent contracts whose functions are delegatecalled through a single `SuretyDiamond` proxy. Storage is shared via `LibAppStorage` using a deterministic storage slot.

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

### Facets (10 implemented)

| Facet | Responsibility |
|-------|---------------|
| `KYCFacet` | FATF-compliant KYC verification, document management, PEP detection |
| `AMLFacet` | AML risk scoring (0–1000 scale), SAR filing, transaction monitoring |
| `SanctionsFacet` | OFAC/UN/EU sanctions screening via Merkle proofs |
| `InvoiceRegistryFacet` | Invoice registration, double-factoring prevention, factoring agreements |
| `FATCACRSFacet` | FATCA/CRS tax compliance, withholding calculation |
| `JurisdictionFacet` | Multi-jurisdiction regulatory routing |
| `AuditFacet` | Hash-chained immutable audit trail |
| `EmergencyFacet` | System pause/unpause, emergency withdrawal |
| `DiamondCutFacet` | Facet upgrades with 48-hour timelock |
| `DiamondLoupeFacet` | Facet and function enumeration |

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

---

## Development Environment

### Prerequisites

- **Foundry** (latest) — `forge`, `cast`, `anvil`
- **Node.js** >= 18.0.0
- **Git**
- **Solidity** ^0.8.24

### Missing Config (must be created before building)

The following files do not yet exist and are needed to compile:

1. **`fluid-compliance/foundry.toml`** — Foundry project configuration
2. **`fluid-compliance/remappings.txt`** — Solidity import remappings

Minimal `foundry.toml`:
```toml
[profile.default]
src = "src"
out = "out"
libs = ["lib"]
solc = "0.8.24"
optimizer = true
optimizer_runs = 200
```

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

No `.env` or `.env.example` file exists yet — create one before deploying.

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
|------|-----------|
| Facets | `PascalCaseFacet` |
| Interfaces | `IPascalCase` (I prefix) |
| Libraries | `LibPascalCase` (Lib prefix) |
| Constants | `SCREAMING_SNAKE_CASE` |
| Roles | `keccak256("ROLE_NAME")` bytes32 constants |
| Events | Past tense: `KYCApproved`, `SARFiled`, `InvoiceRegistered` |

### Access Control

Always guard with role checks. Pattern:
```solidity
if (!LibRoles.hasRole(LibRoles.COMPLIANCE_OFFICER, msg.sender)) {
    revert AccessControlUnauthorized(msg.sender, LibRoles.COMPLIANCE_OFFICER);
}
```

Role constants defined in `LibRoles.sol`:
- `COMPLIANCE_OFFICER`, `KYC_VERIFIER`, `AML_ANALYST`, `SANCTIONS_MANAGER`
- `ORACLE`, `FACTOR`, `SELLER`, `BUYER`
- `EMERGENCY_ADMIN`, `PAUSER`

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
|--------|-----------|
| USA | BSA, USA PATRIOT Act §312/§319, OFAC, FATCA |
| EU | MiCA, 6th AML Directive (6AMLD), GDPR |
| Global | FATF Recommendations, UN Security Council sanctions, Basel III/IV |

**KYC Levels:** NONE → BASIC → STANDARD → ENHANCED → INSTITUTIONAL

**Sanctions Lists:** OFAC_SDN, OFAC_CONS, UN_SC, EU_CONS, UK_HMT

---

## Known Issues / Current State

See `docs/Surety-current-state.md` for the full handoff document. Key gaps as of 2026-03-27:

### Blockers (must fix before `forge build`)
1. **`LibDiamond.sol` is a stub** — needs full EIP-2535 diamond storage implementation
2. **`foundry.toml` missing** — Foundry cannot find project config
3. **`remappings.txt` missing** — imports will fail

### Structural Cleanup
4. **Loose `.sol` files in `fluid-compliance/` root** — old drafts that duplicate `src/` content; should be deleted
5. **`SuretyDiamond.sol` not fully wired** — needs to register all 10 facets on deploy

### Missing Components
6. **`OracleFacet.sol`** — interface exists (`IOracleFacet.sol`) but implementation missing
7. **Deployment script** — `script/Deploy.s.sol` needs to be created
8. **Test suite** — `test/` directory is empty; target 90%+ coverage per spec
9. **`fluid-compliance/README.md`** — project-level docs missing

---

## Priority Order for Next Work

1. Fix `LibDiamond.sol` (complete EIP-2535 implementation)
2. Create `foundry.toml` and `remappings.txt`
3. Wire all facets into `SuretyDiamond` constructor/init
4. Create `script/Deploy.s.sol`
5. Implement `OracleFacet.sol`
6. Write unit tests per facet (`test/*.t.sol`)
7. Write integration tests for cross-facet flows
8. Add fuzzing tests for risk scoring and invoice validation
9. Clean up loose files in `fluid-compliance/` root

---

## Git Workflow

- **Main branch:** `main`
- **Remote:** `fluidkiss1337-creator/Fluid-Innovation`
- Commit messages follow conventional commits: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`
- One logical change per commit
- Never commit private keys or `.env` files

---

## Documentation References

- `compliance-facets-specification.md` — Complete feature spec with business context
- `fluid-compliance/Surety Deployment Guide.md` — Full API reference and deployment steps
- `docs/Surety-current-state.md` — Current state handoff (most recent)
- `nikosys-IComplianceDiamond.txt` — Upstream interface reference
