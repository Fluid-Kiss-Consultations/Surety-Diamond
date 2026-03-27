# Surety — Current State

> Handoff document for incoming instance. Reflects repo state as of 2026-03-27.

---

## Repository

- **Repo:** `fluidkiss1337-creator/Fluid-Innovation` (private)
- **Branch:** `main`
- **Description:** Diamond Standard
- **Standard:** EIP-2535 Diamond Proxy
- **Project name in use:** Surety / fluid-compliance

---

## Root Structure

```
Fluid-Innovation/
├── fluid-compliance/          # Main project module
│   ├── src/
│   │   ├── diamond/           # Proxy + init contracts
│   │   ├── facets/            # All compliance facets
│   │   ├── interfaces/        # All Solidity interfaces
│   │   └── libraries/        # Shared storage + role libs
│   └── [loose files]         # Truncated first drafts — superseded by src/
├── docs/                      # This document lives here
├── README.md
├── compliance-facets-specification.md
└── .gitattributes
```

---

## `src/facets/` — Completed

| File | Purpose |
|---|---|
| `AMLFacet.sol` | FATF-compliant risk scoring and SAR filing |
| `AuditFacet.sol` | Hash-chained immutable audit trail |
| `DiamondCutFacet.sol` | Timelock-enforced upgrade scheduling |
| `DiamondLoupeFacet.sol` | Facet enumeration (EIP-2535 loupe) |
| `EmergencyFacet.sol` | Pause/unpause and timelocked emergency controls |
| `FATCACRSFacet.sol` | FATCA/CRS tax reporting and withholding logic |
| `InvoiceRegistryFacet.sol` | Double-factoring prevention and invoice registry |
| `JurisdictionFacet.sol` | Cross-border compliance and transaction routing |
| `KYCFacet.sol` | FATF-compliant KYC verification with Merkle doc proofs |
| `SanctionsFacet.sol` | Merkle-proof OFAC/SDN screening |

---

## `src/interfaces/` — Completed

| File | Purpose |
|---|---|
| `IDiamondCut.sol` | EIP-2535 cut interface |
| `IDiamondLoupe.sol` | EIP-2535 loupe interface |
| `IERC165.sol` | ERC-165 introspection interface |
| `IAMLFacet.sol` | AML function signatures |
| `IAuditFacet.sol` | Audit function signatures |
| `IEmergencyFacet.sol` | Emergency control signatures |
| `IFATCACRSFacet.sol` | FATCA/CRS function signatures |
| `IInvoiceRegistryFacet.sol` | Invoice registry signatures |
| `IJurisdictionFacet.sol` | Jurisdiction compliance signatures |
| `IKYCFacet.sol` | KYC function signatures |
| `IOracleFacet.sol` | Oracle facet signatures (scaffolded) |
| `ISanctionsFacet.sol` | Sanctions screening signatures |

---

## `src/libraries/` — Scaffolded

| File | Status |
|---|---|
| `LibDiamond.sol` | Scaffolded — needs full EIP-2535 storage impl |
| `LibAppStorage.sol` | Scaffolded — shared app storage struct |
| `LibRoles.sol` | Scaffolded — role-based access control |

---

## `src/diamond/` — Scaffolded

| File | Status |
|---|---|
| `SuretyDiamond.sol` | Scaffolded — main diamond proxy contract |
| `DiamondInit.sol` | Initialization logic — committed |

---

## Loose Files in `fluid-compliance/` Root

These are **truncated first drafts** marked with commit message `truncated first drafts`. They are superseded by the organized `src/` structure and should be reviewed for any content worth salvaging, then cleaned up or deleted.

Files: `AMLFacet.sol`, `AuditFacet.sol`, `DeploySurety.sol`, `EmergencyFacet.sol`, `FATCACRSFacet.sol`, `InvoiceRegistryFacet.sol`, `JurisdictionFacet.sol`, `KYCFacet.sol`, `LibAppStorage.sol`, `LibRoles.sol`, `OracleFacet.sol`, `SanctionsFacet.sol`, `SuretyDiamond.sol`, `SuretyDiamondTest.sol`, `handoff-cray-2.md`, `handoff-cray.txt`, `handoff.txt`, `Surety Deployment Guide.md`

---

## What Does Not Yet Exist

- `script/` — no deployment scripts committed under `src/`
- `test/` — no Foundry test files committed under `src/`
- `foundry.toml` — not present
- `remappings.txt` — not present
- `fluid-compliance/README.md` — not present
- `LibDiamond.sol`, `LibAppStorage.sol`, `LibRoles.sol` are scaffolded stubs, not production-ready
- `SuretyDiamond.sol` (in `src/diamond/`) is a scaffold — not wired to facets
- `OracleFacet.sol` facet implementation — only interface exists, no facet in `src/facets/`

---

## Known Structural Issue

There is a **duplicate file problem**: the root `fluid-compliance/` directory contains old loose `.sol` files that overlap with the organized `src/` subdirectory. These need to be reconciled — either deleted or migrated — before this project is buildable with Foundry.

---

## Next Priorities (in order)

1. Clean up / delete loose files in `fluid-compliance/` root
2. Flesh out `LibDiamond.sol` with full EIP-2535 diamond storage
3. Wire `SuretyDiamond.sol` proxy to facets via `DiamondInit.sol`
4. Add `OracleFacet.sol` implementation to `src/facets/`
5. Add `foundry.toml` and `remappings.txt`
6. Write deployment script (`script/Deploy.s.sol`)
7. Write Foundry tests (`test/`)
8. Add `fluid-compliance/README.md`
