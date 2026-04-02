# Surety by Fluid Kiss Consultations

[![CI](https://github.com/fluidkiss1337-creator/Surety-Diamond/actions/workflows/ci.yml/badge.svg)](https://github.com/fluidkiss1337-creator/Surety-Diamond/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Solidity](https://img.shields.io/badge/Solidity-%5E0.8.24-363636?logo=solidity)](https://soliditylang.org)
[![EIP-2535 Diamond](https://img.shields.io/badge/EIP--2535-Diamond%20Standard-brightgreen?logo=ethereum)](https://eips.ethereum.org/EIPS/eip-2535)
[![Built with Foundry](https://img.shields.io/badge/Built%20with-Foundry-FFDB1C)](https://book.getfoundry.sh)
[![Tests](https://img.shields.io/badge/Tests-186%20passing-brightgreen)]()
[![Facets](https://img.shields.io/badge/Facets-13-blue)]()
[![Selectors](https://img.shields.io/badge/Selectors-102-blue)]()

**On-chain compliance infrastructure for enterprise supply chain finance.**

Enterprise SCF platforms routing hundreds of billions in annual transactions across 80+ countries cannot treat compliance as an afterthought. KYC, AML, sanctions screening, FATCA/CRS tax reporting, double-factoring fraud prevention, and cross-border routing rules are each independently regulated, jurisdiction-specific, and subject to continuous change. A monolithic contract cannot hold them. A non-upgradeable contract cannot track them.

Surety is the infrastructure layer: a modular, upgradeable EIP-2535 Diamond proxy that enforces the full compliance lifecycle on-chain, with granular per-domain access control and a 48-hour upgrade timelock on every facet change.

---

## Facet Map

| Facet | Responsibility |
|-------|---------------|
| `KYCFacet` | FATF-compliant KYC verification, Merkle document proofs, PEP detection |
| `AMLFacet` | Risk scoring (0–1000 scale), SAR auto-filing, entity profiling |
| `SanctionsFacet` | OFAC / UN / EU / HMT Merkle-tree screening across 5 list types |
| `InvoiceRegistryFacet` | Invoice registry, double-factoring prevention, factoring agreements |
| `FATCACRSFacet` | FATCA/CRS classification, withholding calculation, reporting obligations |
| `JurisdictionFacet` | Cross-border routing, jurisdiction configuration, counterparty-pair blocking |
| `AuditFacet` | Hash-chained immutable audit trail with typed compliance events |
| `EmergencyFacet` | System pause/unpause, timelocked emergency upgrade scheduling |
| `OracleFacet` | Oracle registration, ECDSA-verified external data feeds |
| `UpgradeManagerFacet` | Storage layout validation, multi-sig upgrade proposals, upgrade history, rollback snapshots |
| `SecurityGuardFacet` | Rate limiting, circuit breaker auto-pause, threat registry, incident reporting, address blocking |
| `DiamondCutFacet` | Facet upgrades with 48-hour timelock (schedule → wait → execute) |
| `DiamondLoupeFacet` | EIP-2535 introspection, ERC-165 interface detection |

---

## Architecture

```
User / Protocol
      │
      ▼
SuretyDiamond  (EIP-2535 proxy)
      │  delegatecall  ·  function selector → facet address via LibDiamond routing table
      │
      ├─── KYCFacet
      ├─── AMLFacet
      ├─── SanctionsFacet
      ├─── InvoiceRegistryFacet
      ├─── FATCACRSFacet
      ├─── JurisdictionFacet
      ├─── AuditFacet
      ├─── EmergencyFacet
      ├─── OracleFacet
      ├─── UpgradeManagerFacet  (storage validation, multi-sig, rollback)
      ├─── SecurityGuardFacet   (rate limiting, circuit breaker, threats)
      ├─── DiamondCutFacet      (upgrades, 48-hour timelock)
      └─── DiamondLoupeFacet    (introspection)
                │
                ▼  (all facets share one storage slot)
      LibAppStorage  ·  slot: keccak256("surety.compliance.diamond.storage")
```

Facets never declare instance variables. Every read and write goes through `LibAppStorage.appStorage()`. The routing table is stored in a separate EIP-2535 diamond storage slot and is enumerable on-chain via `DiamondLoupeFacet`.

---

## Why Diamond Standard

Compliance logic is a poor fit for monolithic contracts. The Diamond Standard was chosen for specific structural reasons:

- **Contract size ceiling.** Full KYC + AML + sanctions + FATCA/CRS + invoice + oracle logic exceeds the 24KB EVM limit. Diamond removes this ceiling by distributing logic across independently deployable facets.
- **Regulatory change cadence.** Sanctions lists update daily. FATF recommendations revise every few years. OFAC typologies shift with geopolitical events. Timelocked upgradeable facets let compliance logic track regulation without redeploying the entire system.
- **Domain-isolated access control.** A KYC verifier should not hold AML analyst permissions. A sanctions manager should not touch invoice state. Diamond facets enforce per-domain roles with no shared admin key across domains.
- **Shared state, isolated logic.** All compliance data — KYC records, risk scores, sanctions Merkle roots, invoice registry, audit trail — lives in one storage layout. Facets cross-reference it without message calls or storage duplication.
- **On-chain auditability.** `DiamondLoupeFacet` exposes the full function-selector → facet-address routing table on-chain. Compliance auditors can enumerate every system entry point without access to deployment scripts or off-chain tooling.

---

## Regulatory Coverage

| Region | Frameworks |
|--------|----------|
| USA | BSA · USA PATRIOT Act §312/§319 · OFAC SDN & Consolidated · FATCA |
| EU | MiCA · 6th AML Directive (6AMLD) · GDPR |
| UK | HMT Financial Sanctions |
| Global | FATF Recommendations · UN Security Council Sanctions · Basel III/IV |

**Sanctions lists:** `OFAC_SDN` · `OFAC_CONS` · `UN_SC` · `EU_CONS` · `UK_HMT`

**KYC levels:** `NONE` → `BASIC` → `STANDARD` → `ENHANCED` → `INSTITUTIONAL`

---

## Quick Start

```bash
cd fluid-compliance
forge build
forge test        # all tests passing (see CI badge)
```

Full architecture documentation, facet reference, role table, and deployment instructions: [`fluid-compliance/README.md`](fluid-compliance/README.md)

---

## Specification

[`compliance-facets-specification.md`](compliance-facets-specification.md) — 52KB full feature specification covering each facet's business logic, access control model, event schema, and regulatory rationale.

---

## License

MIT License — Copyright (c) 2026 Fluid Kiss Consultations. See [`LICENSE`](LICENSE) for the full text.

---

## Fluid Kiss Consultations

Available for custom EIP-2535 Diamond architecture, implementation, and consultation.

**Contact:** fluidkiss1337@gmail.com
