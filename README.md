# Surety Diamond

## On-Chain Compliance Infrastructure for Global Supply Chain Finance

> Built by **Fluid Kiss Consultations** — a **Systems Oracle** full-consult engagement.

---

[![CI](https://github.com/fluidkiss1337-creator/Surety-Diamond/actions/workflows/ci.yml/badge.svg)](https://github.com/fluidkiss1337-creator/Surety-Diamond/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Solidity](https://img.shields.io/badge/Solidity-%5E0.8.24-363636?logo=solidity)](https://soliditylang.org)
[![EIP-2535 Diamond](https://img.shields.io/badge/EIP--2535-Diamond%20Standard-brightgreen?logo=ethereum)](https://eips.ethereum.org/EIPS/eip-2535)
[![Built with Foundry](https://img.shields.io/badge/Built%20with-Foundry-FFDB1C)](https://book.getfoundry.sh)
[![Foundry Tests](https://img.shields.io/badge/Tests-Passing-success?logo=github-actions)](https://github.com/fluidkiss1337-creator/Surety-Diamond/actions)
[![Solhint Lint](https://img.shields.io/badge/Lint-Solhint-informational?logo=npm)](https://protofire.github.io/solhint/)
[![Coverage](https://img.shields.io/badge/Coverage-Forge-blue?logo=codecov)](https://book.getfoundry.sh/reference/forge/forge-coverage)
[![Security Audit](https://img.shields.io/badge/Audit-14%20Findings%20Resolved-critical)](compliance-facets-specification.md)
[![Facets](https://img.shields.io/badge/Facets-13-blueviolet?logo=ethereum)](fluid-compliance/src/facets/)
[![Selectors](https://img.shields.io/badge/Selectors-103-blue)](fluid-compliance/src/facets/)
[![FATF Compliant](https://img.shields.io/badge/FATF-Compliant-green)](compliance-facets-specification.md)
[![OFAC Screening](https://img.shields.io/badge/OFAC-Sanctions%20Screening-red)](fluid-compliance/src/facets/SanctionsFacet.sol)
[![FATCA/CRS](https://img.shields.io/badge/FATCA%2FCRS-Tax%20Compliance-orange)](fluid-compliance/src/facets/FATCACRSFacet.sol)

---

## The Problem

Enterprise supply chain finance platforms process billions in cross-border payments across 80+ countries and 30+ currencies. Every transaction touches a web of overlapping regulatory regimes — FATF, OFAC, 6AMLD, FATCA, CRS, MiCA — each with its own KYC requirements, sanctions lists, tax withholding rules, and reporting obligations.

The compliance burden is staggering:

- **32+ compliance checks per transaction** across multiple jurisdictions
- **Double-factoring fraud** — the same invoice pledged to multiple financiers
- **Sanctions violations** carrying criminal penalties and reputational collapse
- **Tax authority reporting** across FATCA and CRS with conflicting classification schemes
- **Audit trail requirements** that demand tamper-proof, regulator-accessible records

Traditional compliance stacks are fragmented, manual, and brittle. They don't scale. They don't compose. They can't be audited on-chain.

**We were asked to fix that.**

---

## What We Built

Surety Diamond is a modular, upgradeable smart contract system that moves compliance infrastructure on-chain using the **EIP-2535 Diamond Standard**. Every compliance domain — KYC, AML, sanctions, tax, invoicing, audit — lives in its own independently upgradeable facet, sharing unified storage through a single proxy.

```
User / Protocol
      |
      v
SuretyDiamond (EIP-2535 proxy)
      |  delegatecall
      |
      +--- KYCFacet               FATF-aligned identity verification
      +--- AMLFacet               Risk scoring (0-1000), SAR auto-filing
      +--- SanctionsFacet         OFAC/UN/EU/UK Merkle-proof screening
      +--- InvoiceRegistryFacet   Double-factoring prevention
      +--- FATCACRSFacet          Tax classification and withholding
      +--- JurisdictionFacet      Multi-jurisdiction regulatory routing
      +--- AuditFacet             Hash-chained immutable audit trail
      +--- OracleFacet            ECDSA-verified external data feeds
      +--- EmergencyFacet         System pause and emergency upgrades
      +--- UpgradeManagerFacet    Multi-sig governance with rollback
      +--- SecurityGuardFacet     Rate limiting and circuit breaker
      +--- DiamondCutFacet        48-hour timelocked upgrades
      +--- DiamondLoupeFacet      On-chain introspection (EIP-2535)
      |
      v  (shared state)
LibAppStorage  (deterministic slot: keccak256("surety.compliance.diamond.storage"))
```

![Modular On-Chain Compliance Matrix](Modular%20On-Chain%20Compliance%20Matrix%20(1).png)

---

## By the Numbers

| Metric | Value |
| --- | --- |
| **Facets** | 13 — each a self-contained compliance domain |
| **Function Selectors** | 103 routed through the diamond proxy |
| **Events** | 59 — every state change emits an auditable record |
| **Interfaces** | 14 — full NatSpec-documented API surface |
| **Role Types** | 15 — granular RBAC from admin to buyer |
| **Test Files** | 17 — unit, integration, fuzz, and selector verification |
| **Production Solidity** | 4,772 lines |
| **Sanctions Lists** | 6 — OFAC SDN, OFAC Consolidated, UN SC, EU, UK HMT, Custom |
| **KYC Tiers** | 5 — None through Institutional |
| **Upgrade Timelock** | 48 hours mandatory — no unilateral changes |

---

## Compliance Domains

### KYC — Know Your Customer

FATF-aligned verification across five tiers (BASIC through INSTITUTIONAL). Merkle-proof document verification. PEP detection. Auto-expiry at 365 days with renewal workflows. Full lifecycle tracking: PENDING, APPROVED, REJECTED, EXPIRED, SUSPENDED, UNDER_REVIEW.

### AML — Anti-Money Laundering

Real-time transaction risk scoring on a 0-1000 scale. Automatic SAR filing for high-risk transactions exceeding $10,000. PEP involvement escalates risk by +200 points. Unverified entities add +300. Large transactions add +100. Entity-level risk profiles with escalation support.

### Sanctions Screening

Gas-efficient Merkle-proof verification against six global sanctions lists. Potential match detection at 75% confidence. False positive clearance with documented reasons. Oracle-integrated list root updates. Covers OFAC SDN, OFAC Consolidated, UN Security Council, EU Consolidated, UK HMT, and custom lists.

### Invoice Registry & Supply Chain Finance

On-chain invoice registration with cryptographic double-factoring prevention. ECDSA signature verification for seller/buyer attestation. Factoring agreement lifecycle from PENDING through SETTLED or DEFAULTED. Advance rates enforced at 1-95%. Payment recording and dispute handling.

### FATCA/CRS — International Tax Compliance

Eight FATCA classification types. Six CRS entity categories. Tax form management (W-8BEN, W-8BEN-E, W-9, W-8IMY) with jurisdiction-specific expiry. Withholding rate assessment (US 30%, backup 24%). Cross-border reporting obligation tracking with configurable thresholds.

### Multi-Jurisdiction Routing

Per-jurisdiction compliance configuration: minimum KYC levels, transaction limits, enhanced due diligence thresholds, withholding rates. Cross-border pair assessment. Ability to block specific jurisdiction pairs outright.

### Audit Trail

Hash-chained immutable log with 19 event types spanning KYC, AML, sanctions, invoicing, tax, and system operations. Chain verification for tamper detection. Entity-level audit retrieval with time and event-type filtering. Built for regulator inspection.

---

## Security Architecture

This system protects high-value financial flows. Security is not an afterthought — it's a design constraint.

**Upgrade Governance** — 48-hour mandatory timelock on all diamond cuts. Multi-sig approval with configurable threshold. Pre-upgrade snapshots for rollback reference. Storage layout validation before execution.

**Rate Limiting** — Per-selector, per-address sliding window limits on sensitive operations. Configurable call caps and time windows.

**Circuit Breaker** — Auto-pause when security incidents exceed threshold within a configured window. Prevents cascade failures during active attack.

**Threat Registry** — Severity-graded threat indicators (LOW through CRITICAL). CRITICAL incidents auto-block offending addresses. Security incident history per entity.

**Access Control** — 15 role types with hierarchical admin structure. Every state-changing function is role-gated. Bootstrap bypass is single-use during initialization only.

**Reentrancy Protection** — Guard on all sensitive state-changing operations.

**Custom Errors** — Gas-efficient revert handling. No string messages.

---

## Regulatory Coverage

| Region | Frameworks Addressed |
| --- | --- |
| **United States** | Bank Secrecy Act (BSA), USA PATRIOT Act (Sections 312, 319), OFAC Sanctions Programs, FATCA |
| **European Union** | MiCA, 6th Anti-Money Laundering Directive (6AMLD), GDPR considerations |
| **United Kingdom** | HM Treasury Financial Sanctions |
| **Global** | FATF Recommendations, UN Security Council Sanctions, Basel III/IV Capital Requirements, CRS |

---

## Why Diamond Standard

The EIP-2535 Diamond pattern was chosen deliberately. Compliance requirements change with every regulatory update, sanctions designation, and jurisdictional shift. A monolithic contract cannot keep pace.

- **Modular upgrades** — Update AML scoring without touching KYC or sanctions
- **No size ceiling** — 13 facets worth of compliance logic would exceed the 24KB contract limit many times over
- **Granular access control** — Different permission models per compliance domain
- **Regulator introspection** — DiamondLoupe provides full on-chain transparency into system capabilities
- **Storage efficiency** — Single shared storage slot eliminates cross-contract coordination

---

## The Engagement

This repository represents a **Systems Oracle** full-consult delivery — from specification through implementation, security remediation, and deployment preparation.

**Scope delivered:**

- 52KB compliance specification mapping business requirements to smart contract architecture
- Complete EIP-2535 Diamond implementation with 13 facets
- 14 security findings identified and resolved (2 Critical, 4 High, 3 Medium, 4 Low, 1 Informational)
- Full test suite with unit, integration, and fuzz coverage
- Deployment automation with selector verification
- Technical documentation and API reference

**What this demonstrates:**

- Deep fluency in EIP-2535 Diamond architecture and delegatecall storage patterns
- Regulatory domain expertise across FATF, OFAC, FATCA/CRS, 6AMLD, and MiCA
- Security-first development — timelocked upgrades, circuit breakers, hash-chained audit, multi-sig governance
- Production-grade engineering — custom errors, NatSpec documentation, role-based access on every function, Foundry toolchain

---

## Work With Us

**Fluid Kiss Consultations** delivers Systems Oracle full-consult engagements for teams building on-chain infrastructure that intersects with real-world regulatory requirements.

**What we do:**

- EIP-2535 Diamond Standard architecture, implementation, and upgrade governance
- On-chain compliance systems — KYC/AML, sanctions, tax, audit
- Smart contract security review and remediation
- Specification-to-deployment pipeline for complex Solidity systems

**If your protocol touches compliance, jurisdictions, or regulated finance — we should talk.**

**Contact:** [john.welch@fluidsoulutions.store](mailto: john.welch@fluidsolutions.store)

---

## Repository Structure

```
Surety-Diamond/
+-- fluid-compliance/              Foundry project root
|   +-- src/
|   |   +-- diamond/               EIP-2535 proxy and initializer
|   |   +-- facets/                13 facet contracts
|   |   +-- interfaces/            14 Solidity interfaces
|   |   +-- libraries/             Shared storage, roles, diamond mechanics
|   +-- test/                      17 test files (unit, integration, fuzz)
|   +-- script/                    Deployment automation
|   +-- foundry.toml
|   +-- remappings.txt
+-- compliance-facets-specification.md   Full feature specification
+-- CLAUDE.md                            AI assistant context
+-- README.md                            This file
```

---

## Quick Start

```bash
cd fluid-compliance

# Build
forge build

# Test
forge test -vvv

# Coverage
forge coverage
```

> Requires: [Foundry](https://getfoundry.sh), Solidity ^0.8.24

---

*Surety Diamond is open source under the MIT License.*
