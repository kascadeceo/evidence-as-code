# Evidence-as-Code

Compliance evidence should work like software: automated, versioned, and always current.
Not assembled by hand every 12 months during audit season.

## The Problem

Most cloud compliance programs run on a manual loop:
1. Auditor requests evidence
2. Engineers pull logs, screenshots, and config exports by hand
3. Someone assembles a spreadsheet
4. The evidence is stale before the auditor opens it
5. Repeat next year

This isn't a security program. It's a documentation program with a security theme.

## The Approach

**Automate the collection.** Prowler scans your cloud environment and maps every
finding to a compliance control. No human in the loop for the technical checks.

**Normalize the output.** Every finding maps to CSA CCM v4.0 controls. The same
scan covers HIPAA, SOC 2, and CSA STAR simultaneously with the right framework files.

**Flag what's manual.** Policy controls — governance, HR, physical security — can't
be automated. The tool marks them clearly so humans know exactly what needs attestation.
No false passes, no silent gaps.

**Ship an artifact.** The output is a filled CAIQ ready to submit. Not a dashboard.
Not a score. An actual compliance artifact an auditor can verify.

## CCM Control Coverage (AWS)

| Domain | Automated Checks |
|--------|-----------------|
| CEK (Cryptography & Key Mgmt) | 38 |
| DSP (Data Security & Privacy) | 18 |
| IAM (Identity & Access Mgmt) | 16 |
| BCR (Business Continuity) | 10 |
| LOG (Logging & Monitoring) | 9 |
| IVS (Infrastructure & Virtualization) | 9 |
| TVM (Threat & Vulnerability Mgmt) | 7 |
| DCS (Datacenter Security) | 7 |
| AIS (Application & Interface Security) | 4 |
| + 8 more domains | varies |

Azure coverage is broader: 367 check mappings across 104 controls.

## What Requires Human Attestation

The following control domains are policy-based and cannot be fully automated:

- **A&A** — Audit policies and independent assessment processes
- **BCR** — Business continuity strategy and disaster response plans
- **CCC** — Change management policies and approval processes
- **CEK** — Cryptography governance policies (key lifecycle procedures)
- **DCS** — Physical datacenter security (equipment disposal, cabling)
- **DSP** — Data protection policies, DPIAs, sub-processor agreements
- **GRC** — Governance framework, ERM program, regulatory mapping
- **HRS** — HR security, background screening, termination procedures
- **IPY** — Portability and interoperability assessments
- **UEM** — Endpoint management policies

The tool marks every one of these as `Partial` with a specific description of
what documentation is required. Your compliance team handles the attestation.
The tool handles the rest.

## Framework Files

The `frameworks/` directory contains audited Prowler compliance framework files:

- `csa_ccm_4.0_aws.json` — 197 controls, 129 check mappings
- `csa_ccm_4.0_azure.json` — 130 controls, 367 check mappings
- `csa_ccm_4.0_oci.json` — 15 OCI-specific controls

Use these with Prowler's `--compliance` flag or as custom framework files.

## Principle

Start with one control. Automate it completely. Ship the rest.

The goal isn't a perfect compliance score. It's a compliance program that runs
continuously, catches real problems before auditors do, and produces artifacts
that mean something because they reflect actual system state — not what someone
typed into a spreadsheet at 11pm before the audit.
