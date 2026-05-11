# Evidence-as-Code

**Run a Prowler scan. Get a filled CAIQ.**

Automates CSA CCM v4.0 compliance evidence collection for AWS, Azure, and Oracle Cloud. Maps Prowler findings to CAIQ v4.0.3 answers automatically. Flags what's manual. Ships an artifact.

Built by [Kascade Security](https://kascade.security).

---

## How It Works

```
prowler aws --compliance csa_ccm_4.0_aws -M csv
    ↓
caiq_autofill.py --scan output.csv --template CAIQv4.0.3.xlsx
    ↓
CAIQ_filled_20260516.csv  ← hand this to your auditor
```

- **Automated controls** → answered Yes/No with evidence citations from the scan
- **Policy controls** → marked Partial with specific documentation requirements
- **OCI controls** → normalized from OCI-specific IDs to standard CCM IDs

## Quickstart

```bash
# Install dependencies
pip install pandas openpyxl prowler

# Run a scan (AWS example)
prowler aws --compliance csa_ccm_4.0_aws --output-directory ./output -M csv

# Fill the CAIQ
# Download the CAIQ template from: https://cloudsecurityalliance.org/star/registry/documentation
python3 caiq_autofill.py \
  --scan ./output/<your_scan>_csa_ccm_4.0_aws.csv \
  --template CAIQv4.0.3_STAR-Security-Questionnaire.xlsx
```

## What You Get

```
Output: CAIQ_filled_20260516_143022.csv
  Automated — Pass : 22
  Automated — Fail : 17
  Manual review    : 48
  Total filled     : 87
```

Open in Excel or LibreOffice. The manual review items tell you exactly what documentation is required before submission.

## Framework Files

The `frameworks/` directory contains audited Prowler compliance framework definitions:

| File | Provider | Controls | Check Mappings |
|------|----------|----------|----------------|
| `csa_ccm_4.0_aws.json` | AWS | 197 | 129 |
| `csa_ccm_4.0_azure.json` | Azure | 130 | 367 |
| `csa_ccm_4.0_oci.json` | Oracle Cloud | 15 | 15 |

Use with Prowler's `--compliance` flag or as custom framework definitions.

## CCM Domain Coverage (AWS)

| Domain | Automated Checks |
|--------|-----------------|
| CEK — Cryptography & Key Mgmt | 38 |
| DSP — Data Security & Privacy | 18 |
| IAM — Identity & Access Mgmt | 16 |
| BCR — Business Continuity | 10 |
| LOG — Logging & Monitoring | 9 |
| IVS — Infrastructure & Virtualization | 9 |
| TVM — Threat & Vulnerability Mgmt | 7 |
| DCS — Datacenter Security | 7 |

## Requirements

- Python 3.9+
- `pandas`, `openpyxl`
- [Prowler](https://github.com/prowler-cloud/prowler) (for running scans)
- CAIQ v4.0.3 Excel template ([download from CSA](https://cloudsecurityalliance.org/star/registry/documentation))

## What This Doesn't Replace

Policy controls — governance documentation, HR procedures, physical security, DPIAs, sub-processor agreements — require human attestation. This tool marks every one of them with a clear description of what's needed. Your compliance team handles those. This handles the rest.

## Full Pipeline (TitanGuard)

This tool is the open-source core of [TitanGuard](https://kascade.security), which adds:
- Multi-cloud scan orchestration
- LLM-generated remediation for every failed control
- Continuous evidence collection (not annual)
- Exportable audit bundles with timestamped artifacts
- HIPAA and SOC 2 coverage alongside CSA STAR

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Contributing

PRs welcome. If you find a Prowler check ID that's wrong, missing, or broken — open an issue.
