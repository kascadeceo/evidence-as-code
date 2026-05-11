#!/usr/bin/env python3
"""
evidence-as-code: CAIQ Auto-Fill
Kascade Security — https://kascade.security

Takes a Prowler CSA CCM compliance CSV and fills a CAIQ v4.0.3 Excel template
automatically. Manual-review controls are flagged. Automated controls are
answered Yes/No based on actual scan results with evidence citations.

Usage:
    python3 caiq_autofill.py --scan <prowler_output.csv> --template <CAIQv4.0.3.xlsx>

Requirements:
    pip install pandas openpyxl

Prowler scan command (AWS example):
    prowler aws --compliance csa_ccm_4.0_aws -M csv
"""

import pandas as pd
import os
import sys
import glob
import argparse
from datetime import datetime


# OCI-specific control IDs → standard CCM control IDs
OCI_TO_CCM_MAPPING = {
    "IAM-O1-OCI": "IAM-01",
    "IAM-O2-OCI": "IAM-01",
    "IAM-O3-OCI": "IAM-01",
    "IAM-O7-OCI": "IAM-07",
    "IAM-O10-OCI": "IAM-01",
    "IAM-O12-OCI": "IAM-02",
    "IAM-O13-OCI": "IAM-02",
    "LOG-O3-OCI": "LOG-01",
    "LOG-O4-OCI": "SEF-02",
    "LOG-O10-OCI": "LOG-01",
    "LOG-O11-OCI": "LOG-01",
    "LOG-O12-OCI": "LOG-01",
    "DCS-O1-OCI": "IAM-01",
    "DCS-O12-OCI": "IAM-01",
    "TVM-O1-OCI": "TVM-01",
}

# Related control proxy lookups — use evidence from related controls
# when a control has no direct automated checks
RELATED_CONTROL_MAPPINGS = {
    "IAM-04": ["IAM-02"],
    "IAM-05": ["IAM-02"],
    "LOG-01": ["LOG-04"],
    "TVM-02": ["TVM-01"],
    "TVM-03": ["TVM-01"],
}

# Policy-based controls that require manual attestation
# These cannot be fully automated — they need human documentation
MANUAL_REVIEW_DEFAULTS = {
    "A&A-01": "MANUAL REVIEW: Audit policies must be reviewed and approved by management. See organizational audit policy documentation.",
    "A&A-02": "MANUAL REVIEW: Independent assessments must be conducted annually. See audit reports.",
    "A&A-03": "MANUAL REVIEW: Risk-based audit planning documentation required.",
    "A&A-04": "MANUAL REVIEW: Compliance verification against standards required.",
    "A&A-05": "MANUAL REVIEW: Audit management process documentation required.",
    "A&A-06": "MANUAL REVIEW: Corrective action process documentation required.",
    "BCR-02": "MANUAL REVIEW: Business continuity risk assessment criteria documentation required.",
    "CCC-01": "MANUAL REVIEW: Change control policy documentation required.",
    "CCC-02": "MANUAL REVIEW: Configuration management process documentation required.",
    "CCC-03": "MANUAL REVIEW: Change approval process documentation required.",
    "CCC-04": "MANUAL REVIEW: Emergency change procedures documentation required.",
    "CCC-05": "MANUAL REVIEW: Configuration baseline documentation required.",
    "CCC-06": "MANUAL REVIEW: Change testing procedures documentation required.",
    "CCC-07": "MANUAL REVIEW: Rollback procedures documentation required.",
    "CCC-08": "MANUAL REVIEW: Configuration audit procedures documentation required.",
    "CEK-01": "MANUAL REVIEW: Cryptography policy documentation required.",
    "CEK-05": "MANUAL REVIEW: Key change management procedures documentation required.",
    "CEK-06": "MANUAL REVIEW: Cost-benefit analysis for encryption required.",
    "CEK-07": "MANUAL REVIEW: Key risk assessment documentation required.",
    "CEK-11": "MANUAL REVIEW: Key purpose classification documentation required.",
    "CEK-15": "MANUAL REVIEW: Key activation procedures documentation required.",
    "CEK-16": "MANUAL REVIEW: Key suspension procedures documentation required.",
    "CEK-17": "MANUAL REVIEW: Key deactivation procedures documentation required.",
    "CEK-18": "MANUAL REVIEW: Key archival procedures documentation required.",
    "CEK-20": "MANUAL REVIEW: Key recovery procedures documentation required.",
    "DCS-01": "MANUAL REVIEW: Equipment disposal procedures documentation required.",
    "DCS-12": "MANUAL REVIEW: Physical cabling security documentation required.",
    "DSP-01": "MANUAL REVIEW: Data security policy documentation required.",
    "DSP-06": "MANUAL REVIEW: Data ownership documentation required.",
    "DSP-09": "MANUAL REVIEW: Data Protection Impact Assessment documentation required.",
    "DSP-11": "MANUAL REVIEW: Personal data access/deletion procedures documentation required.",
    "DSP-12": "MANUAL REVIEW: Purpose limitation procedures documentation required.",
    "DSP-13": "MANUAL REVIEW: Sub-processor documentation required.",
    "DSP-14": "MANUAL REVIEW: Sub-disclosure documentation required.",
    "DSP-15": "MANUAL REVIEW: Production data use procedures documentation required.",
    "DSP-18": "MANUAL REVIEW: Breach notification procedures documentation required.",
    "GRC-01": "MANUAL REVIEW: Governance framework documentation required.",
    "GRC-02": "MANUAL REVIEW: Risk management framework documentation required.",
    "GRC-03": "MANUAL REVIEW: Compliance monitoring procedures documentation required.",
    "GRC-04": "MANUAL REVIEW: Regulatory requirements documentation required.",
    "GRC-06": "MANUAL REVIEW: Internal audit procedures documentation required.",
    "GRC-07": "MANUAL REVIEW: Third-party risk management procedures documentation required.",
    "GRC-08": "MANUAL REVIEW: Legal review procedures documentation required.",
    "HRS-01": "MANUAL REVIEW: HR security procedures documentation required.",
    "HRS-02": "MANUAL REVIEW: Employee acceptable use procedures documentation required.",
    "HRS-03": "MANUAL REVIEW: Clean desk policy documentation required.",
    "HRS-04": "MANUAL REVIEW: Remote working policy documentation required.",
    "HRS-05": "MANUAL REVIEW: Asset return procedures documentation required.",
    "HRS-07": "MANUAL REVIEW: Employment agreement process documentation required.",
    "HRS-08": "MANUAL REVIEW: Employment agreement content documentation required.",
    "HRS-09": "MANUAL REVIEW: Personnel roles documentation required.",
    "HRS-10": "MANUAL REVIEW: Non-disclosure agreement procedures documentation required.",
    "HRS-11": "MANUAL REVIEW: Security awareness training documentation required.",
    "HRS-12": "MANUAL REVIEW: Sensitive data awareness training documentation required.",
    "HRS-13": "MANUAL REVIEW: Compliance responsibility documentation required.",
    "IPY-01": "MANUAL REVIEW: Portability assessment documentation required.",
    "IPY-02": "MANUAL REVIEW: Data format documentation required.",
    "IPY-03": "MANUAL REVIEW: Interoperability testing documentation required.",
    "IVS-01": "MANUAL REVIEW: Infrastructure security policy documentation required.",
    "IVS-08": "MANUAL REVIEW: High-risk environment documentation required.",
    "LOG-02": "MANUAL REVIEW: Audit log protection procedures documentation required.",
    "LOG-08": "MANUAL REVIEW: Audit record generation procedures documentation required.",
    "UEM-02": "MANUAL REVIEW: Endpoint security procedures documentation required.",
    "UEM-03": "MANUAL REVIEW: Asset management procedures documentation required.",
    "UEM-04": "MANUAL REVIEW: Endpoint configuration procedures documentation required.",
    "UEM-05": "MANUAL REVIEW: Software update procedures documentation required.",
    "UEM-06": "MANUAL REVIEW: Endpoint monitoring procedures documentation required.",
    "UEM-07": "MANUAL REVIEW: Endpoint incident response procedures documentation required.",
    "UEM-08": "MANUAL REVIEW: Endpoint disposal procedures documentation required.",
    "UEM-09": "MANUAL REVIEW: BYOD policy documentation required.",
    "UEM-10": "MANUAL REVIEW: Mobile device management procedures documentation required.",
    "UEM-11": "MANUAL REVIEW: Remote access procedures documentation required.",
    "UEM-12": "MANUAL REVIEW: Container security procedures documentation required.",
    "UEM-13": "MANUAL REVIEW: Serverless security procedures documentation required.",
    "UEM-14": "MANUAL REVIEW: Microservices security procedures documentation required.",
}


def normalize_ccm_id(requirement_id: str) -> str:
    return OCI_TO_CCM_MAPPING.get(requirement_id, requirement_id)


def detect_provider(csv_path: str) -> str:
    path_lower = csv_path.lower()
    if "_aws" in path_lower:
        return "AWS"
    elif "_azure" in path_lower:
        return "Azure"
    elif "_oraclecloud" in path_lower or "_oci" in path_lower:
        return "Oracle Cloud"
    elif "_gcp" in path_lower:
        return "GCP"
    return "Unknown"


def main():
    parser = argparse.ArgumentParser(
        description="Auto-fill a CAIQ v4.0.3 template from a Prowler CSA CCM compliance scan."
    )
    parser.add_argument("--scan", required=True, help="Path to Prowler CSA CCM compliance CSV (semicolon-delimited)")
    parser.add_argument("--template", required=True, help="Path to CAIQ v4.0.3 Excel template (.xlsx)")
    parser.add_argument("--output", default=None, help="Output filename (default: CAIQ_filled_<timestamp>.csv)")
    args = parser.parse_args()

    if not os.path.exists(args.scan):
        print(f"Error: Scan file not found: {args.scan}")
        sys.exit(1)
    if not os.path.exists(args.template):
        print(f"Error: Template file not found: {args.template}")
        sys.exit(1)

    provider = detect_provider(args.scan)
    print(f"Evidence-as-Code CAIQ Autofill")
    print(f"Provider: {provider} | Scan: {args.scan}")
    print()

    # Load scan evidence
    try:
        df_evidence = pd.read_csv(args.scan, sep=';')
        df_evidence.columns = [c.upper() for c in df_evidence.columns]
        print(f"Loaded {len(df_evidence)} compliance records from scan.")
    except Exception as e:
        print(f"Error reading scan CSV: {e}")
        sys.exit(1)

    # Load CAIQ template
    try:
        xls = pd.ExcelFile(args.template)
        sheet_name = [s for s in xls.sheet_names if 'CAIQ' in s][0]
        df_caiq = pd.read_excel(xls, sheet_name=sheet_name, header=1)
        print(f"Loaded CAIQ template: sheet '{sheet_name}'")
    except Exception as e:
        print(f"Error reading CAIQ template: {e}")
        sys.exit(1)

    if 'CSP CAIQ Answer' in df_caiq.columns:
        df_caiq['CSP CAIQ Answer'] = df_caiq['CSP CAIQ Answer'].astype(object)
    if 'CSP Implementation Description (Optional/Recommended)' in df_caiq.columns:
        df_caiq['CSP Implementation Description (Optional/Recommended)'] = \
            df_caiq['CSP Implementation Description (Optional/Recommended)'].astype(object)

    # Normalize OCI control IDs
    df_evidence['CCM_ID'] = df_evidence['REQUIREMENTS_ID'].apply(normalize_ccm_id)

    fill_count = 0
    yes_count = 0
    no_count = 0
    manual_count = 0

    for index, row in df_caiq.iterrows():
        question_id = str(row.get('Question ID', ''))
        if not question_id or pd.isna(question_id) or question_id == 'nan':
            continue

        if '-' not in question_id:
            continue

        control_root = question_id.split('.')[0]

        # Step 1: Direct match
        relevant_evidence = df_evidence[df_evidence['CCM_ID'] == control_root]

        # Step 2: Related control proxy
        if relevant_evidence.empty and control_root in RELATED_CONTROL_MAPPINGS:
            for related in RELATED_CONTROL_MAPPINGS[control_root]:
                proxy = df_evidence[df_evidence['CCM_ID'] == related]
                if not proxy.empty:
                    relevant_evidence = proxy
                    break

        # Step 3: Apply evidence
        if not relevant_evidence.empty:
            failures = relevant_evidence[relevant_evidence['STATUS'] == 'FAIL']

            if not failures.empty:
                answer = "No"
                no_count += 1
                comment = "FAILURES DETECTED:\n"
                for i, fail_row in failures.head(5).iterrows():
                    status_text = str(fail_row.get('STATUSEXTENDED', 'Check failed')).replace('\n', ' ')
                    resource = str(fail_row.get('RESOURCENAME', 'Unknown'))
                    comment += f"- {status_text} ({resource})\n"
                if len(failures) > 5:
                    comment += f"...and {len(failures) - 5} more findings."
            else:
                answer = "Yes"
                yes_count += 1
                comment = "VERIFIED:\n"
                for i, pass_row in relevant_evidence.head(3).iterrows():
                    status_text = str(pass_row.get('STATUSEXTENDED', 'Check passed')).replace('\n', ' ')
                    resource = str(pass_row.get('RESOURCENAME', ''))
                    comment += f"- {status_text} ({resource})\n"

            df_caiq.at[index, 'CSP CAIQ Answer'] = answer
            df_caiq.at[index, 'CSP Implementation Description (Optional/Recommended)'] = comment.strip()
            fill_count += 1

        # Step 4: Manual review defaults
        elif control_root in MANUAL_REVIEW_DEFAULTS:
            manual_text = MANUAL_REVIEW_DEFAULTS[control_root]
            answer = "Partial"
            manual_count += 1
            df_caiq.at[index, 'CSP CAIQ Answer'] = answer
            df_caiq.at[index, 'CSP Implementation Description (Optional/Recommended)'] = manual_text
            fill_count += 1

    # Save output
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = args.output or f"CAIQ_filled_{timestamp}.csv"
    df_caiq.to_csv(output_file, index=False, encoding='utf-8-sig')

    print()
    print(f"Output: {output_file}")
    print(f"  Automated — Pass : {yes_count}")
    print(f"  Automated — Fail : {no_count}")
    print(f"  Manual review    : {manual_count}")
    print(f"  Total filled     : {fill_count}")
    print()
    print("Open in Excel or LibreOffice Calc.")
    print("Manual review items require human attestation before submission.")


if __name__ == "__main__":
    main()
