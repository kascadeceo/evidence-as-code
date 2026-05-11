#!/usr/bin/env bash
# Run a Prowler CSA CCM v4.0 scan and generate a filled CAIQ
#
# Prerequisites:
#   pip install prowler
#   AWS credentials configured (aws configure or environment variables)
#
# Usage:
#   bash examples/run_scan.sh

set -e

PROVIDER="${1:-aws}"
OUTPUT_DIR="./output"
mkdir -p "$OUTPUT_DIR"

echo "Running Prowler CSA CCM v4.0 scan for provider: $PROVIDER"
echo "Output directory: $OUTPUT_DIR"
echo ""

# Run Prowler with CSA CCM compliance framework
# -M csv generates the compliance CSV needed by caiq_autofill.py
prowler "$PROVIDER" \
  --compliance "csa_ccm_4.0_${PROVIDER}" \
  --output-directory "$OUTPUT_DIR" \
  -M csv

echo ""
echo "Scan complete. Finding compliance CSV..."
SCAN_CSV=$(ls -t "$OUTPUT_DIR"/*csa_ccm*.csv 2>/dev/null | head -1)

if [ -z "$SCAN_CSV" ]; then
  echo "Error: No CSA CCM compliance CSV found in $OUTPUT_DIR"
  exit 1
fi

echo "Found: $SCAN_CSV"
echo ""
echo "To fill your CAIQ, run:"
echo "  python3 caiq_autofill.py --scan \"$SCAN_CSV\" --template CAIQv4.0.3.xlsx"
echo ""
echo "Download the CAIQ template from:"
echo "  https://cloudsecurityalliance.org/star/registry/documentation"
