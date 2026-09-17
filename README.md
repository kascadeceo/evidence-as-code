# Evidence-as-Code — a working sample

Your cloud already exposes evidence about access, encryption, logging, and configuration through read-only APIs. This repository shows how to collect that evidence like code: structured, reviewable, diffable, and independently verifiable.

This is intentionally thin teaching code from [Kascade Security](https://kascadesecurity.com). It demonstrates the workflow without publishing the platform that generates and manages evidence at scale.

## 1. Run one scanner with structured output, on a schedule

Use read-only credentials, run nightly, and retain the structured JSON. Committing or otherwise versioning each scan creates evidence history that screenshots cannot provide.

Start with [`examples/run_scan.sh`](examples/run_scan.sh). Review the script and scope its credential before running it in your environment.

Scan engine attribution: [Prowler](https://github.com/prowler-cloud/prowler) is the open-source scanner used by the example script (Apache-2.0).

## 2. Read the compliance metadata already in your findings

Do not rebuild a framework dictionary for every engagement. Start with the metadata carried by the findings, choose one framework, then allow-list only the mappings your team agrees with.

[`mappings/`](mappings/) contains deliberately small HIPAA and SOC 2 samples with source and license information. They are examples, not complete crosswalks or audit advice.

## 3. Diff today against yesterday and alert on it

```bash
python3 drift_diff.py yesterday.json today.json
```

The tool prints each new failure. Exit 1 is the alert hook, exit 0 means no new failures, and exit 2 means the input could not be read. Machine-readable output is available with `--json`.

```bash
python3 drift_diff.py --json yesterday.json today.json
```

## 4. Verify an evidence bundle

```bash
python3 verify.py examples/evidence-bundle
```

The verifier checks every provenance record, every link in the SHA-256 chain, and the current artifacts listed by the latest record. It uses only the Python standard library.

Try the tamper case on a disposable copy:

```bash
cp -r examples/evidence-bundle /tmp/evidence-bundle
echo >> /tmp/evidence-bundle/ssp.md
python3 verify.py /tmp/evidence-bundle
```

The second command reports `artifact_altered` and exits 1. The bundle is synthetic and contains no customer data.

## 5. Draft a CAIQ from scan evidence

The original sample remains available:

```bash
python3 caiq_autofill.py \
  --scan ./output/scan_csa_ccm_4.0_aws.csv \
  --template CAIQv4.0.3_STAR-Security-Questionnaire.xlsx
```

It produces a draft, not a submission. Evidence-backed answers are cited; questions the scan cannot prove remain marked for review. The CSA template is not redistributed here.

## What is public here, and what remains in the platform

| This repository | Kascade platform |
|---|---|
| Verify a supplied evidence bundle | Generate and retain evidence bundles continuously |
| Diff two supplied scans | Detect and route drift across fleets and tenants |
| Review small, sourced mapping samples | Normalize and map evidence across multiple clouds and frameworks |
| Draft one CAIQ from a scan | Generate governed SSP and POA&M artifacts with full provenance |

The dividing line is generation and operation at scale. Verification and a small two-scan diff are public so anyone can inspect the core idea. Collection, normalization, cross-cloud mapping, bundle generation, and fleet operations remain platform capabilities.

## Honest scope

- A cloud scan cannot assess documentation, process, or human behavior.
- An unanswered control is never a pass.
- A mapping is a reviewable claim, not automatic truth.
- Verification proves whether the supplied chain and current artifacts agree; it does not prove the underlying control was designed correctly.
- Nothing here writes to your cloud.

## Test locally

```bash
python3 -m unittest discover -s tests -v
python3 tools/sanitize_check.py
```

The public examples and tools require Python 3.10 or newer and use only the standard library. The CAIQ utility retains its existing dependencies in `requirements.txt`.

## Contributing

Issues and pull requests are welcome. Treat incorrect mappings as defects: a missing claim is safer than a confident wrong one.

Find Kascade Security at [kascadesecurity.com](https://kascadesecurity.com) and Darius Davis on [LinkedIn](https://linkedin.com/in/ddbna).

## License

See [LICENSE](LICENSE). Upstream mapping excerpts retain their Apache-2.0 attribution in [`mappings/README.md`](mappings/README.md).
