# Evidence-as-Code — a working sample

**Your cloud already proves most of your compliance posture. This is a small,
runnable demonstration of collecting it like code instead of like screenshots.**

Point a read-only scan at your cloud, and it already knows whether your buckets
are public, your keys rotate, and your logging is on. That is evidence. It just
arrives as findings instead of as answers.

This repo turns a **CSA CCM v4.0** scan into a filled **CAIQ v4.0.3** draft —
the questionnaire behind a CSA STAR Level 1 self-assessment — with evidence
cited next to every answer it could prove and an explicit flag on every answer
it could not.

**One framework. One pipeline. Run it yourself.**

A sample from [Kascade Security](https://kascadesecurity.com).

---

## What this sample is — and what it isn't

This is **one framework, end to end**, so you can run the idea and see it work.
It is deliberately not the whole thing.

| Here | At Kascade |
|---|---|
| CSA CCM → CAIQ | Evidence mapped across **39 frameworks** from a single scan — HIPAA, SOC 2, ISO 27001, NIST 800-171, 800-53, PCI |
| One scan, one artifact | **Drift detection** — what changed between this scan and the last one, which is what an annual audit structurally cannot see |
| A CSV in, a CSV out | **Hash-chained provenance** — every artifact tied to the scan that produced it, and tamper-evident |
| You run it | Continuous collection, SSP and POA&M generation, an evidence trail an assessor can check |

**This is a single-cloud sample of the approach.** The multi-cloud mapping
layer, drift detection, and evidence provenance are the commercial platform —
not omissions from this repo. If the sample is useful, the platform is the same
idea with the hard parts finished:
**[kascadesecurity.com](https://kascadesecurity.com)**.

## How it works

```
cloud compliance scan  (CSA CCM v4.0, CSV)
    ↓
caiq_autofill.py
    ↓
CAIQ_filled_<date>.csv   ← a draft, with its evidence attached
```

- **Automated controls** — answered with evidence citations from the scan
- **Policy and process controls** — marked `Partial`, with the specific
  documentation still required

## Scope — on purpose

Stated plainly, because a compliance tool that overstates itself is the problem
it claims to solve:

- **It produces a draft, not a submission.** Most answers land on
  `Partial — review required`, because a scan cannot see your documentation or
  your process. That is the honest ceiling of automated evidence.
- **It does not make you compliant.** It makes your posture *provable*.
- **An unanswered control is never a pass.** Anything the scan could not
  establish stays unanswered. This is the single rule worth stealing from this
  repo even if you never run it.
- **One framework, one cloud, one direction.** AWS only, CSA CCM only. It does
  not infer an answer from a related control when direct evidence is missing —
  it says `Partial`. Multi-cloud mapping, multi-framework crosswalks, drift and
  provenance are the commercial product.

## Quickstart

```bash
pip install -r requirements.txt

# 1. Produce a CSA CCM v4.0 compliance CSV from your cloud — read-only.
#    See "Producing the scan".

# 2. Get the CAIQ template from CSA:
#    https://cloudsecurityalliance.org/star/registry/documentation

# 3. Fill it.
python3 caiq_autofill.py \
  --scan ./output/<scan>_csa_ccm_4.0_aws.csv \
  --template CAIQv4.0.3_STAR-Security-Questionnaire.xlsx
```

Use **read-only credentials.** Nothing here needs write access to your cloud,
and nothing here should have it.

## Producing the scan

This is a consumer, not a scanner. It reads the CSA CCM v4.0 compliance CSV
produced by [Prowler](https://github.com/prowler-cloud/prowler), an open-source
multi-cloud scanner (Apache-2.0):

```bash
prowler aws --compliance csa_ccm_4.0_aws --output-directory ./output -M csv
```

`frameworks/` holds the CCM v4.0 definitions this sample uses — pass them with
`--compliance` or as custom framework files.

## Credits

- [Prowler](https://github.com/prowler-cloud/prowler) — Apache-2.0. Scanning is
  a solved, commoditized problem and this project does not re-solve it; it
  builds the evidence layer on top.
- [Cloud Security Alliance](https://cloudsecurityalliance.org) — CCM v4.0 and
  CAIQ v4.0.3. The CAIQ template is CSA's and is not redistributed here.

## Contributing

PRs welcome. If a mapped check ID is wrong, missing, or broken, open an issue —
a wrong mapping in a compliance artifact is worse than a missing one.

## License

See [LICENSE](LICENSE).
