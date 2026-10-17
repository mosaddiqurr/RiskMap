# Risk Scoring

## Purpose

The 0–100 organisation score is a deterministic prioritisation aid. It is not a probability of compromise, compliance grade or absolute security measurement.

## Finding contribution, formula 2.0

Base severity weights:

| Severity      | Weight |
| ------------- | -----: |
| Critical      |     28 |
| High          |     18 |
| Medium        |     10 |
| Low           |      4 |
| Informational |      1 |

Asset criticality multiplier:

| Criticality | Multiplier |
| ----------- | ---------: |
| Critical    |       1.35 |
| High        |       1.20 |
| Medium      |       1.00 |
| Low         |       0.80 |

Evidence confidence multiplier:

| Confidence | Multiplier |
| ---------- | ---------: |
| High       |       1.00 |
| Medium     |       0.82 |
| Low        |       0.62 |

Context adjustments:

- externally reachable: multiply by 1.15
- newly observed: +3
- reopened: +3
- age over 30 days: +2
- age over 90 days: +4 instead of +2
- at least two related findings: add up to 4
- included in a current potential path: +6

Status multiplier:

| Status         | Multiplier |
| -------------- | ---------: |
| Open           |       1.00 |
| Reopened       |       1.05 |
| In progress    |       0.80 |
| Accepted risk  |       0.70 |
| Resolved       |          0 |
| False positive |          0 |

A finding that is not currently observed contributes zero. Each finding contribution is capped at 35.

## Organisation aggregation

Contributions are sorted descending and decayed:

```text
weightedTotal = Σ contribution[index] × 0.82^index
score = round(100 × (1 − exp(−weightedTotal / 70)))
```

This reduces the chance that many low-impact observations overwhelm a smaller number of material findings.

## Best Next Fix estimate

Best Next Fix does not simply subtract a fixed number. It removes a candidate finding from the current graph, recalculates paths, recomputes which remaining findings are in paths and runs the organisation formula again.

The displayed reduction is:

```text
current organisation score − projected organisation score
```

Ranking also considers removed paths, aggregate affected-path risk, severity, asset criticality, confidence and effort.

## Limitations

- The score depends on available evidence and customer criticality labels.
- Missing data can lower or distort the result.
- Inferred edges reduce path confidence but may still influence prioritisation.
- Accepted risk still contributes because acceptance does not remove exposure.
- A lower score after remediation is an estimate, not a guarantee of lower breach probability.

## Phase 4 validation coverage

The unit, integration and deterministic performance suites execute finding aggregation,
attack-path scoring and a Best Next Fix scenario in which neutralising one shared
weakness removes two paths and reduces organisation risk. Production-backed browser
tests verify that Risk contributors and Best Next Fix remain visible and explainable.
Stored contributors allow the result to be reproduced without an opaque score.
