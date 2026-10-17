# Potential attack paths

An attack path is an analytical exposure path derived from supplied evidence, not proof of compromise or exploitation. RiskMap performs no live discovery or access validation.

## Graph construction

The active graph contains Internet, supplied assets/identities, services, findings and sensitive targets. `public: true` creates an Internet entry edge. Targets are `CRITICAL_ASSET` assets or assets with `CRITICAL` criticality. Neither a name nor an IP string implies exposure.

Relationships follow their supplied `from -> to` direction. `viaFindingId` gates a transition through a finding on the source asset, avoiding a parallel bypass edge. General dependencies remain during remediation. Every edge carries evidence, confidence and observed/inferred state. Exact duplicate relationship evidence is rejected; distinct evidence remains distinguishable.

## Search

The engine starts at Internet or explicit entry nodes, follows active directed edges, prevents repeated nodes in a chain and requires at least one finding, an exposure/service step and a sensitive target. Confidence filtering can further constrain the search.

The active pipeline searches at most eight nodes, 400 recorded paths and 30,000 explored states. Path/state-budget exhaustion sets a completeness flag exposed in the UI and reports. Maximum depth remains a modeling boundary even without budget exhaustion. Ordered node and edge identities distinguish parallel routes. Results sort by score, then shorter length.

Path scoring combines entry exposure, supplied finding severity, asset criticality, service sensitivity, path length and administrative/data/API context. Inferred relationships incur a penalty, and supplied confidence adjusts the score. Scores are clamped to 0-100. Critical is >=80, high >=60, medium >=35, otherwise low. These labels are distinct from imported finding severity. The UI shows contributing terms.

## Best Next Fix and comparison

The simulation removes each candidate finding and its dependent edges, reruns the bounded search and recalculates finding scores at the original timestamp. Ranking combines score-point change, provably affected paths and their aggregate scores, severity, asset importance, confidence and a rough category-based effort estimate. Stable ties retain input order. Candidates with neither path nor rounded-score benefit are omitted.

Only original paths containing the removed finding are claimed as removed. A bounded re-search may discover a different subset; it is not an exhaustive before/after enumeration. The graph retains inventory, public service reachability, general relationships and unrelated findings. Qualitative benefit and score points describe this model, not measured real-world risk percentages. Reimport updated evidence after implementing a real fix.

The selected graph path highlights exact edge IDs and offers node/edge evidence. Textual paths provide the full chain and finding/remediation context alongside the visual graph. See [testing](TESTING.md) for correctness coverage.
