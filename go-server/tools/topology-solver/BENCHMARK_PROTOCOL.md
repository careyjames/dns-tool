# Benchmark protocol

## Goal
Compare:
- current FR engine
- ELK layered baseline
- hybrid placement only
- hybrid placement plus routing
- hybrid full system

## Required outputs
1. Raw metrics JSON per run
2. One CSV summary for all runs
3. PNG snapshot grid by solver x scenario
4. Markdown report with:
   - per-metric winners
   - failure cases
   - notable trade-offs
   - desktop/tablet/mobile comparison
   - resize stability analysis

## Mandatory scenarios
- Base graph
- Long labels (150%)
- Add one protocol node
- Remove one source node
- Add one soft dependency
- Resize sequence

## Metric rules
- Node overlap ratio must be exactly 0 for any candidate that is considered publishable.
- Label overlap ratio must be exactly 0 on desktop and tablet.
- Flow x-monotonicity violations must be 0 on desktop and tablet.
- Edge-node intersections for flow edges must be 0.
- Stress is important but cannot override obvious geometric failures.
- Final ranking must be based on the full metric vector, not a single weighted score.

## Statistical handling
- Run the current FR engine for 30 seeds.
- Deterministic solvers need one run per scenario.
- Report median and IQR for FR, single values for deterministic systems.
- Provide paired comparisons by scenario and metric.

## Snapshot policy
Export at least these views:
- phone_large
- tablet_portrait
- desktop
- wall

## Known limitation
Until the production topology.html has been extracted into LayoutSpec JSON, the reconstructed fixture is only a scaffold.
