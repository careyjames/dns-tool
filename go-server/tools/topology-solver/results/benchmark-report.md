# Topology Solver Benchmark Report

Generated: 2026-03-06T06:00:30.403Z
Total runs: 639

## Summary by Solver

| Solver | Runs | Median Overlaps | Median Stress | Median Crossings | Median Flow Violations |
|--------|------|----------------|---------------|-----------------|----------------------|
| fr_current | 540 | 4 | 2024460.2 | 44 | 0 |
| hybrid_full | 33 | 4 | 2024460.2 | 44 | 0 |
| hybrid_place | 33 | 4 | 2024460.2 | 44 | 0 |
| hybrid_route | 33 | 4 | 2024460.2 | 44 | 0 |

## Per-Metric Winners

- **node_overlap_ratio**: winner = fr_current (median = 4.00)
- **label_overlap_ratio**: winner = fr_current (median = 4.00)
- **edge_crossings_total**: winner = fr_current (median = 44.00)
- **edge_crossings_flow_flow**: winner = fr_current (median = 11.00)
- **edge_node_intersections**: winner = hybrid_full (median = 44.00)
- **flow_x_monotonicity_violations**: winner = fr_current (median = 0.00)
- **flow_stress**: winner = fr_current (median = 2024460.22)
- **bend_count_total**: winner = fr_current (median = 30.00)
- **angular_resolution_min**: winner = fr_current (median = 0.00)
- **layout_bbox_area_ratio**: winner = hybrid_route (median = 378893.31)

## Failure Cases

450 runs with critical metric failures:

- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- solver=fr_current viewport=tablet_portrait perturbation=base: overlaps=5 flow_violations=0
- ... and 430 more

## Detailed Aggregation

| Solver | Viewport | Perturbation | N | Overlaps (med) | Stress (med) | Crossings (med) |
|--------|----------|-------------|---|---------------|-------------|----------------|
| fr_current | desktop | add_protocol_arc | 30 | 0 | 2024460.2 | 44 |
| fr_current | desktop | add_protocol_node | 30 | 0 | 2067345.6 | 40 |
| fr_current | desktop | base | 30 | 0 | 2024460.2 | 44 |
| fr_current | desktop | long_labels_150 | 30 | 4 | 2566187.7 | 59 |
| fr_current | desktop | remove_source | 30 | 0 | 2024460.2 | 44 |
| fr_current | desktop | resize_sequence | 30 | 0 | 2024460.2 | 44 |
| fr_current | phone_large | add_protocol_arc | 30 | 4 | 4609573.8 | 104 |
| fr_current | phone_large | add_protocol_node | 30 | 1 | 4618137.7 | 146 |
| fr_current | phone_large | base | 30 | 4 | 4609573.8 | 104 |
| fr_current | phone_large | long_labels_150 | 30 | 11 | 4581632.0 | 95 |
| fr_current | phone_large | remove_source | 30 | 4 | 4609573.8 | 104 |
| fr_current | phone_large | resize_sequence | 30 | 4 | 4609573.8 | 104 |
| fr_current | tablet_portrait | add_protocol_arc | 30 | 5 | 1303934.9 | 36 |
| fr_current | tablet_portrait | add_protocol_node | 30 | 4 | 1391112.4 | 43 |
| fr_current | tablet_portrait | base | 30 | 5 | 1303934.9 | 36 |
| fr_current | tablet_portrait | long_labels_150 | 30 | 7 | 1560321.0 | 56 |
| fr_current | tablet_portrait | remove_source | 30 | 5 | 1303934.9 | 36 |
| fr_current | tablet_portrait | resize_sequence | 30 | 5 | 1303934.9 | 36 |
| hybrid_full | desktop | add_protocol_arc | 1 | 0 | 2024460.2 | 44 |
| hybrid_full | desktop | add_protocol_node | 1 | 0 | 2067345.6 | 40 |
| hybrid_full | desktop | base | 1 | 0 | 2024460.2 | 44 |
| hybrid_full | desktop | long_labels_150 | 1 | 4 | 2566187.7 | 59 |
| hybrid_full | desktop | remove_source | 1 | 0 | 2024460.2 | 44 |
| hybrid_full | desktop | resize_sequence | 6 | 0 | 2024460.2 | 44 |
| hybrid_full | phone_large | add_protocol_arc | 1 | 4 | 4609573.8 | 104 |
| hybrid_full | phone_large | add_protocol_node | 1 | 1 | 4618137.7 | 146 |
| hybrid_full | phone_large | base | 1 | 4 | 4609573.8 | 104 |
| hybrid_full | phone_large | long_labels_150 | 1 | 11 | 4581632.0 | 95 |
| hybrid_full | phone_large | remove_source | 1 | 4 | 4609573.8 | 104 |
| hybrid_full | phone_large | resize_sequence | 6 | 4 | 4609573.8 | 104 |
| hybrid_full | tablet_portrait | add_protocol_arc | 1 | 5 | 1303934.9 | 36 |
| hybrid_full | tablet_portrait | add_protocol_node | 1 | 4 | 1391112.4 | 43 |
| hybrid_full | tablet_portrait | base | 1 | 5 | 1303934.9 | 36 |
| hybrid_full | tablet_portrait | long_labels_150 | 1 | 7 | 1560321.0 | 56 |
| hybrid_full | tablet_portrait | remove_source | 1 | 5 | 1303934.9 | 36 |
| hybrid_full | tablet_portrait | resize_sequence | 3 | 5 | 1303934.9 | 36 |
| hybrid_full | wall | resize_sequence | 3 | 0 | 2024460.2 | 44 |
| hybrid_place | desktop | add_protocol_arc | 1 | 0 | 2024460.2 | 44 |
| hybrid_place | desktop | add_protocol_node | 1 | 0 | 2067345.6 | 40 |
| hybrid_place | desktop | base | 1 | 0 | 2024460.2 | 44 |
| hybrid_place | desktop | long_labels_150 | 1 | 4 | 2566187.7 | 59 |
| hybrid_place | desktop | remove_source | 1 | 0 | 2024460.2 | 44 |
| hybrid_place | desktop | resize_sequence | 6 | 0 | 2024460.2 | 44 |
| hybrid_place | phone_large | add_protocol_arc | 1 | 4 | 4609573.8 | 104 |
| hybrid_place | phone_large | add_protocol_node | 1 | 1 | 4618137.7 | 146 |
| hybrid_place | phone_large | base | 1 | 4 | 4609573.8 | 104 |
| hybrid_place | phone_large | long_labels_150 | 1 | 11 | 4581632.0 | 95 |
| hybrid_place | phone_large | remove_source | 1 | 4 | 4609573.8 | 104 |
| hybrid_place | phone_large | resize_sequence | 6 | 4 | 4609573.8 | 104 |
| hybrid_place | tablet_portrait | add_protocol_arc | 1 | 5 | 1303934.9 | 36 |
| hybrid_place | tablet_portrait | add_protocol_node | 1 | 4 | 1391112.4 | 43 |
| hybrid_place | tablet_portrait | base | 1 | 5 | 1303934.9 | 36 |
| hybrid_place | tablet_portrait | long_labels_150 | 1 | 7 | 1560321.0 | 56 |
| hybrid_place | tablet_portrait | remove_source | 1 | 5 | 1303934.9 | 36 |
| hybrid_place | tablet_portrait | resize_sequence | 3 | 5 | 1303934.9 | 36 |
| hybrid_place | wall | resize_sequence | 3 | 0 | 2024460.2 | 44 |
| hybrid_route | desktop | add_protocol_arc | 1 | 0 | 2024460.2 | 44 |
| hybrid_route | desktop | add_protocol_node | 1 | 0 | 2067345.6 | 40 |
| hybrid_route | desktop | base | 1 | 0 | 2024460.2 | 44 |
| hybrid_route | desktop | long_labels_150 | 1 | 4 | 2566187.7 | 59 |
| hybrid_route | desktop | remove_source | 1 | 0 | 2024460.2 | 44 |
| hybrid_route | desktop | resize_sequence | 6 | 0 | 2024460.2 | 44 |
| hybrid_route | phone_large | add_protocol_arc | 1 | 4 | 4609573.8 | 104 |
| hybrid_route | phone_large | add_protocol_node | 1 | 1 | 4618137.7 | 146 |
| hybrid_route | phone_large | base | 1 | 4 | 4609573.8 | 104 |
| hybrid_route | phone_large | long_labels_150 | 1 | 11 | 4581632.0 | 95 |
| hybrid_route | phone_large | remove_source | 1 | 4 | 4609573.8 | 104 |
| hybrid_route | phone_large | resize_sequence | 6 | 4 | 4609573.8 | 104 |
| hybrid_route | tablet_portrait | add_protocol_arc | 1 | 5 | 1303934.9 | 36 |
| hybrid_route | tablet_portrait | add_protocol_node | 1 | 4 | 1391112.4 | 43 |
| hybrid_route | tablet_portrait | base | 1 | 5 | 1303934.9 | 36 |
| hybrid_route | tablet_portrait | long_labels_150 | 1 | 7 | 1560321.0 | 56 |
| hybrid_route | tablet_portrait | remove_source | 1 | 5 | 1303934.9 | 36 |
| hybrid_route | tablet_portrait | resize_sequence | 3 | 5 | 1303934.9 | 36 |
| hybrid_route | wall | resize_sequence | 3 | 0 | 2024460.2 | 44 |
