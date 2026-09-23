# FEC-R2 follow-up probe: greedy comparison without a first-step tie

Date: 2026-09-06. Separate label; does not replace or re-run the two completed trials.

Question: in the completed sweeps the certificate policy beat the myopic greedy policy in only 1 of 374 and 3 of 374 states, and those cases could be explained by tie-breaking among equally good first repairs. This probe checks a prescribed state where the best first repair is strictly unique, so any remaining difference must come from planning both repairs together rather than from tie-breaking.

Prescribed case: V = span(14), i.e. one received equation over source coordinates 1, 2 and 3; no source symbol individually decoded. Sender priorities fixed in advance as 4, 3, 3, 3, 1.

Predeclared expectation: greedy takes coordinate 0 first because 4 > 3 strictly, then one more coordinate, for weight 7. Selecting coordinates 1 and 2 releases coordinates 1, 2 and 3 through the recorded relation, for weight 9. A different outcome refutes the expectation and must be reported as such.

Unchanged: RU decoder program and its hash, transport, controls, budgets, cleanup and the rule that no production settings are touched. Changed on the MCP side only: the case list is this single state, and the priorities are the fixed values above instead of fresh random ones. Source symbols are still freshly generated after the RU listener is ready.

This probe is a targeted mechanism check on one state. It is not a performance benchmark, not a random sample, and not evidence about general traffic.
