# FEC-R2: late-binding repair priorities — exploration protocol v1

Date: 2026-09-06. Status at authoring: no experiment executed.

## Contract
Develop a receiver-state descriptor sufficient to choose up to two additional linear transmissions over GF(2), maximizing the weighted count of separately recovered source symbols. The sender may choose weights after receiving feedback. This is a point-to-point synthetic functional experiment on MCP and RU, not a VPN throughput benchmark, an address-privacy experiment, or evidence of a new physical channel. No claim of global novelty.

Only MCP and RU participate. No compilation is required (Python standard library); any later compilation must be on RU. Do not change production code, services, routes, firewall, namespaces, or VPN. Use an ephemeral RU TCP listener restricted to the observed MCP management source address, one accepted connection, an in-memory random authorization value, bounded frames, a hard runtime limit, and synthetic data only. Administrative SSH and test TCP are separate, both visible; no address-absence claim. The local authoring computer must not execute the experiment.

## Candidate queue before selection
1. Rank plus decoded bitmap: known baseline; cheap test is a pair of states with equal rank/bitmap and different recovery response.
2. One-repair equivalence classes: relation e_i+e_j in received row space; close prior art found in Sundararajan et al. 2009. Keep as calibration, not novelty.
3. Two-repair relational certificate (selected): partition plus triples whose quotient labels sum to zero. Test whether this predicts the optimal weighted recovery for weights chosen after feedback, without revealing the full row space.
4. Stale-feedback certificates: old relations remain valid under row-space growth, but reported undecoded symbols may already be decoded. Defer; requires separate protocol and delayed-feedback trials.
5. Deadline-aware/adaptive window coding: close to AC-RLNC, CRLNC-FB, UEP/IDNC and multi-phase BNC. Do not relabel as a new principle.
6. Three-or-more-repair dependency certificate: higher-order quotient relations; more ambitious, potentially prohibitive feedback. Queue only; no claim or implementation in v1.

## Definitions and proof obligation
Let V be the row space of received coefficient vectors in F_2^K and e_i the i-th source unit vector. Symbol i is exactly recoverable iff e_i is in V (no noise, correct coefficients). Define q_i=e_i+V. Zero labels mean already decoded symbols. Nonzero identical q_i form a class. Include a triangle {a,b,c} iff the three distinct nonzero class labels satisfy q_a+q_b+q_c=0.

Adding two repair vectors expands V by a quotient subspace U of dimension at most two. Over GF(2), U has at most three nonzero points. If U contains at least two occupied source classes, two representatives of those classes span U; replacing arbitrary repair vectors with those two systematic vectors leaves the recovered set unchanged. If U contains only one occupied class, one systematic representative suffices. Thus some optimal two-transmission action is a pair of systematic symbols. Its newly recovered classes are those two classes and, if present, the third class in their recorded triangle. Partition plus triangles therefore suffices for arbitrary nonnegative source weights fixed at selection time, provided feedback is current and at most two repair vectors are used.

This is a derivation from elementary quotient-space algebra, not a claim that the theorem is new. General fields, three repairs, multiple receivers, noisy coefficients, stale feedback, moving windows and time deadlines are outside this statement.

## Strong alternatives and limitations
A receiver can simply recommend an optimal pair with very few bits if it already knows the weights. That is a required baseline. The proposed descriptor only has a potential reason to exist when priorities change AFTER feedback and another feedback exchange is undesirable. Full row-space feedback is an exact-information baseline. Greedy immediate recovery is another baseline, not a claim of state-of-the-art comparison.

No compactness is assumed: partition/triangle JSON may cost MORE than a dense basis. Record actual feedback frame bytes and separate theoretical raw descriptor bit counts from wire bytes. Do not claim a compression or speed win unless measured against a fair representation including protocol overhead.

## Predeclared experiment
- K=5, 64 fresh random bytes per source symbol, independently generated on MCP after RU is ready; source values never sent through SSH, common files, seeds or expected-answer fields.
- Enumerate all distinct subspaces of F_2^5 as controlled initial decoder states, plus explicit matched witnesses V=span(7) and V=span(28).
- MCP transmits only encoded rows and then actual repair symbol bytes over the dedicated TCP connection. RU performs Gaussian elimination on bytes and reports hashes of symbols it can decode; MCP compares against its private source values.
- Receiver sends a partition/triangle certificate and an optimal recommendation for equal weights. Only then MCP chooses fresh weights in {1,2,4,8} (fixed unit weights for the declared witnesses).
- Treatments: certificate-selected pair; greedy immediate-recovery pair given full matrix knowledge; receiver's earlier equal-weight recommendation. All get the same initial rows and exactly two equal-size repair symbols, with randomized treatment order. These are parallel logical decoders, not independent network-performance runs.
- Main gate: every certificate-selected action achieves the exact best weighted recovery among all pairs of arbitrary binary coefficient vectors, independently enumerated at the sender, and every reported recovered hash matches the actual fresh source symbol.
- Positive control: empty decoder then all five systematic symbols, exact recovery of all five. Negative control: no equations, no decoded symbols. Causal control: parity-only state with no repairs must not decode any individual source symbol. Duplicate and zero equations must not add recovery.
- Log inputs, feedback, actions, timestamps, errors, wire application-frame bytes and returned hashes. This is exact finite-state calibration with fresh payload checks, not an estimate of Internet traffic probabilities. A failed control makes the run uninformative.
- One run, hard client budget 240 seconds; RU hard cap 300 seconds, maximum application data 5 MiB, maximum frame 65536 bytes, at most 5000 requests. No retrying a failed experiment under the same result label.
- Confirmation: a separate second run with new source values after the exploratory run only if the first is valid and remains within practical budget. Do not silently call the same payloads independent replications.

## Stop and cleanup
Close the dedicated TCP connection and SSH session, ensure RU child process exits and the listener disappears. Keep code, protocol and raw logs in a new research directory only; do not rewrite prior experiments. On any unexpected destination, peer, timeout, resource growth or protocol failure stop, record it and do not change firewall or routes to make it pass.

## Novelty search ledger (2026-09-06)
- Queries included: partial decoding network coding rank recoverable source symbols feedback deadline; network coding equivalence classes decoding feedback; network coding cosets partial decoding; network coding quotient space feedback; two-step feedback decoding; matroid partial decoding; decoding delay lookahead; 2025/2026 RLNC feedback.
- RFC 9273: https://www.rfc-editor.org/rfc/rfc9273.html — relevant terminology and feedback passages read.
- Feedback-based online network coding (2009): https://arxiv.org/html/0904.1730v1 — search excerpts explicitly describe equivalence classes of undecoded packets; direct full-text extraction and local PDF retrieval did not succeed in this pass. Do not claim full text reviewed.
- CRLNC-FB (2018): https://faculty.engineering.asu.edu/mre/wp-content/uploads/sites/31/2020/02/CRLNC_FB.pdf — abstract/search excerpts read; direct full-text request canceled. Uses systematic retransmissions and specialized elimination for low-delay delivery.
- AC-RLNC (2019/2020): https://arxiv.org/abs/1905.02870 — abstract/search excerpts; adaptive coding with delayed feedback, not the exact selected descriptor claim.
- Multi-Phase Adaptive Recoding (2024): https://www.mdpi.com/2673-8732/4/4/24 — relevant full-page extracts read; feedback rank and unresolved feedback-cost tradeoffs.
- APC-RLNC preprint, 2026-08-26: https://arxiv.org/html/2608.26040v1 — relevant extracts read; adaptive peer clustering, different problem; reported claims not independently verified.

Novelty status: known algebra and known one-step classes; possible difference in a two-repair, late-binding-priority descriptor, PRIOR-ART CHECK INCOMPLETE. No global priority or patentability claim.
