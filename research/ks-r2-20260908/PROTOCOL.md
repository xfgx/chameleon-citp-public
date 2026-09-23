# KS-R2 — pre-run protocol, 2026-09-08

Question: does R1 alternate4 synchronization survive finite observation precision and clustered erasures?
Scope: offline Go FieldParams.Step and ObserverStepMulti on RU; no networking, no credentials, no production change.
64 public fields: the original 32 plus 32 fresh fields derived with SHA-256 namespace KS-R2-public-only/. Same parameter ranges and fixed ring. No filtering.
28 paired conditions: observation precision 12,16,24,48 fractional bits; no loss, or 1%,5%,10% target loss under IID and two-state burst8. All four observed coordinates are erased together. Shared tick phase continues through loss; no resynchronization or latency model.
Quantizer: generic Q0.b nearest rounding and saturation, not the production modem codec. 48 bits is identity. Burst chain: 0->1=p/(8*(1-p)), 1->0=1/8, stationary initialization; mean dropped run 8. Public random uniforms shared across precision levels. Report realized, not just target, loss.
Burn2048, measurement8192, final1024. Endpoints: RMS over 8 coordinates, max absolute error, fraction of final steps with any coordinate error>.01, exact equality across the whole final window. Predeclared tolerance success: RMS<.001. Show per-cohort and pooled counts; conditions are paired, not independent field samples.
Controls: quantizer range/absolute-error bound and 48-bit identity (40004 cases); no-loss 48-bit replication; compare existing golden tests; no hidden failed rows. Aggregate independently from CSV before reporting.
Predictions, not results: precision creates a nonzero floor; clustered losses can produce larger excursions than IID at similar average loss. Neither is claimed as novel before literature comparison. No DPI/TSPU claim.
Runtime limit600s CPU25% memory512MiB. Preserve script, fields, raw rows, log and manifest. Failure or stopping is reported, not replaced by a selected subset.
