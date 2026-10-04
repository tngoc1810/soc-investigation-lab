# Building an honest, reproducible portfolio

This foundation was created with Codex assistance. A strong final portfolio identifies what the learner personally investigated, changed and validated, along with community datasets/rules and assistance. Keep dated notes in learning/LOG.md.

Before adding a case, record the original source, scenario, permitted use, pinned version, hashes, telemetry and limits. Third-party raw EVTX stays local; link the origin instead of assuming redistribution rights. Never combine unrelated samples into an invented incident.

For detection changes, document the behavioral hypothesis, source requirements, false positives and blind spots. Add tests for a real failure mode or legitimate lookalike, then run python -m unittest discover -s tests -v. Include before/after findings without presenting tiny samples as production detection rates.

Keep credentials, local raw evidence and generated reports out of Git unless explicitly reviewed and safe to publish. Publish curated reports with provenance and defanged historical indicators. Do not visit or execute indicator content.
