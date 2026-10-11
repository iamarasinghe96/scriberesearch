# Working in this repository

- This is an independent assessment research workspace, not Arlo application code.
- Keep checks opt-in, unauthenticated, non-destructive, and limited to public data.
- Do not introduce authentication bypasses, credential attacks, or patient data.
- Keep raw evidence and private authorization records out of this public repo.
- Preserve certificate verification, public-address checks, and connection limits.
- Use synthetic fixtures and mocks. Tests must never contact a live target.
- Validate changes with `python -m unittest discover -s tests -v`.
- Do not report observations as verified vulnerabilities without supporting evidence.
