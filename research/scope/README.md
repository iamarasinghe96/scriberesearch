# Assessment scope

The assessor has stated that consent exists. This scaffold does not verify or
expand that consent. Keep the signed authorization in approved private storage.
Optionally create `authorization.local.md` here; that name is ignored by Git.

Record these details privately before a live check:

- System owner, assessor, approval reference, and escalation contact.
- Exact allowed hostnames and assessment dates/window.
- Allowed methods (for these scripts: public DNS, verified TLS on 443, `HEAD /`).
- Rate limits, exclusions, stop conditions, and evidence retention requirements.

`app.aus.getarlo.io` appeared in the earlier discussion. Verify its inclusion
against the owner's scope; no other Arlo domains, tenants, accounts, APIs, or
backends are implied. The tools require an explicit host each time.
