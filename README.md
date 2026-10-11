# Scribe security research workspace

An independent workspace for authorized security assessment research relating to
the Arlo AI clinical scribe. This is newly created research scaffolding, not
Arlo's proprietary application source, a reconstruction of it, or an official
Arlo project. No application source existed in this repository at initialization.

## Setup

Use Python 3.11 or later with TLS support. Runtime and tests use only the Python
standard library; there are no third-party dependencies or installation hooks.

```sh
git clone https://github.com/iamarasinghe96/scriberesearch.git
cd scriberesearch
python --version
python -m unittest discover -s tests -v
```

On systems where Python is named `python3`, substitute it for `python`.
An optional isolated environment can be created with `python -m venv .venv`.
`requirements.txt` intentionally contains no packages. For a Codex environment,
no dependency installation is required; use the test command above to validate
the checkout. Tests run offline and never contact Arlo or another live target.

## Optional public checks

Run only against a host included in your assessment scope. There is no default
target and setup does not run these checks. Supply an ASCII DNS hostname, not a
URL, IP address, path, port, credential, or query string.

```sh
python -m scripts.check_headers --host example.com
python -m scripts.check_tls --host example.com
```

Replace `example.com` with your scoped hostname. The previously referenced
`app.aus.getarlo.io` is a candidate to record in the scope document, not an
embedded default or evidence of authorization. Keep the actual authorization
record private; see [scope guidance](research/scope/README.md).

Each invocation makes one TCP connection to port 443 after a DNS lookup. The
header check sends one unauthenticated `HEAD /` request, records selected public
security headers and the response status, and does not follow redirects or read
the response body. The TLS check performs one normal, verified handshake and
records the negotiated protocol, cipher, and certificate dates/fingerprint. It
sends no HTTP request. Both use certificate and hostname verification, reject
non-public or multicast DNS answers, pin the checked IP for the connection, and
use a five-second socket timeout. DNS resolution uses the OS resolver and may
take longer than that timeout. There are no retries, alternate-IP fallbacks,
proxy support, scans, endpoint discovery, or authentication attempts.

Results are JSON on standard output. Failures return exit code 1; argument
errors return 2. A successful observation returns 0 even when headers are absent.
Missing headers alone are not confirmed vulnerabilities. A single handshake
does not enumerate all supported TLS versions or ciphers. See the
[methodology](research/methodology/public-checks.md) for interpretation.

## Layout

```text
docs/                    Environment history and maintenance notes
research/scope/          Scope guidance; private local authorization records
research/methodology/    Reproducible, non-destructive procedures
research/notes/          Sanitized working notes
research/findings/       Finding template and reviewed findings
research/evidence/       Local evidence guidance (raw evidence is ignored)
scripts/                Opt-in public header and TLS checks
tests/                  Offline tests with synthetic responses
```

## Handling research data

This repository is public. Do not commit patient records, clinical audio or
transcripts, real credentials, session cookies, tokens, private authorization
agreements, or unredacted traffic captures. Use synthetic fixtures for tests.
Ignore rules are a convenience, not a substitute for reviewing staged files.
Keep private evidence in approved storage and publish only reviewed, sanitized
observations. No live assessment findings are claimed by this starter project.

The project contains no authentication bypass, exploit, brute-force, destructive
test, or proprietary backend-access tooling. Broader work must be separately
scoped and use the owner's approved assessment process.

Implementation references: Python's official
[TLS documentation](https://docs.python.org/3/library/ssl.html) and
[HTTP client documentation](https://docs.python.org/3/library/http.client.html).
