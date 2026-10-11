# Public checks

## Header observation

1. Select one exact scoped public hostname.
2. Run `python -m scripts.check_headers --host HOSTNAME` once.
3. Record the UTC timestamp, response status, and selected security headers.
4. Review each missing or unusual header in the context of the actual response.

The only HTTP method/path is `HEAD /`. Redirect destinations are not contacted.
The response body, cookies, and authentication headers are not included in the
report. A 401, 403, 405, 429, or redirect is recorded as an observation; the tool
does not retry or substitute another method. Stop and consult scope if the
owner asks you to stop or a response indicates traffic restrictions.

The reported headers are Strict-Transport-Security, Content-Security-Policy,
X-Content-Type-Options, X-Frame-Options, Referrer-Policy, and Permissions-Policy.
Their presence alone does not establish effective protection, and absence alone
does not establish an exploitable defect. An edge/CDN/root response may differ
from authenticated application pages. No application behavior is inferred.

## TLS observation

1. Run `python -m scripts.check_tls --host HOSTNAME` once.
2. Record the negotiated TLS version, cipher, certificate dates, and SHA-256
   fingerprint of the leaf certificate.
3. Treat this as one verified connection from the assessor's environment.

Certificate and hostname checks remain enabled. Verification failure is an
error; do not disable verification to force a result. There is no cipher or
protocol enumeration, downgrade probing, or backend discovery. The result
does not establish that weaker configurations are absent on other connections.

## Transport limits

The complete DNS answer set must consist of public unicast IP addresses. An
empty, private, loopback, link-local, reserved, or multicast answer is refused
before opening a connection. The tool connects directly to the first validated
numeric address, preserving the original hostname for TLS and HTTP. It does
not resolve the name again during connection establishment. Only port 443 is
used. There is one connection attempt and no fallback. An IPv6 connectivity
failure therefore remains an error if that was the first returned address.

Socket operations have a five-second timeout; OS DNS resolution has its own
timing. The scripts ignore proxy configuration and never accept credentials,
custom paths, or URLs. Tests use mocks and synthetic HTTP responses only.
