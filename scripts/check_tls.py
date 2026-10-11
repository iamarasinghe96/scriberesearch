"""Observe one verified TLS handshake; send no HTTP request."""

import hashlib

from .common import observed_at, open_verified_tls, run_cli, validate_host


def check_tls(host):
    host = validate_host(host)
    with open_verified_tls(host) as tls:
        certificate = tls.getpeercert()
        fingerprint = hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()
        cipher = tls.cipher()
        return {
            "check": "public_tls",
            "host": host,
            "observed_at_utc": observed_at(),
            "tls_version": tls.version(),
            "cipher": cipher[0] if cipher else None,
            "certificate": {
                "not_before": certificate.get("notBefore"),
                "not_after": certificate.get("notAfter"),
                "sha256": fingerprint,
            },
            "note": "One verified negotiation; supported versions and ciphers are not enumerated.",
        }


def main():
    return run_cli(check_tls, __doc__)


if __name__ == "__main__":
    raise SystemExit(main())
