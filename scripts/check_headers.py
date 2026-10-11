"""Observe selected headers with one unauthenticated HEAD / request."""

import http.client

from .common import SOCKET_TIMEOUT, USER_AGENT, observed_at, open_verified_tls
from .common import run_cli, validate_host


SECURITY_HEADERS = (
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
)


def check_headers(host):
    host = validate_host(host)
    with open_verified_tls(host) as tls:
        connection = http.client.HTTPConnection(host, port=443, timeout=SOCKET_TIMEOUT)
        # The socket is already TLS-wrapped and validated; never auto-connect.
        connection.sock = tls
        connection.auto_open = False
        try:
            connection.request(
                "HEAD",
                "/",
                headers={"Host": host, "User-Agent": USER_AGENT, "Connection": "close"},
            )
            response = connection.getresponse()
            try:
                headers = {name: response.getheader(name) for name in SECURITY_HEADERS}
                return {
                    "check": "public_headers",
                    "host": host,
                    "observed_at_utc": observed_at(),
                    "method": "HEAD",
                    "path": "/",
                    "status": response.status,
                    "security_headers": headers,
                    "missing_headers": [name for name, value in headers.items() if value is None],
                    "note": "Missing headers are observations, not confirmed vulnerabilities.",
                }
            finally:
                response.close()
        finally:
            connection.close()


def main():
    return run_cli(check_headers, __doc__)


if __name__ == "__main__":
    raise SystemExit(main())
