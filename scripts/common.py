"""Small verified transport shared by the public-check commands."""

import argparse
from datetime import datetime, timezone
import http.client
import ipaddress
import json
import re
import socket
import ssl
import sys


SOCKET_TIMEOUT = 5
USER_AGENT = "scriberesearch-public-check/0.1"
_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", re.ASCII)


def validate_host(host):
    """Accept an ASCII DNS hostname only, never a URL or IP literal."""
    if not isinstance(host, str) or not host.isascii() or host != host.strip():
        raise ValueError("Supply an ASCII DNS hostname without whitespace.")
    host = host.lower()
    if host.endswith("."):
        host = host[:-1]
    labels = host.split(".")
    if len(host) > 253 or len(labels) < 2 or any(
        not _LABEL.fullmatch(label) for label in labels
    ):
        raise ValueError("Supply a DNS hostname only, without a URL, path, or port.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host
    raise ValueError("IP literals are not accepted; supply a scoped public hostname.")


def public_endpoint(host):
    """Validate every DNS answer and return one numeric socket endpoint."""
    host = validate_host(host)
    answers = socket.getaddrinfo(
        host, 443, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP
    )
    if not answers:
        raise ValueError("DNS returned no usable addresses.")
    for family, _, _, _, address in answers:
        if family not in (socket.AF_INET, socket.AF_INET6):
            raise ValueError("DNS returned an unsupported address family.")
        ip = ipaddress.ip_address(address[0])
        if not ip.is_global or ip.is_multicast or ip.is_reserved:
            raise ValueError("Refusing a hostname with a non-public DNS answer.")
    return answers[0]


def open_verified_tls(host):
    """One connection to a validated IP; keep hostname verification enabled."""
    host = validate_host(host)
    family, socktype, proto, _, address = public_endpoint(host)
    context = ssl.create_default_context()
    context.keylog_filename = None
    context.set_alpn_protocols(["http/1.1"])
    raw = socket.socket(family, socktype, proto)
    try:
        raw.settimeout(SOCKET_TIMEOUT)
        # Numeric sockaddr avoids a second DNS lookup and DNS rebinding.
        raw.connect(address)
        return context.wrap_socket(raw, server_hostname=host)
    except BaseException:
        raw.close()
        raise


def observed_at():
    return datetime.now(timezone.utc).isoformat()


def run_cli(check, description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--host", required=True, help="Exact scoped public DNS hostname")
    args = parser.parse_args()
    try:
        result = check(args.host)
    except (ValueError, OSError, http.client.HTTPException) as error:
        print(json.dumps({"error": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0
