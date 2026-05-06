"""Shared URL safety checks for server-side scanning requests."""

import ipaddress
import socket
from urllib.parse import urljoin, urlparse


ALLOWED_SCHEMES = {"http", "https"}


def is_blocked_ip(ip):
    """Return True for addresses that should never be scanned server-side."""
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped

    return (
        ip.is_loopback
        or ip.is_private
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or not ip.is_global
    )


def resolve_target_ips(hostname):
    """Resolve a hostname and reject localhost aliases."""
    normalized = hostname.rstrip(".").lower()
    if normalized == "localhost" or normalized.endswith(".localhost"):
        raise ValueError("Localhost targets are not allowed")

    try:
        return [ipaddress.ip_address(hostname)]
    except ValueError:
        pass

    try:
        addrinfo = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Target hostname could not be resolved") from exc

    addresses = []
    for entry in addrinfo:
        ip_text = entry[4][0]
        try:
            addresses.append(ipaddress.ip_address(ip_text))
        except ValueError as exc:
            raise ValueError("Target hostname resolved to an invalid address") from exc

    if not addresses:
        raise ValueError("Target hostname could not be resolved")

    return addresses


def validate_public_http_url(url):
    """Validate that a URL targets a public http(s) address."""
    parsed = urlparse(url)
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError("Only http and https URLs are allowed")
    if not parsed.hostname:
        raise ValueError("Target hostname is required")

    try:
        parsed.port
    except ValueError as exc:
        raise ValueError("Target port is invalid") from exc

    addresses = resolve_target_ips(parsed.hostname)
    if any(is_blocked_ip(ip) for ip in addresses):
        raise ValueError("Target address is not allowed")


def validate_redirect_target(base_url, location):
    """Validate a redirect destination before following it."""
    if not location:
        return

    validate_public_http_url(urljoin(base_url, location))
