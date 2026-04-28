"""
shodan_client.py
Thin wrapper around the Shodan REST API.
Handles key validation, host lookups, DNS resolution, and search.
"""

import socket
import shodan
from dataclasses import dataclass, field
from typing import Optional


# ──────────────────────────────────────────────
# Data models
# ──────────────────────────────────────────────

@dataclass
class PortService:
    port: int
    transport: str          # tcp / udp
    product: str
    version: str
    banner: str
    cpe: list[str]
    vulns: list[str]        # CVE IDs from Shodan vuln data


@dataclass
class HostReport:
    ip: str
    hostnames: list[str]
    org: str
    isp: str
    asn: str
    country: str
    city: str
    os: str
    last_update: str
    ports: list[PortService]
    tags: list[str]
    vulns: dict[str, dict]  # CVE → {cvss, summary}
    raw: dict               # full Shodan response for power users


@dataclass
class DnsRecord:
    subdomain: str
    type: str
    value: str
    last_seen: str


@dataclass
class SearchResult:
    total: int
    hosts: list[HostReport]


# ──────────────────────────────────────────────
# Client
# ──────────────────────────────────────────────

class ShodanClient:
    def __init__(self, api_key: str):
        self._api = shodan.Shodan(api_key)
        self._key = api_key

    # ── Key validation ───────────────────────────────────────────────

    def validate_key(self) -> tuple[bool, str]:
        """Check that the API key works and return plan info."""
        try:
            info = self._api.info()
            plan  = info.get("plan", "unknown")
            query = info.get("query_credits", "?")
            scan  = info.get("scan_credits", "?")
            return True, f"API key valid | plan={plan} | query_credits={query} | scan_credits={scan}"
        except shodan.APIError as e:
            return False, f"Invalid Shodan API key: {e}"

    # ── DNS helpers ──────────────────────────────────────────────────

    def resolve_hostname(self, hostname: str) -> list[str]:
        """
        Resolve a hostname to one or more IP addresses.
        Uses Shodan DNS resolution first, falls back to system resolver.
        """
        try:
            result = self._api.dns.resolve([hostname])
            ips = [v for v in result.values() if v]
            if ips:
                return ips
        except Exception:
            pass

        # Fallback: system resolver
        try:
            infos = socket.getaddrinfo(hostname, None)
            return list({i[4][0] for i in infos})
        except Exception:
            return []

    def dns_info(self, domain: str) -> list[DnsRecord]:
        """Fetch Shodan's passive DNS records for a domain."""
        try:
            raw = self._api.dns.domain_info(domain, history=False, type=None)
            records: list[DnsRecord] = []
            for entry in raw.get("data", []):
                records.append(DnsRecord(
                    subdomain=entry.get("subdomain", ""),
                    type=entry.get("type", ""),
                    value=entry.get("value", ""),
                    last_seen=entry.get("last_seen", ""),
                ))
            return records
        except shodan.APIError as e:
            raise RuntimeError(f"Shodan DNS lookup failed: {e}") from e

    # ── Host lookup ──────────────────────────────────────────────────

    def host_info(self, ip: str) -> HostReport:
        """Full Shodan host report for a given IP address."""
        try:
            h = self._api.host(ip, history=False, minify=False)
        except shodan.APIError as e:
            raise RuntimeError(f"Shodan host lookup failed for {ip}: {e}") from e

        ports: list[PortService] = []
        for item in h.get("data", []):
            ports.append(PortService(
                port=item.get("port", 0),
                transport=item.get("transport", "tcp"),
                product=item.get("product", ""),
                version=item.get("version", ""),
                banner=(item.get("data", "") or "")[:300],   # trim long banners
                cpe=item.get("cpe23", []) or item.get("cpe", []),
                vulns=list((item.get("vulns") or {}).keys()),
            ))

        # Aggregate vulns across all services
        all_vulns: dict[str, dict] = {}
        for item in h.get("data", []):
            for cve, info in (item.get("vulns") or {}).items():
                all_vulns[cve] = info

        return HostReport(
            ip=h.get("ip_str", ip),
            hostnames=h.get("hostnames", []),
            org=h.get("org", ""),
            isp=h.get("isp", ""),
            asn=h.get("asn", ""),
            country=h.get("country_name", ""),
            city=h.get("city", ""),
            os=h.get("os", "") or "",
            last_update=h.get("last_update", ""),
            ports=ports,
            tags=h.get("tags", []),
            vulns=all_vulns,
            raw=h,
        )

    # ── Search ───────────────────────────────────────────────────────

    def search_hostname(self, hostname: str, max_results: int = 10) -> SearchResult:
        """
        Search Shodan for all records associated with a hostname.
        Uses the `hostname:` filter so results are scoped to that host.
        """
        query = f"hostname:{hostname}"
        try:
            raw = self._api.search(query, limit=max_results)
        except shodan.APIError as e:
            raise RuntimeError(f"Shodan search failed: {e}") from e

        hosts: list[HostReport] = []
        for match in raw.get("matches", []):
            ip = match.get("ip_str", "")
            try:
                hosts.append(self.host_info(ip))
            except Exception:
                # If individual lookup fails, build a minimal record
                hosts.append(HostReport(
                    ip=ip,
                    hostnames=match.get("hostnames", []),
                    org=match.get("org", ""),
                    isp=match.get("isp", ""),
                    asn=match.get("asn", ""),
                    country=match.get("location", {}).get("country_name", ""),
                    city=match.get("location", {}).get("city", ""),
                    os=match.get("os", "") or "",
                    last_update=match.get("timestamp", ""),
                    ports=[],
                    tags=[],
                    vulns={},
                    raw=match,
                ))

        return SearchResult(total=raw.get("total", 0), hosts=hosts)
