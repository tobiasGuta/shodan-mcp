"""
main.py  –  Shodan MCP Server
Exposes four MCP tools to AI agents:
  • shodan_host      – resolve target → IPs → full Shodan host report
  • shodan_search    – search Shodan by hostname filter
  • shodan_dns       – passive DNS records for a domain
  • check_scope      – inspect H1 scope without any network call
  • list_programs    – list all in-scope targets from H1 snapshots
"""

import os
import sys
from mcp.server.fastmcp import FastMCP
from scope_validator import validate_target, list_scope_summary
from shodan_client import ShodanClient

# ──────────────────────────────────────────────
# Config
# ──────────────────────────────────────────────

SNAPSHOTS_DIR  = os.environ.get("SNAPSHOTS_DIR", "/data/snapshots")
SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")

if not SHODAN_API_KEY:
    print(
        "[shodan-mcp] ⚠️  SHODAN_API_KEY is not set. "
        "All scan tools will return an error until it is configured.",
        file=sys.stderr,
    )

# ──────────────────────────────────────────────
# MCP server
# ──────────────────────────────────────────────

mcp = FastMCP(
    "shodan-mcp",
    instructions=(
        "You are a passive reconnaissance assistant powered by Shodan. "
        "ALWAYS validate scope before any lookup. "
        "NEVER query IPs or hostnames that are not in the H1 scope snapshots. "
        "Shodan lookups are PASSIVE — they do not touch the target directly."
    ),
)


def _get_client() -> ShodanClient:
    if not SHODAN_API_KEY:
        raise RuntimeError(
            "SHODAN_API_KEY environment variable is not set. "
            "Pass it with -e SHODAN_API_KEY=<your_key> when running the container."
        )
    return ShodanClient(SHODAN_API_KEY)


# ──────────────────────────────────────────────
# Formatters
# ──────────────────────────────────────────────

CVSS_ICON = {
    range(9, 11): "🔴 Critical",
    range(7, 9):  "🟠 High",
    range(4, 7):  "🟡 Medium",
    range(0, 4):  "🔵 Low",
}

def _cvss_label(score) -> str:
    try:
        s = float(score)
        for r, label in CVSS_ICON.items():
            if s >= r.start:
                return label
    except (TypeError, ValueError):
        pass
    return "❓ Unknown"


def _format_host(report, show_banner: bool = False) -> str:
    lines = [
        f"🖥️  {report.ip}",
        f"   Hostnames  : {', '.join(report.hostnames) or '—'}",
        f"   Org        : {report.org or '—'}",
        f"   ISP        : {report.isp or '—'}",
        f"   ASN        : {report.asn or '—'}",
        f"   Location   : {report.city or '?'}, {report.country or '?'}",
        f"   OS         : {report.os or '—'}",
        f"   Last seen  : {report.last_update}",
        f"   Tags       : {', '.join(report.tags) or '—'}",
    ]

    if report.ports:
        lines.append(f"\n   🔌 Open Ports ({len(report.ports)}):")
        for p in sorted(report.ports, key=lambda x: x.port):
            svc = f"{p.product} {p.version}".strip() or "unknown service"
            cve_flag = "  ⚠️  CVEs" if p.vulns else ""
            cpe_flag = f"  [{', '.join(p.cpe[:2])}]" if p.cpe else ""
            lines.append(
                f"      {p.port}/{p.transport:<4}  {svc:<30}{cpe_flag}{cve_flag}"
            )
            if show_banner and p.banner:
                for bl in p.banner.splitlines()[:3]:
                    lines.append(f"                 │ {bl}")

    if report.vulns:
        lines.append(f"\n   ⚠️  Shodan CVE Data ({len(report.vulns)}):")
        for cve, info in sorted(
            report.vulns.items(),
            key=lambda x: float(x[1].get("cvss", 0) or 0),
            reverse=True,
        ):
            score = info.get("cvss", "?")
            summary = (info.get("summary", "") or "")[:90]
            lines.append(
                f"      {_cvss_label(score)} | {cve} (CVSS {score})"
            )
            if summary:
                lines.append(f"         {summary}…")

    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 1 – shodan_host
# ──────────────────────────────────────────────

@mcp.tool()
def shodan_host(target: str, show_banners: bool = False) -> str:
    """
    Resolve a target to its IP address(es) and return the full Shodan
    host report for each IP — open ports, services, CVEs, banners, ASN.

    ⚠️  SCOPE GATE: blocked if target is not in H1 scope snapshots OR
    is not bounty-eligible.

    Shodan lookups are PASSIVE — they never directly connect to the target.

    Args:
        target:       Domain, URL, or fuzzy program name (e.g. "life360").
        show_banners: Include raw service banners (first 3 lines each).
                      Default False to keep output concise.
    """
    # ── Scope gate ──────────────────────────────────────────────────
    vr = validate_target(target, SNAPSHOTS_DIR)
    if not vr.allowed:
        return f"🚫 LOOKUP BLOCKED\n{vr.reason}\n\nUse list_programs to see in-scope targets."

    matched_id = vr.matched[0].asset_id
    header = (
        f"{vr.reason}\n"
        f"🔎 Shodan host lookup: {matched_id}\n"
        "─" * 60 + "\n"
    )

    # ── Resolve hostname → IPs ───────────────────────────────────────
    try:
        client = _get_client()
    except RuntimeError as e:
        return header + f"❌ {e}"

    ips = client.resolve_hostname(matched_id)
    if not ips:
        return header + f"❌ Could not resolve '{matched_id}' to any IP address."

    # ── Fetch Shodan report per IP ───────────────────────────────────
    sections = [header, f"Resolved to {len(ips)} IP(s): {', '.join(ips)}\n"]
    for ip in ips:
        try:
            report = client.host_info(ip)
            sections.append(_format_host(report, show_banners))
        except RuntimeError as e:
            sections.append(f"⚠️  {ip}: {e}")
        sections.append("")

    return "\n".join(sections)


# ──────────────────────────────────────────────
# Tool 2 – shodan_search
# ──────────────────────────────────────────────

@mcp.tool()
def shodan_search(target: str, max_results: int = 5) -> str:
    """
    Search Shodan using a `hostname:` filter for the target.
    Returns all records Shodan associates with that hostname across
    any IP that has ever served it.

    ⚠️  SCOPE GATE: blocked if target is not in H1 scope snapshots OR
    is not bounty-eligible.

    Useful for finding:
      - Shadow IT / forgotten infrastructure
      - Old IPs still serving the domain
      - Services exposed on non-standard ports
      - Staging/dev environments indexed by Shodan

    Args:
        target:      Domain, URL, or fuzzy program name.
        max_results: Max hosts to return (default 5, max 20).
    """
    max_results = min(max_results, 20)

    vr = validate_target(target, SNAPSHOTS_DIR)
    if not vr.allowed:
        return f"🚫 SEARCH BLOCKED\n{vr.reason}"

    matched_id = vr.matched[0].asset_id
    header = (
        f"{vr.reason}\n"
        f"🔎 Shodan search: hostname:{matched_id}\n"
        "─" * 60 + "\n"
    )

    try:
        client = _get_client()
    except RuntimeError as e:
        return header + f"❌ {e}"

    try:
        result = client.search_hostname(matched_id, max_results)
    except RuntimeError as e:
        return header + f"❌ {e}"

    if not result.hosts:
        return header + "No Shodan records found for this hostname."

    sections = [
        header,
        f"📊 {result.total} total Shodan record(s) — showing {len(result.hosts)}:\n",
    ]
    for host in result.hosts:
        sections.append(_format_host(host))
        sections.append("")

    return "\n".join(sections)


# ──────────────────────────────────────────────
# Tool 3 – shodan_dns
# ──────────────────────────────────────────────

@mcp.tool()
def shodan_dns(target: str) -> str:
    """
    Fetch Shodan's passive DNS records for a domain.
    Returns all subdomains, A/CNAME/MX/TXT records that Shodan has
    observed — without sending a single packet to the target.

    ⚠️  SCOPE GATE: blocked if target is not in H1 scope snapshots OR
    is not bounty-eligible.

    Great for subdomain discovery before running subfinder or katana.

    Args:
        target: Root domain, URL, or fuzzy program name (e.g. "life360").
    """
    vr = validate_target(target, SNAPSHOTS_DIR)
    if not vr.allowed:
        return f"🚫 DNS LOOKUP BLOCKED\n{vr.reason}"

    matched_id = vr.matched[0].asset_id

    # Strip any subdomain — DNS info works on the root domain
    parts = matched_id.split(".")
    root_domain = ".".join(parts[-2:]) if len(parts) >= 2 else matched_id

    header = (
        f"{vr.reason}\n"
        f"🔎 Shodan DNS records: {root_domain}\n"
        "─" * 60 + "\n"
    )

    try:
        client = _get_client()
    except RuntimeError as e:
        return header + f"❌ {e}"

    try:
        records = client.dns_info(root_domain)
    except RuntimeError as e:
        return header + f"❌ {e}"

    if not records:
        return header + "No passive DNS records found in Shodan."

    # Group by record type
    by_type: dict[str, list] = {}
    for r in records:
        by_type.setdefault(r.type, []).append(r)

    lines = [header, f"📋 {len(records)} DNS record(s) found:\n"]
    for rtype, recs in sorted(by_type.items()):
        lines.append(f"  [{rtype}] ({len(recs)} records)")
        for r in recs:
            fqdn = f"{r.subdomain}.{root_domain}" if r.subdomain else root_domain
            lines.append(f"    {fqdn:<50} → {r.value}   (last seen: {r.last_seen})")
        lines.append("")

    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 4 – check_scope  (same gate as nuclei-mcp)
# ──────────────────────────────────────────────

@mcp.tool()
def check_scope(target: str) -> str:
    """
    Preview the scope gate result for a target WITHOUT making any
    Shodan API call.

    Args:
        target: Domain, URL, or fuzzy program name.
    """
    vr = validate_target(target, SNAPSHOTS_DIR)
    lines = [vr.reason]

    if vr.matched:
        lines.append("\n✅ Bounty-eligible matches:")
        for a in vr.matched:
            lines.append(
                f"   • {a.asset_id} [{a.asset_type}]"
                f"  max_severity={a.max_severity}"
                + (f"  — {a.instruction}" if a.instruction else "")
            )

    if vr.blocked:
        lines.append("\n⛔ Out-of-scope / no-bounty matches (would be BLOCKED):")
        for a in vr.blocked:
            lines.append(
                f"   • {a.asset_id} [{a.asset_type}]"
                f"  bounty={a.eligible_for_bounty}"
                f"  submission={a.eligible_for_submission}"
            )

    return "\n".join(lines)


# ──────────────────────────────────────────────
# Tool 5 – list_programs
# ──────────────────────────────────────────────

@mcp.tool()
def list_programs() -> str:
    """
    List all programs and assets currently tracked in the HackerOne
    scope snapshots, grouped by bounty eligibility.
    """
    return list_scope_summary(SNAPSHOTS_DIR)


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    # Validate API key at startup and log result (does not exit on failure
    # so the server still starts and other tools like check_scope work)
    if SHODAN_API_KEY:
        try:
            ok, msg = ShodanClient(SHODAN_API_KEY).validate_key()
            tag = "✅" if ok else "❌"
            print(f"[shodan-mcp] {tag} {msg}", file=sys.stderr)
        except Exception as e:
            print(f"[shodan-mcp] ❌ Could not validate Shodan key: {e}", file=sys.stderr)

    mcp.run(transport="stdio")
