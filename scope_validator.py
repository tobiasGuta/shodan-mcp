"""
scope_validator.py
Reads HackerOne scope snapshots from /data/snapshots and validates
targets before allowing Nuclei to scan them.
"""

import json
import os
import glob
from urllib.parse import urlparse
from dataclasses import dataclass, field
from typing import Optional


# ──────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────

@dataclass
class ScopeMatch:
    asset_id: str
    asset_type: str
    eligible_for_bounty: bool
    eligible_for_submission: bool
    max_severity: str
    instruction: str
    source_file: str

@dataclass
class ValidationResult:
    allowed: bool                          # True → scan can proceed
    reason: str                            # Human-readable explanation
    matched: list[ScopeMatch] = field(default_factory=list)   # What matched
    blocked: list[ScopeMatch] = field(default_factory=list)   # Out-of-scope hits


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

SCANNABLE_TYPES = {"URL", "WILDCARD", "OTHER"}


def _hostname(target: str) -> str:
    """Strip scheme / path / port from a target string → bare hostname."""
    t = target.strip()
    if not t.startswith(("http://", "https://")):
        t = "https://" + t
    return urlparse(t).netloc.lower().split(":")[0]


def _exact_match(hostname: str, asset_id: str, asset_type: str) -> bool:
    """Return True when hostname falls inside the declared asset."""
    aid = asset_id.lower().strip()
    host = hostname.lower()

    if asset_type == "WILDCARD":
        # *.tile.com  →  matches sub.tile.com  AND  tile.com itself
        if aid.startswith("*."):
            suffix = aid[2:]          # tile.com
            return host == suffix or host.endswith("." + suffix)
        return host == aid

    # URL / OTHER – exact hostname or any subdomain of it
    return host == aid or host.endswith("." + aid)


def _fuzzy_match(keyword: str, asset_id: str) -> bool:
    """Substring match so 'life360' finds 'api.life360.com'."""
    return keyword.lower() in asset_id.lower()


# ──────────────────────────────────────────────
# Main public functions
# ──────────────────────────────────────────────

def load_all_assets(snapshots_dir: str) -> list[ScopeMatch]:
    """
    Read every *.json file in snapshots_dir and return a flat list
    of ScopeMatch objects for URL / WILDCARD / OTHER entries.
    """
    assets: list[ScopeMatch] = []
    files = glob.glob(os.path.join(snapshots_dir, "*.json"))

    for fpath in files:
        try:
            with open(fpath, encoding="utf-8") as fh:
                raw = json.load(fh)
        except Exception:
            continue

        entries = raw if isinstance(raw, list) else [raw]
        for entry in entries:
            atype = entry.get("asset_type", "")
            if atype not in SCANNABLE_TYPES:
                continue
            assets.append(ScopeMatch(
                asset_id=entry.get("asset_identifier", ""),
                asset_type=atype,
                eligible_for_bounty=bool(entry.get("eligible_for_bounty", False)),
                eligible_for_submission=bool(entry.get("eligible_for_submission", False)),
                max_severity=entry.get("max_severity") or "unknown",
                instruction=entry.get("instruction") or "",
                source_file=os.path.basename(fpath),
            ))

    return assets


def validate_target(target: str, snapshots_dir: str) -> ValidationResult:
    """
    Full scope check:
      1. Load all assets from snapshots.
      2. Try exact hostname match first, then fuzzy keyword match.
      3. Split matches into bounty-eligible vs out-of-scope.
      4. Return ValidationResult(allowed=True) only when at least one
         match is both eligible_for_bounty AND eligible_for_submission.
    """
    assets = load_all_assets(snapshots_dir)

    if not assets:
        return ValidationResult(
            allowed=False,
            reason=(
                f"⛔ No scope data found in '{snapshots_dir}'. "
                "Make sure h1-scope-watcher has run at least once."
            ),
        )

    hostname = _hostname(target)

    # ── Pass 1: exact / wildcard match ──────────────────────────────
    exact_hits = [a for a in assets if _exact_match(hostname, a.asset_id, a.asset_type)]

    # ── Pass 2: fuzzy keyword match (e.g. "life360") ─────────────────
    if not exact_hits:
        keyword = target.strip().lower()
        exact_hits = [a for a in assets if _fuzzy_match(keyword, a.asset_id)]

    if not exact_hits:
        return ValidationResult(
            allowed=False,
            reason=(
                f"⛔ '{target}' not found in any H1 scope snapshot. "
                "Scan blocked."
            ),
        )

    eligible = [a for a in exact_hits if a.eligible_for_bounty and a.eligible_for_submission]
    blocked  = [a for a in exact_hits if not (a.eligible_for_bounty and a.eligible_for_submission)]

    if not eligible:
        details = "; ".join(
            f"{a.asset_id} (bounty={a.eligible_for_bounty}, "
            f"submission={a.eligible_for_submission})"
            for a in blocked
        )
        return ValidationResult(
            allowed=False,
            reason=f"⛔ Target found but is OUT OF SCOPE / not bounty-eligible: {details}",
            blocked=blocked,
        )

    # At least one eligible hit → allow
    best = eligible[0]
    return ValidationResult(
        allowed=True,
        reason=(
            f"✅ Scope validated — matched '{best.asset_id}' "
            f"[{best.asset_type}] | max_severity={best.max_severity}"
            + (f" | note: {best.instruction}" if best.instruction else "")
        ),
        matched=eligible,
        blocked=blocked,
    )


def list_scope_summary(snapshots_dir: str) -> str:
    """Return a formatted summary of all scannable assets."""
    assets = load_all_assets(snapshots_dir)
    if not assets:
        return f"No scope data in {snapshots_dir}"

    eligible   = [a for a in assets if a.eligible_for_bounty and a.eligible_for_submission]
    oos        = [a for a in assets if not (a.eligible_for_bounty and a.eligible_for_submission)]

    lines = [
        f"📋 H1 Scope Snapshot  ({len(assets)} scannable assets total)\n",
        f"✅ Bounty-eligible ({len(eligible)}):",
    ]
    for a in eligible:
        lines.append(f"   {a.asset_id:<45} [{a.asset_type}]  max={a.max_severity}")

    lines += ["", f"⛔ Out-of-scope / no-bounty ({len(oos)}):"]
    for a in oos:
        lines.append(f"   {a.asset_id:<45} [{a.asset_type}]")

    return "\n".join(lines)
