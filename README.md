# shodan-mcp

Passive reconnaissance MCP server powered by Shodan.
Scope-gated against your HackerOne snapshots — identical gate to `nuclei-mcp`.

> **Passive only** — Shodan queries never send a packet to your target.
> All data comes from Shodan's pre-existing internet-wide scan index.

---

## Architecture

```
Claude/copilot (AI agent)
    │
    │  MCP (stdio)
    ▼
shodan-mcp container
    ├── reads scope ──► /data/snapshots/*.json  ◄─── h1-scope-watcher
    └── queries     ──► api.shodan.io  (passive, no target contact)
```

---

## Scope Gate

Every tool runs the same gate as `nuclei-mcp`:

1. Load all `*.json` from `/data/snapshots`
2. Exact → wildcard → fuzzy keyword match
3. Check `eligible_for_bounty` AND `eligible_for_submission`
4. **Block** if either is false — no override

[H1-Scope-Watcher](https://github.com/tobiasGuta/H1-Scope-Watcher)

---

## Quick Start

### 1. Build

```bash
cd shodan-mcp
docker build -t shodan-mcp .
```

### 2. Add to Claude/Copilot MCP config

```json
{
  "mcpServers": {
    "h1-scope-watcher": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "D:/projects/H1-Scope-Watcher/snapshots:/data/snapshots",
        "-e", "SNAPSHOTS_DIR=/data/snapshots",
        "mcp/h1-scope"
      ]
    },
    "nuclei-mcp": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "D:/projects/H1-Scope-Watcher/snapshots:/data/snapshots",
        "-e", "SNAPSHOTS_DIR=/data/snapshots",
        "nuclei-mcp"
      ]
    },
    "shodan-mcp": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "D:/projects/H1-Scope-Watcher/snapshots:/data/snapshots",
        "-e", "SNAPSHOTS_DIR=/data/snapshots",
        "-e", "SHODAN_API_KEY=YOUR_KEY_HERE",
        "shodan-mcp"
      ]
    }
  }
}
```

Replace `YOUR_KEY_HERE` with your key from https://account.shodan.io

---

## MCP Tools

### `shodan_host`

Resolve target → IP(s) → full Shodan host report.

| Parameter      | Type    | Default | Description                              |
|----------------|---------|---------|------------------------------------------|
| `target`       | string  | —       | Domain, URL, or fuzzy name               |
| `show_banners` | bool    | `false` | Include raw service banners (first 3 lines) |

**What you get per IP:**
- Open ports + transport protocol
- Service / product / version fingerprint
- CPE identifiers
- CVE list with CVSS scores and summaries
- ASN, ISP, org, geolocation, OS
- Shodan tags (e.g. `cloud`, `self-signed`, `vpn`)

**Example prompts:**
- *"Run shodan on dummy-target"*
- *"What ports does api.tile.com expose on Shodan?"*
- *"Check shodan for production.tile-api.com with banners"*

---

### `shodan_search`

Search Shodan's `hostname:` index — finds records across ALL IPs that
have ever served the hostname, including old/shadow infrastructure.

| Parameter     | Type | Default | Description              |
|---------------|------|---------|--------------------------|
| `target`      | str  | —       | Domain, URL, or keyword  |
| `max_results` | int  | `5`     | Max hosts (cap: 20)      |

**Example prompts:**
- *"Search Shodan for dummy-target — show me 10 results"*
- *"Any forgotten infrastructure for tile.com on Shodan?"*

---

### `shodan_dns`

Pull Shodan's **passive DNS** records — all subdomains, A/CNAME/MX/TXT
Shodan has ever observed for a root domain.

| Parameter | Type | Description          |
|-----------|------|----------------------|
| `target`  | str  | Domain or keyword    |

**Example prompts:**
- *"What subdomains does Shodan know about for dummy-target?"*
- *"Show me Shodan DNS records for tile.com"*

---

### `check_scope`

Preview scope gate without any API call.

---

### `list_programs`

List all H1 scope assets grouped by bounty eligibility.

---

## Shodan Plan Notes

| Plan         | `shodan_host` | `shodan_search` | `shodan_dns` |
|--------------|:---:|:---:|:---:|
| Free         | ✅  | ✅ (limited) | ❌ |
| Membership   | ✅  | ✅           | ✅ |
| API (paid)   | ✅  | ✅           | ✅ |

`shodan_dns` requires a paid Shodan plan.
The server validates your key and plan at startup and logs the result.

---

## Chained Workflow Example

```
You: "Full passive recon on dummy-target"

Claude/Copilot:
  1. check_scope("dummy-target")
    → ✅ api.dummy-target.com, api-cloudfront.dummy-target.com

  2. shodan_dns("dummy-target")
    → 14 subdomains discovered passively

  3. shodan_host("api.dummy-target.com")
    → Port 443 (nginx 1.18), Port 8443 (unknown)
    → CVE-2021-23017 CVSS 7.7 (nginx)

  4. shodan_search("dummy-target", max_results=10)
    → 3 IPs, one on non-standard port 9200 (Elasticsearch!)

  5. nuclei_scan("api.dummy-target.com")
    → Confirms Elasticsearch exposure
```

Zero packets sent to the dummy target until step 5.
