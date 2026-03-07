# 🌳 Cthaeh

*"It sees all the ways the future can branch and blossom from a single moment."*

Ghidra-powered triage scanner for Windows kernel drivers. Scores drivers on 97 vulnerability heuristics so you know which `.sys` files to pull apart first.

Cthaeh doesn't find vulnerabilities. It finds the drivers most likely to *have* them.

## Quick Start

```bash
pip install -r requirements.txt
python download_dta.py                              # Talos type archive (once)
python extract_driverstore.py --output C:\drivers   # Pull third-party drivers

python run_triage.py C:\drivers                     # Scan (only loaded drivers by default)
python run_triage.py C:\drivers --all               # Scan everything
python run_triage.py --single C:\path\to\driver.sys # Single driver
python run_triage.py --explain example.sys          # Explain a score
```

Set `GHIDRA_HOME` and you never need `--ghidra`. Pre-filter, parallel workers, JSON, and markdown report are all on by default.

## How It Works

1. **Running-only filter** (Windows default): scans only loaded drivers. `--all` to override.
2. **Pre-filter** (pefile): drops uninteresting drivers in milliseconds (~37% eliminated)
3. **Parallel Ghidra headless**: N workers (auto = half CPUs)
4. **97 heuristic checks**: dangerous primitives, IOCTL surface, BYOVD, validation gaps, memory corruption, vendor context, and more
5. **Enriched output**: CSV + JSON + markdown report with vendor/CNA status, prior CVEs, and actionable recommendations

## Priority Tiers

| Tier | Threshold | Action |
|------|-----------|--------|
| 💀 CRITICAL | ≥250 | Drop everything and analyze |
| 🔴 HIGH | ≥150 | Investigate soon |
| 🟡 MEDIUM | ≥75 | Worth a look |
| 🟢 LOW | ≥30 | Probably boring |
| ⚪ SKIP | <30 | Move on |

## Explain Mode

```bash
python run_triage.py --explain example.sys
```

```
============================================================
  Driver: example.sys v1.0.2.5 (Example Corp.)
============================================================
  Vendor: Example Corp. (CNA: YES) | Bounty: PRESENT
  Prior CVEs: 3 (CVE-2024-1234, CVE-2023-5678, CVE-2022-9012)
  Score: 285 | Priority: CRITICAL
  Hardware: PRESENT (Intel Wi-Fi 6 AX201)
  Priority: CRITICAL - IMMEDIATE - full reverse engineering, build PoC exploit

  Scored checks:
    + 25  [msr_write] Contains WRMSR instruction(s)
    + 20  [symlink_no_acl] Symbolic link + IoCreateDevice without Secure
    + 20  [port_io_rw] Port I/O: 12 IN + 8 OUT instructions
    ...
    Positive: +285 | Negative: 0 | Net: 285
```

## Investigated Drivers

Already-analyzed drivers go in `investigated.json` and are skipped on future scans:

```json
{
  "investigated": {
    "example.sys": "4 vulns submitted to vendor PSIRT"
  }
}
```

## The Workflow

```
DriverStore --> extract --> running-only --> pre-filter --> Cthaeh --> ranked list --> manual audit
                                                                                        |
                                                           Claude Code + Ghidra MCP --> vuln
```

## Requirements

- Python 3.8+ with `pefile`
- Ghidra 10.x+ (headless mode)
- Windows for DriverStore extraction (analysis works on any OS)

See [REFERENCE.md](REFERENCE.md) for full flag list, check categories, anti-pattern tags, and file descriptions.

## Acknowledgments

- [HolyGrail](https://github.com/BlackSnufkin/Holygrail) (BlackSnufkin) — WDAC + LOLDrivers
- [Rhabdomancer](https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java) (0xdea) — candidate point strategy
- [KernelSight](https://splintersfury.github.io/KernelSight/guides/secure-driver-anatomy/) — anti-pattern taxonomy (134 CVEs)
- [DriverAtlas](https://github.com/splintersfury/DriverAtlas) (splintersfury) — framework detection
- [Cisco Talos](https://github.com/Cisco-Talos/Windows-drivers-GDT-file) — Windows driver data type archive

## License

MIT

---

*"The Cthaeh does not lie. The Cthaeh sees the true shape of the world."*
