# 🌳 Cthaeh

*"It sees all the ways the future can branch and blossom from a single moment."*

Ghidra-powered triage scanner for Windows kernel drivers. Scores drivers on 97 vulnerability heuristics: dangerous primitives, IOCTL attack surface, missing validation, BYOVD patterns, and more. So you know which `.sys` files to pull apart first.

Named after the all-seeing tree from *The Kingkiller Chronicle*.

Cthaeh doesn't find vulnerabilities. It finds the drivers most likely to *have* them.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Download Talos data type archive (once, for better Ghidra type recovery)
python download_dta.py

# Extract third-party drivers from your machine
python extract_driverstore.py --output C:\drivers\extracted

# Run triage (smart defaults — on Windows, only loaded drivers are scanned)
python run_triage.py C:\drivers\extracted

# Scan all drivers, not just running ones
python run_triage.py C:\drivers\extracted --all

# Or point at your Ghidra install explicitly
python run_triage.py C:\drivers\extracted --ghidra C:\ghidra_11.3

# Single driver (--running-only is skipped in single mode)
python run_triage.py --single C:\path\to\suspicious.sys

# Explain a specific driver's score (no rescan needed)
python run_triage.py --explain example.sys
```

**That's it.** Pre-filter, parallel workers, JSON output, and markdown report are all on by default. Set `GHIDRA_HOME` env var and you never need `--ghidra` again.

## What It Does

1. **Running-only filter** (Windows default): only loaded drivers via `driverquery`. `--all` to override.
2. **Pre-filter** (pefile): eliminates uninteresting drivers in milliseconds (~37% dropped)
3. **Parallel Ghidra headless**: analyzes remaining drivers with N workers (auto = half your CPUs)
4. **97 heuristic checks**: scores each driver on vulnerability indicators
5. **Ranked output**: CSV, JSON, and markdown report with vendor/CNA status, prior CVEs, and priority recommendations

## Scoring

All weights live in `scoring_rules.yaml`. Both `driver_triage.py` (Ghidra/Jython) and `prefilter.py` load from it. Missing file? They fall back to hardcoded defaults.

### Check Categories

| Category | Checks | What it catches |
|----------|--------|-----------------|
| **Device security** | IoCreateDevice vs Secure, symlink+no ACL, WDM vs WDF | Weak access controls |
| **IOCTL surface** | Dispatched IOCTL count, METHOD_NEITHER, FILE_ANY_ACCESS | Attack surface size |
| **Dangerous primitives** | MSR R/W, CR access, physical memory mapping, port I/O | Kernel-level capabilities |
| **BYOVD** | Process open + terminate, token steal, DSE bypass | Weaponizable drivers |
| **Validation gaps** | No ProbeForRead/Write, no auth imports, unchecked memcpy | Missing input validation |
| **USB/BT** | URB construction, HCI passthrough, eFuse access | Hardware control passthrough |
| **Firmware** | UEFI variables, HAL bus data, hardcoded crypto keys | Firmware manipulation |
| **Vendor context** | CNA status, bounty programs, driver class (WiFi bonus, audio penalty) | Vuln assignment likelihood |
| **Compound scoring** | MSR+PhysMem=god-mode, IOCTL+no-auth+named-device=easy target | Multi-primitive combinations |
| **Kernel Rhabdomancer** | Per-function candidate point mapping, call graph from IOCTL dispatch, missing validation detection | Pinpoints *where* dangerous APIs are called, not just that they're imported |
| **Vuln pattern** | IOCTL surface + dangerous primitive + missing validation | Pattern from 8 confirmed vulns |
| **WDAC block policy** | Checks Win10/Win11 driver block policy by SHA256 + filename | Skips already-blocked drivers |
| **LOLDrivers (HolyGrail)** | Cross-references SHA256 against HolyGrail's curated LOLDrivers list | Flags known LOLDrivers for variant research |
| **Comms capability** | IoCreateDevice, IoCreateSymbolicLink, FltRegisterFilter, FltCreateCommunicationPort | User-mode attackable bridge detection |
| **PPL killer** | ZwTerminateProcess + ZwOpenProcess/PsLookupProcessByProcessId combo | Protected process termination potential |
| **Enhanced imports** | MmCopyMemory, ZwReadVirtualMemory, KeStackAttachProcess, IoAllocateMdl, etc. | Expanded dangerous primitive coverage |
| **Memory corruption** | UAF, double-free, free-without-null in IOCTL dispatch paths | Instruction-level pattern analysis |
| **BYOVD expanded** | Arbitrary R/W via MmMapIoSpace, kernel execute via APC/WorkItem, PID termination | Full exploitation primitive coverage |
| **IORING surface** | IORING APIs, shared memory section patterns | Novel kernel attack surface detection |
| **Killer driver** | Process enum+kill, callback removal, minifilter unload, EDR product strings | EDR/AV termination pattern detection |
| **Bloatware/OEM** | Consumer OEM vendor boost, utility driver strings, PE age | Prioritizes historically weak vendors |
| **Double-fetch / TOCTOU** | User buffer pointer read multiple times without local capture | Race condition patterns in IOCTL handlers |
| **On-disk offset trust** | Parsed offsets used without bounds checking in FS/minifilter drivers | Trusted offset → OOB read/write |
| **Framework detection** | WDF vs WDM detection, auto-adjusts scoring | WDF drivers get less noise, WDM gets more scrutiny |

### Priority Tiers

| Tier | Threshold | Meaning |
|------|-----------|---------|
| 💀 CRITICAL | ≥250 | Drop everything and analyze (~1% of drivers) |
| 🔴 HIGH | ≥150 | Strong candidate, investigate soon |
| 🟡 MEDIUM | ≥75 | Worth a look |
| 🟢 LOW | ≥30 | Probably boring |
| ⚪ SKIP | <30 | Move on |

### Investigated Drivers

Drivers you've already analyzed go in `investigated.json`:

```json
{
  "investigated": {
    "example.sys": "4 vulns submitted to vendor PSIRT",
    "another.sys": "FP - WDF device interface blocks unprivileged access"
  }
}
```

These are skipped on future scans, labeled `INVESTIGATED` in output.

### Anti-Pattern Tags

Findings are tagged with KernelSight anti-patterns (AP1-AP6) when they match known vulnerability patterns:

| Tag | Pattern | CVE frequency |
|-----|---------|---------------|
| AP1 | Trusting user-supplied lengths | ~60% of driver CVEs |
| AP2 | Missing synchronization on shared state | ~14% |
| AP3 | Trusting on-disk/file-embedded offsets | FS/minifilter bugs |
| AP4 | Exposing physical memory or MSR access | God-mode primitives |
| AP5 | No IOCTL auth / open device ACLs | Easy targets |
| AP6 | Double-fetch / TOCTOU on user buffers | Race conditions |

Reports show which anti-patterns each driver triggers, so you know *what class* of bug to look for.

### Data Type Archive

Cthaeh can auto-load the [Cisco Talos Windows Driver DTA](https://github.com/Cisco-Talos/Windows-drivers-GDT-file) during analysis. This gives Ghidra proper type definitions for 45+ Windows kernel functions that it doesn't know natively.

```bash
python download_dta.py   # fetches .gdt to data/
```

When `data/windows_driver_types.gdt` exists, Ghidra automatically applies it as a pre-script before each analysis run. No flags needed.

## Output

Every scan produces (by default):

| File | Content |
|------|---------|
| `triage_results.csv` | Ranked results with top checks |
| `triage_results.json` | Full results with all findings per driver |
| `triage_report.md` | Markdown report with scoring breakdowns for top 20 |

### Explain Mode

Inspect any driver's scoring without re-scanning:

```bash
python run_triage.py --explain example.sys
```

```
============================================================
  Driver: example.sys v1.0.2.5 (Example Corp.)
============================================================
  Vendor: Example Corp. (CNA: YES | Bounty: PRESENT)
  Prior CVEs: 3 (CVE-2024-1234, CVE-2023-5678, CVE-2022-9012)
  Score: 285 | Priority: CRITICAL
  Size: 148,224 bytes | Functions: 47
  Driver Class: NETWORK (WiFi)
  Hardware: PRESENT (Intel Wi-Fi 6 AX201)
  Device Access: Users (\\.\ExampleDev)
  Priority: CRITICAL - IMMEDIATE - full reverse engineering, build PoC exploit

  Scored checks:
    + 25  [msr_write] Contains WRMSR instruction(s)
    + 20  [symlink_no_acl] Symbolic link + IoCreateDevice without IoCreateDeviceSecure
    + 20  [port_io_rw] Port I/O: 12 IN + 8 OUT instructions
    + 15  [wifi_driver] WiFi driver - massive IOCTL/WDI attack surface
    ...

    Positive: +285 | Negative: 0 | Net: 285

  Informational (4 checks, 0 pts each):
    [0]  [wdac_not_blocked] Not on WDAC block list
    ...
```

The top scorer is auto-explained after every scan.

## Files

| File | Purpose |
|------|---------|
| `driver_triage.py` | Ghidra headless script (97 checks, configurable weights) |
| `run_triage.py` | Orchestrator (parallel, prefilter, running-only filter, explain, smart defaults) |
| `prefilter.py` | Fast PE import pre-filter |
| `extract_driverstore.py` | Extracts third-party .sys from Windows DriverStore |
| `scoring_rules.yaml` | All scoring weights and thresholds in one place |
| `apply_dta.py` | Ghidra pre-script: loads Talos DTA for kernel types |
| `download_dta.py` | Downloads the Talos .gdt file to `data/` |
| `hw_check.py` | Post-triage hardware presence check via PnP device enumeration |
| `device_check.py` | Post-triage device object DACL check for access levels |
| `cna_vendors.json` | CNA status, bounty URLs, and driver patterns per vendor |
| `driver_cves.json` | Prior CVE history mapped to driver families |
| `investigated.json` | Drivers already analyzed (skipped on scan) |
| `policies/` | WDAC block policy JSONs and HolyGrail LOLDrivers data |
| `test_regression.py` | Regression tests against known ground-truth samples |

## CLI Reference

```
python run_triage.py C:\drivers                    # Scan with smart defaults (running-only on Windows)
python run_triage.py C:\drivers --all              # Scan ALL drivers, not just running ones
python run_triage.py C:\drivers --no-prefilter     # Skip pre-filter
python run_triage.py --single C:\path\to\driver.sys  # Single driver (running-only skipped)
python run_triage.py --explain example.sys         # Explain existing results
python run_triage.py C:\drivers --workers 8        # Override worker count
python run_triage.py C:\drivers --no-json --no-report  # CSV only
python run_triage.py C:\drivers --hw-check         # Check hardware presence post-triage
python run_triage.py C:\drivers --device-check     # Check device DACLs post-triage
python run_triage.py C:\drivers --device-check --device-check-min-score 50  # Lower threshold
python run_triage.py C:\drivers --research         # Research mode (hw_absent is informational)
```

| Flag | Default | Description |
|------|---------|-------------|
| `--running-only` | ON | Only scan currently loaded drivers (Windows, uses `driverquery`) |
| `--all` | OFF | Scan all drivers, overrides `--running-only` |
| `--hw-check` | OFF | Post-triage hardware presence check (Windows only) |
| `--device-check` | OFF | Post-triage device object DACL check (Windows only) |
| `--device-check-min-score` | 75 | Minimum score for device check |
| `--research` | OFF | Research mode: hardware_absent is informational only |
| `--workers N` | auto | Parallel Ghidra instances (default: half CPUs) |
| `--no-prefilter` | OFF | Disable pefile pre-filter |
| `--no-json` | OFF | Disable JSON output |
| `--no-report` | OFF | Disable markdown report |

**Environment variables:**
- `GHIDRA_HOME` - Path to Ghidra installation (auto-detected if not set)
- `CTHAEH_FP_PATH` - Override path to investigated.json
- `CTHAEH_DTA_PATH` - Override path to .gdt data type archive

## Performance

| Drivers | Mode | Time |
|---------|------|------|
| 340 | Pre-filter + 5 workers | ~1.5 hours |
| 340 | Pre-filter + sequential | ~6 hours |
| 533 | No filter + sequential | ~44 hours |

## The Workflow

```
DriverStore --> extract --> running-only --> pre-filter --> Cthaeh triage --> ranked list --> manual audit
                           [Win default]    (pefile)       (97 checks)                         |
                                                                          Claude Code + Ghidra MCP --> vuln
```

## Requirements

- Python 3.8+
- Ghidra 10.x+ (headless mode)
- `pip install -r requirements.txt` (pefile)
- Windows (for DriverStore extraction; analysis works on any OS)

## Acknowledgments

- WDAC block policy checking and LOLDrivers cross-reference inspired by [HolyGrail](https://github.com/BlackSnufkin/Holygrail) by BlackSnufkin.
- Kernel Rhabdomancer candidate point strategy inspired by [Rhabdomancer.java](https://github.com/0xdea/ghidra-scripts/blob/main/Rhabdomancer.java) by Marco Ivaldi (0xdea). See also: [Automating binary vulnerability discovery with Ghidra and Semgrep](https://hnsecurity.it/blog/automating-binary-vulnerability-discovery-with-ghidra-and-semgrep/).
- Anti-pattern tagging (AP1-AP6) based on [KernelSight](https://splintersfury.github.io/KernelSight/guides/secure-driver-anatomy/) vulnerability root cause analysis across 134 CVEs.
- Framework detection and YAML scoring inspired by [DriverAtlas](https://github.com/splintersfury/DriverAtlas) by splintersfury.
- Ghidra Data Type Archive for Windows drivers by [Talos Intelligence](https://blog.talosintelligence.com/ghidra-data-type-archive-for-windows-drivers/).
- Windows driver data type archive from [Cisco Talos](https://github.com/Cisco-Talos/Windows-drivers-GDT-file). Blog post: [Ghidra data type archive for Windows drivers](https://blog.talosintelligence.com/ghidra-data-type-archive-for-windows-drivers/).

## License

MIT

---

*"The Cthaeh does not lie. The Cthaeh sees the true shape of the world."*
