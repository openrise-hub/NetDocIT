# NetDocIT — Critical Fixes & Implementation Roadmap

Date: 2026-05-09
Scope: Top 5 critical issues blocking competitiveness against Advanced IP Scanner

---

## Issue 1: Replace subprocess ping with raw sockets

**Current state:** `scanner.py:_python_ping_sweep()` spawns `subprocess.run(["ping", ...])` per IP.
Each call forks a new OS process. On a /24 (254 hosts), that's 254 process forks.

**Target:** Use Python raw sockets (`AF_INET, SOCK_RAW, IPPROTO_ICMP`) to send ICMP echo
requests directly. This matches how Advanced IP Scanner operates.

**Implementation plan:**

### Phase 1A — ICMP socket module (new file)
- Create `src/backend/transports/icmp.py`
- Implement `IcmpScanner` class using `socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)`
- Payload: ICMP echo request (type 8, code 0), 32-byte payload, sequence number tracking
- Timeout model: send batch of N packets, `select()` / `poll()` for responses
- Windows caveat: raw sockets require admin/elevated privileges on modern Windows
  - Detection: check `IsUserAnAdmin()` before attempting raw socket path
  - Graceful fallback: if not admin, fall back to the existing `ping` subprocess path
- Concurrency: 64–128 concurrent ICMP probes via `ThreadPoolExecutor` or `asyncio`
  using a single raw socket (thread-safe with a send lock)

### Phase 1B — Benchmark harness (new file)
- Create `tools/benchmark_scan.py`
- Compare: old subprocess-ping vs new raw-socket ICMP on same /24 target
- Metrics: wall-clock time, hosts found, false positive rate
- Target: <5 seconds for a /24 subnet (Advanced IP Scanner benchmark)

### Phase 1C — Integration into `_python_ping_sweep()`
- Replace `_icmp_ping()` call with `IcmpScanner.batch_ping(ips)`
- Keep ARP pre-seeding path intact
- Keep TCP fallback intact (only triggers if ICMP yields zero results)
- Condition: only use raw socket path on Windows when admin; always on Linux/macOS

### Phase 1D — Tests
- `tests/test_icmp_scanner.py`: unit tests for packet construction, batch dispatch, timeout
- `tests/test_scan_speed.py` (update): assert /24 scan completes under 10s in safe profile

### Success criteria
- `/24 subnet scanned in <10s (safe profile), <5s (aggressive)`
- ICMP echo reply correctly parsed with RTT measurement
- Admin detection prevents crash on unprivileged Windows
- No process-spawning per IP in the primary code path

| Files to touch | Effort |
|---|---|
| `src/backend/transports/__init__.py` (new) | — |
| `src/backend/transports/icmp.py` (new) | Medium |
| `src/backend/scanner.py` | Small |
| `tools/benchmark_scan.py` (new) | Small |
| `tests/test_icmp_scanner.py` (new) | Medium |

---

## Issue 2: Add a GUI / Web Dashboard

**Current state:** Terminal-only Rich TUI. Network admins expect a visual interface.

**Target:** A web-based dashboard served locally that replicates the key workflows:
- Live scan view with sortable/filterable host table
- Click-to-copy IP/MAC, click to open HTTP/HTTPS/RDP
- Topology visualization
- Export buttons (CSV, JSON, HTML)

**Why web vs native GUI:**
- Python GUI libraries (tkinter, PyQt, wxPython) add heavy dependencies and packaging complexity
- A web dashboard uses the existing jinja2/markdown2/html skills from the reporting layer
- It runs in any browser on the scanning machine or remotely
- Works cross-platform if the Windows PowerShell dependency is ever relaxed

**Implementation plan:**

### Phase 2A — Lightweight HTTP server
- Use `http.server` from stdlib (no new dependency)
- Endpoint design:
  - `GET /` → SPA dashboard
  - `GET /api/devices` → JSON device list
  - `GET /api/scan/status` → current scan progress
  - `POST /api/scan/start` → trigger discovery
  - `GET /api/topology` → topology graph data
  - `GET /api/export/csv` → CSV download
  - `GET /api/export/json` → JSON download

### Phase 2B — SPA frontend (new directory)
- Create `src/presentation/web/`
- Single HTML file with embedded CSS/JS (no build step, no npm)
- Use a lightweight table/grid library or vanilla JS
- Features:
  - Sortable device table (IP, hostname, vendor, OS, confidence)
  - Search/filter bar
  - Click IP → copy to clipboard
  - Click hostname → attempt `http://hostname` in new tab
  - Action buttons: RDP (`mstsc /v:ip`), ping, traceroute
  - Live scan progress bar with ETA
  - Embedded topology from pyvis (already generated as topology.html)
  - "Last scan" timestamp and drift summary

### Phase 2C — CLI integration
- New subcommand: `netdocit web` or `netdocit serve`
- Binds to `localhost:8080` by default, configurable port
- Opens browser automatically (`webbrowser.open()`)
- Runs scan on startup if `--scan` flag provided
- Exits on Ctrl+C

### Phase 2D — Keep TUI as fallback
- `netdocit` with no args still opens TUI
- `netdocit web` opens web dashboard
- `netdocit scan --quiet` runs headless

### Success criteria
- Dashboard loads in browser at `localhost:8080`
- Device table populates from last scan or live scan
- Actions (copy IP, open RDP, open HTTP) function correctly
- Zero npm/build dependencies — single `.html` file with inline everything

| Files to touch | Effort |
|---|---|
| `src/presentation/web/__init__.py` (new) | — |
| `src/presentation/web/server.py` (new) | Medium |
| `src/presentation/web/dashboard.html` (new) | Large |
| `src/main.py` | Small |

---

## Issue 3: Add Port Scanning & Service Detection

**Current state:** No port scanning. TCP connect is only used as an ICMP fallback for
liveness (`_tcp_connect` in `scanner.py`). No service identification beyond WMI/SNMP.

**Target:** Fast configurable port sweep with service fingerprinting on live hosts.

**Implementation plan:**

### Phase 3A — Port scan module
- Create `src/backend/transports/tcp_scan.py`
- `TcpPortScanner` class:
  - Configurable port list: default `[21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 3389, 8080, 8443]`
  - Half-open (SYN) scan on admin Windows using raw sockets (fast, stealthy)
  - Connect scan fallback on non-admin (slower, uses OS TCP stack)
  - Concurrent per host: scan all ports on a host in parallel
  - Concurrent across hosts: scan multiple hosts simultaneously
  - Timeout per port: 200ms default, adaptive based on RTT

### Phase 3B — Service fingerprinting
- Create `src/backend/transports/fingerprint.py`
- Banner grab on connect: for HTTP, SMTP, FTP, SSH — read first 256 bytes after connect
- Identify services:
  - Port 22 → SSH (check banner for "SSH")
  - Port 80/8080 → HTTP (send `GET / HTTP/1.0\r\n\r\n`, parse `Server:` header)
  - Port 443/8443 → HTTPS (detect TLS handshake, not full connection)
  - Port 445 → SMB (check for SMB negotiation)
  - Port 3389 → RDP (check for RDP negotiation header)
  - Port 21 → FTP (check for "220" banner)
  - Port 25 → SMTP (check for "220" banner)
- Store results as `EvidenceRecord` (already defined in `evidence_model.py`)
- Feed into existing `service_fingerprint.py` pipeline

### Phase 3C — Integration into discovery pipeline
- After ICMP ping sweep, before WMI/SNMP enrichment, run port scan on live hosts
- Add `ProbeTask` entries for `tcp` probe type (already defined in `PROBE_TYPES`)
- `AdaptiveProbeScheduler` already supports `tcp` worker pool
- Add port scan results to `host_data` or a new `service_data` key in summary
- Display open ports in TUI device detail panel and web dashboard

### Phase 3D — Tests
- `tests/test_tcp_port_scanner.py`
- `tests/test_service_fingerprint.py` (update existing)

### Success criteria
- `/24 port scan completes in <30s (top 13 ports per host)`
- Services correctly identified for HTTP, SSH, RDP, SMB at >90% accuracy
- Open ports displayed per device in both TUI and web UI

| Files to touch | Effort |
|---|---|
| `src/backend/transports/tcp_scan.py` (new) | Medium |
| `src/backend/transports/fingerprint.py` (new) | Medium |
| `src/backend/discovery.py` | Small |
| `src/backend/adaptive_scheduler.py` | Small (tcp pool already exists) |
| `src/presentation/tui.py` | Small |
| `tests/test_tcp_port_scanner.py` (new) | Small |

---

## Issue 4: Drop Python 3.14 requirement to 3.10+

**Current state:** `pyproject.toml` declares `requires-python = ">=3.14"`.
Python 3.14 is not stable. No enterprise environment, no package manager, no CI runner
ships with it. This single line blocks all real-world adoption.

**Target:** Support Python 3.10 through 3.14. Python 3.10 is the oldest version
still receiving security updates and is widely deployed on Windows (shipped with
VS 2022 tools, available in winget/chocolatey/scoop).

**Implementation plan:**

### Phase 4A — Audit dependencies for 3.10 compatibility
- Check each dependency's minimum Python version:
  - `jinja2>=3.1.6` — supports 3.7+
  - `markdown2>=2.5.5` — supports 3.7+
  - `networkx>=3.6.1` — needs checking (3.x line may require 3.10+)
  - `pysnmp>=7.1.15` — supports 3.8+
  - `pyvis>=0.3.2` — supports 3.8+
  - `rich>=14.3.3` — supports 3.8+
- Likely result: all dependencies support 3.10+ without changes

### Phase 4B — Code compatibility audit
- Check for Python 3.11+ only syntax:
  - `Self` type (3.11) — not used in codebase
  - `except*` (3.11) — not used
  - PEP 695 type params (3.12) — not used
  - `type` statement (3.12) — not used
  - `@override` (3.12) — not used
  - PEP 701 f-strings (3.12) — check usage
- Check stdlib imports for 3.10 availability
- The `msvcrt` shim uses `ModuleNotFoundError` which exists in 3.6+ — fine

### Phase 4C — Update metadata
- `pyproject.toml`: `requires-python = ">=3.10"`
- `.python-version`: `3.10`
- `uv.lock`: regenerate with `uv lock` targeting 3.10
- `README.md`: update version requirement
- `Roadmap.md` and any docs referencing Python version

### Phase 4D — CI matrix
- Update `.github/workflows/python-ci.yml`:
  - Test matrix: `[3.10, 3.11, 3.12, 3.13, 3.14]`
  - Windows runner for 3.10 and latest
  - Ubuntu runner for all versions

### Success criteria
- `uv run netdocit` works on Python 3.10, 3.11, 3.12, 3.13, 3.14
- CI passes on all versions
- No runtime `SyntaxError` or import failures on 3.10

| Files to touch | Effort |
|---|---|
| `pyproject.toml` | Trivial |
| `.python-version` | Trivial |
| `uv.lock` | Regenerate |
| `.github/workflows/python-ci.yml` | Small |
| `README.md` | Trivial |

---

## Issue 5: Fix MAC Resolution in Python Fallback Scanner

**Current state:** `_python_ping_sweep()` returns `"mac": None` for all devices.
`_parse_arp_table()` parses `arp -a` output but only extracts IPs, discarding MACs.
The PowerShell `ping_sweep.ps1` correctly resolves MACs via `Get-NetNeighbor`, but
it's never called (Issue 1 of the full report).

**Target:** Every discovered host has a MAC address when available from the ARP table.

**Implementation plan:**

### Phase 5A — Fix `_parse_arp_table()` to return IP → MAC mapping
- Current return type: `list[str]` (just IPs)
- New return type: `dict[str, str]` → `{ip: mac}`
- Parse the Windows `arp -a` output format:
  ```
  Interface: 192.168.1.10 --- 0x5
    Internet Address      Physical Address      Type
    192.168.1.1           00-11-22-33-44-55     dynamic
    192.168.1.5           aa-bb-cc-dd-ee-ff     dynamic
  ```
- Regex: `r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})"`
- Normalize MAC format: uppercase, colon-separated (`00:11:22:33:44:55`)

### Phase 5B — Update `_python_ping_sweep()` to use MAC mapping
- After ARP parse, build `arp_map: dict[str, str]`
- When building result dicts, look up MAC from `arp_map`:
  ```python
  {"ip": ip, "mac": arp_map.get(ip), "hostname": ip}
  ```
- For seeded ARP IPs that responded, MAC is already known
- For newly discovered ICMP responders, also try reverse ARP lookup
  (run `arp -a` again after pings, since Windows populates the ARP cache on outbound ping)

### Phase 5C — Add reverse DNS resolution (bonus)
- After MAC fix, add optional `socket.gethostbyaddr()` for hostname resolution
- Timeout-wrapped (can be slow), disabled by default, enabled via `--resolve-hostnames`

### Phase 5D — Restore or deprecate `ping_sweep.ps1`
- Option A: Fix any PowerShell parse errors and re-enable the PowerShell path
  as an alternative (faster ARP resolution via `Get-NetNeighbor`)
- Option B: Acknowledge it as deprecated and remove the file
- Recommendation: Option A — keep PowerShell as the primary path on Windows
  with the Python fallback for headless/core servers without PowerShell

### Phase 5E — Tests
- `tests/test_arp_parser.py`: parse real `arp -a` output samples, verify MAC extraction
- `tests/test_ping_sweep_script.py` (update): assert MAC is not None for ARP-resolvable IPs

### Success criteria
- `_parse_arp_table()` returns correct `{ip: mac}` mapping
- `_python_ping_sweep()` output includes MAC for ARP-cached hosts
- No regression: existing tests pass with updated return types

| Files to touch | Effort |
|---|---|
| `src/backend/scanner.py` | Medium |
| `tests/test_arp_parser.py` (new) | Small |
| `tests/test_ping_sweep_script.py` | Small |

---

## Execution Order Recommendation

```
Week 1-2:  Issue 4 (Python 3.10) → Issue 5 (MAC resolution)
           Rationale: Fast wins, unblock CI, fix data quality immediately

Week 3-4:  Issue 1 (Raw socket ICMP)
           Rationale: Biggest perf win, requires Issue 5's ARP fix first

Week 5-6:  Issue 3 (Port scanning + service detection)
           Rationale: Builds on Issue 1's transport layer

Week 7-9:  Issue 2 (Web dashboard)
           Rationale: Largest effort, builds on all previous fixes for display data
```

---

## Appendix: Full Audit Report

### Critical Issues
1. PowerShell `ping_sweep.ps1` is dead code — always redirected to Python fallback
2. Python ping sweep uses `subprocess.run("ping")` per IP — extremely slow
3. No real MAC resolution in Python fallback — all MACs are `None`
4. `python >=3.14` requirement blocks nearly all real-world users
5. `discover_all()` is a 600-line god function with 4 repeated summary dicts

### Major Feature Gaps vs Advanced IP Scanner

| Feature | Advanced IP Scanner | NetDocIT |
|---|---|---|
| GUI | Native Win32 GUI | Terminal-only (Rich TUI) |
| Port scanning | Yes (configurable) | No |
| HTTP/HTTPS browser | Built-in | None |
| FTP browser | Built-in | None |
| RDP/Radmin launcher | One-click | None |
| NetBIOS/mDNS/LLMNR | Yes | No |
| Wake-on-LAN | Yes | No |
| Remote shutdown | Yes | No |
| CSV export | Yes | No (JSON/HTML/MD only) |
| Right-click actions | Extensive context menu | Keyboard-only shortcuts |
| Favorites/bookmarks | Yes | No |
| Scan speed | Sub-second per /24 (raw sockets) | Minutes (subprocess per IP) |
| Dead host history | Shows last-seen alongside live | DB only, not surfaced in TUI |
| Shared folder detection | Yes | No |

### Performance & Architecture Issues

6. **SQLite connection per operation** — `database.py` opens/closes a connection for every CRUD call. No WAL mode, no connection pooling.
7. **`devices` table fully cleared per ingestion** — `DELETE FROM devices` on every scan loses history.
8. **TCP fallback is extremely aggressive** — 9 ports x 128 IPs = 1152 connections, triggers IDS/IPS.
9. **Repeated `load_config()` calls** — called in `discover_all()`, `report_readiness()`, `processor.py`.
10. **No incremental/differential scanning** — every scan is full sweep despite existing temporal state model.

### Usability & UX Issues

11. **Terminal-only — no GUI** — biggest adoption barrier for network admins.
12. **Only 20 devices visible at once** — `tui.py:292` hardcodes `visible_devices[:20]`.
13. **CLI dispatch is fragile** — `nargs="*"` plus manual string-splitting for `schedule` prefix.
14. **Module-level mutable global `QUIET`** — state leak if `main()` called twice.
15. **No progress bar / ETA during scan** — users have no idea how long remains.

### Security Concerns

16. **Hardcoded default SNMP communities** — `["public", "monitor", "read-only"]` in `secrets.py`.
17. **SNMP community strings in process listings** — PowerShell command lines are visible in Task Manager.
18. **No encrypted credential storage** — plaintext in both config file and SQLite `credentials` table.
19. **No scope policy validation on CLI overrides** — `--community` and `--timeout` bypass config.

### Code Quality Issues

20. **Duplicate imports** — `src/main.py:145` re-imports already-imported functions.
21. **`time` imported mid-file** — `src/main.py:191`.
22. **`_as_dict_list` duplicated** — defined locally in `discovery.py` and duplicated in `database.py`.
23. **Missing type annotations** — `scanner.py`, `processor.py`, `topology.py`.
24. **SNMP engine has independent config loading** — `snmp_engine.py` bypasses `config_parser.py`.
25. **Bare try/except in scan thread** — `src/main.py:287` catches `Exception` but the prior audit's bare `except: pass` was fixed.

### Test Quality Concerns

26. **No end-to-end integration test** — 78 unit tests but no full `discover_all()` pipeline test.
27. **Ubuntu CI can't test PowerShell code path** — primary Windows path untested in CI.
