# NetDocIT

NetDocIT is a Windows-first network discovery and documentation tool.
It collects interface and route information, performs live host discovery, enriches data with host and SNMP details, and exports topology and inventory reports.

## Requirements

For contributors, maintainers, and users forking this repository:

- Python 3.14+
- Windows PowerShell (for discovery scripts)

For end users using the packaged installer:

- No Python setup required

## Installation

Using `uv`:

```powershell
uv sync
```

Using `pip`:

```powershell
python -m pip install -e .
```

## Quick Start

Run full discovery and generate reports:

```powershell
uv run netdocit scan
```

Run report generation from stored data:

```powershell
uv run netdocit report
```

Generate topology from stored data:

```powershell
uv run netdocit map
```

Open interactive dashboard:

```powershell
uv run netdocit
```

## Outputs

- `REPORT.md`: Markdown inventory report
- `inventory.html`: Printable HTML inventory dashboard
- `topology.html`: Interactive topology map
- `data/netdocit.sqlite`: Local scan database

Generated report/map artifacts are intended as runtime outputs and can be regenerated on demand.

## Source Of Truth

- SNMP enrichment source of truth: `src/backend/snmp_engine.py` (Python `pysnmp` implementation)

## Version Control Policy

- Commit source code, tests, templates, and configuration
- Do not rely on committed generated artifacts for operational state
- Regenerate `REPORT.md`, `inventory.html`, and `topology.html` from current scan data when needed

## Commands

- `scan` / `discover`: Run full discovery pipeline
- `report`: Build report artifacts from database state
- `map`: Build topology artifact from database state
- `logs`: Show persisted scanner logs
- `schedule --time HH:mm`: Register daily scheduled scan task (Administrator required)

## Testing

```powershell
python -m unittest discover -v
```

## Notes

- The discovery pipeline is currently Windows-oriented because it depends on PowerShell scripts and Windows networking cmdlets.
- SNMP enrichment is handled in Python via `pysnmp`.
