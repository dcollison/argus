# Rhada

Rhada is a compliance, Software Bill of Materials (SBOM), binary linkage, and security vulnerability auditor for Python source workspaces and compiled Linux distributions (Nuitka and PyInstaller).

## Overview

1. **Dual-Mode Operation**
   - **Source Mode (default when `--dist` is omitted):** Inspects Python source workspaces. Supports modern PEP 621 / `uv` projects (`pyproject.toml`, `uv.lock`) as well as legacy `setuptools` and pip workspaces (`setup.py`, `setup.cfg`, `requirements.txt`). `setup.py` is safely inspected using static Abstract Syntax Tree (AST) parsing without executing untrusted code. Discovers installed package metadata across virtual environments (`.venv`, `venv`, `env`) to separate direct runtime dependencies from development/build tools, extract SPDX licence metadata, and check for security advisories.
   - **Compiled Distribution Mode (`--dist <path>`):** Audits Nuitka and PyInstaller artefacts, including standalone directories (`app.dist/`, `dist/app/`) and monolithic single-file binaries (`app.bin`). Identifies bundled Python modules (excluding build and test tools such as `pytest`, `ruff`, `mypy`, `nuitka`, and `pyinstaller`), inspects bundled native shared libraries (`.so`), and verifies ELF dynamic linkage.

2. **Legal and Licence Compliance**
   - Parses and normalises `METADATA` licence headers, PEP 639 `License-Expression` fields, Trove classifiers, and verbatim licence texts into canonical SPDX identifiers and compound expressions (`MIT OR Apache-2.0`, `GPL-2.0-only AND BSD-3-Clause`) using `license-expression`.
   - Categorises licence risk (`permissive`, `public-domain`, `weak-copyleft`, `strong-copyleft`, `proprietary`, `unknown`) and evaluates redistribution rules:
     - Flags strong copyleft (`GPL-*`, `AGPL-*`, `SSPL-1.0`) obligations (`LIC-COP-STRONG`, `LIC-COP-NETWORK`).
     - Detects LGPL relinking issues (`LIC-LGPL-MONOLITHIC`) when weak-copyleft libraries are statically compiled or embedded into monolithic binaries without dynamic `.so` relinking support.
   - Generates a `THIRD_PARTY_NOTICES` attribution file containing component inventory, copyright notices, `NOTICE` / `AUTHORS` files, and verbatim licence texts.

3. **ELF Binary and Native Library Inspection**
   - Parses 32-bit and 64-bit ELF executables and `.so` libraries via `pyelftools` with a `struct` fallback for stripped or header-truncated binaries.
   - Extracts `DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, `DT_RUNPATH`, `PT_INTERP`, exported symbols (`PyInit_*`, `modulecode_*`), and embedded library version strings (`OpenSSL`, `zlib`, `SQLite`, `libffi`, `gmp`, `readline`, etc.).
   - Verifies whether each `DT_NEEDED` shared library is resolved within the distribution, satisfied by the baseline Linux/glibc ABI, or missing as an unbundled external dependency, and flags insecure RPATH/RUNPATH tokens.

4. **Security Vulnerability Auditing**
   - Integrates `pip-audit` (`OsvService` and `ResolvedDependency`) alongside the OSV.dev batch API (`/v1/querybatch`) and advisory endpoints (`/v1/vulns/{id}`) for discovered Python packages and versioned native libraries.
   - Calculates CVSS v3.0/v3.1 base scores using `cvss` and summarises findings by severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) with fixed version recommendations.

5. **Standards-Compliant SBOMs and CLI Exit Codes**
   - Generates **CycloneDX 1.5 JSON** (via `cyclonedx-python-lib` and `packageurl-python`) and **SPDX 2.3 JSON** SBOMs.
   - Provides a typed CLI built with `typer` and deterministic exit codes for CI/CD enforcement.

## Installation

Manage and install with [`uv`](https://docs.astral.sh/uv/):

```bash
# Install dependencies and synchronise virtual environment
uv sync

# Run via uv
uv run rhada --help
```

## CLI Usage

### 1. Audit a Python / `uv` Source Workspace

```bash
uv run rhada --project . \
  --sbom sbom.cdx.json \
  --notices THIRD_PARTY_NOTICES
```

### 2. Audit a Compiled Nuitka or PyInstaller Distribution

```bash
# Standalone directory (Nuitka .dist or PyInstaller folder)
uv run rhada --project . --dist ./build/app.dist \
  --sbom dist-sbom.json \
  --sbom-format cyclonedx \
  --notices dist/THIRD_PARTY_NOTICES \
  --fail-on-linkage

# Monolithic single-file binary (PyInstaller onefile or Nuitka onefile)
uv run rhada --project . --dist ./dist/app-linux-x86_64 \
  --sbom dist-sbom.spdx.json \
  --sbom-format spdx \
  --notices dist/THIRD_PARTY_NOTICES
```

### 3. Policy Controls and Approved Licences

If your organisation maintains proprietary in-house packages or approved commercial licences, you can permit them using `--allow-licence` (or `--allow-licences` / `--allow-license`):

```bash
# Approve standard open-source licences alongside internal company or proprietary licences
uv run rhada --project . \
  --allow-licence "MIT,Apache-2.0,BSD-3-Clause,LicenseRef-AcmeCorp,Proprietary"
```

- Any component declaring an approved licence will **not** trigger `LIC-POLICY-NOT-ALLOWED`, `LIC-PROPRIETARY`, or `LIC-UNKNOWN`.
- Custom SPDX identifiers using the `LicenseRef-[A-Za-z0-9.-]+` convention are supported throughout all audit checks, SBOMs, and notice generators.

### 4. LGPL Source Code Links and Compliance Offers

For packages governed by the GNU Lesser General Public License (LGPL-2.0, LGPL-2.1, LGPL-3.0), Section 4(d) / Section 6 requires that recipients have access to complete corresponding source code and retain the ability to modify and relink the library:
- Rhada resolves upstream repository and release source URLs from package `Project-URL` metadata, PyPI files, or native library registries.
- Discovered source links are included directly in `LIC-LGPL-DYNAMIC` and `LIC-LGPL-MONOLITHIC` compliance findings and embedded into CycloneDX (`vcs`) and SPDX (`downloadLocation`) SBOMs.
- `THIRD_PARTY_NOTICES` includes a dedicated **LGPL Compliance & Source Code Offer** section providing exact source code download locations and written offer statements.

### 5. Subcommands

```bash
# Generate SBOM to stdout or file
uv run rhada sbom --project . --format spdx --output sbom.spdx.json

# Generate THIRD_PARTY_NOTICES
uv run rhada notices --project . --dist ./build/app.dist --output THIRD_PARTY_NOTICES

# Inspect ELF binaries and DT_NEEDED linkage directly
uv run rhada inspect-elf ./build/app.dist
```

## Exit Codes

| Exit Code | Enum Name | Meaning |
| :---: | :--- | :--- |
| `0` | `OK` | Audit passed all security, licence, and binary linkage policies. |
| `1` | `VULNERABILITY_FAILURE` | One or more vulnerabilities met or exceeded `--fail-on-severity` (default: `high`). |
| `2` | `LICENSE_FAILURE` | One or more licence compliance findings met or exceeded `--fail-on-licence` / `--fail-on-license` (default: `high`). |
| `3` | `COMBINED_POLICY_FAILURE` | Both vulnerability and licence compliance thresholds were breached. |
| `4` | `LINKAGE_FAILURE` | `--fail-on-linkage` was set and unbundled external `DT_NEEDED` libraries or insecure RPATHs were found. |
| `5` | `USAGE_OR_IO_ERROR` | Invalid CLI arguments or unreadable target paths. |

### GitHub Actions CI Example

```yaml
jobs:
  compliance-and-security-gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v4
      - name: Run Rhada Audit and Generate Release Artefacts
        run: |
          uv run rhada audit \
            --project . \
            --dist ./dist/my-service.dist \
            --sbom ./dist/sbom.cdx.json \
            --notices ./dist/THIRD_PARTY_NOTICES \
            --report-json ./dist/rhada-report.json \
            --fail-on-severity high \
            --fail-on-licence high \
            --fail-on-linkage
```

## Legal Disclaimer

> [!IMPORTANT]
> **Rhada is an automated analysis tool and does not provide legal advice or guarantee legal compliance.**
>
> 1. **No Legal Counsel**: The licence classifications, risk categorisations, compliance findings, and attribution files generated by Rhada are automated heuristics based on metadata and static file inspection. They do not constitute legal advice and do not establish an attorney-client relationship.
> 2. **No Compliance Warranty**: Upstream metadata in open-source packages may be incomplete, inaccurate, or outdated. Software distributors are solely responsible for verifying their own legal obligations and should consult qualified legal counsel for binding compliance determinations.
> 3. **Limitation of Liability**: In accordance with the project licence (Apache-2.0, Sections 7 and 8), Rhada is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. The contributors and maintainers cannot be held liable for any damages, legal actions, or compliance failures arising from the use of this software.

## Running Tests

```bash
uv run pytest -v
```
