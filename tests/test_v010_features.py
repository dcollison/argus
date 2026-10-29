"""Unit tests for new features introduced in Rhada v0.1.0:
1. Pre-commit hooks configuration
2. Ignore vulnerabilities (CLI and pyproject.toml with expiry)
3. Licence text overrides ([tool.rhada.license-files] and [tool.rhada.license-texts])
4. Markdown notices output
5. SBOM diff engine and CLI command
"""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from rhada.auditor import run_audit
from rhada.cli import cli
from rhada.compliance import (
    generate_third_party_notices,
    generate_third_party_notices_markdown,
    write_third_party_notices,
)
from rhada.diff import compare_sboms
from rhada.models import (
    AuditConfig,
    AuditMode,
    AuditReport,
    Component,
    ComponentType,
    DistributionLayout,
    ExitCode,
    Severity,
    Vulnerability,
)
from rhada.spdx import build_license_info
from tests.helpers import create_dist_info


def test_pre_commit_hooks_file_exists_and_valid() -> None:
    hook_file = Path(".pre-commit-hooks.yaml")
    assert hook_file.is_file()
    content = hook_file.read_text(encoding="utf-8")
    assert "id: rhada" in content
    assert "id: rhada-audit" in content
    assert "entry: rhada audit" in content


def test_ignore_vulnerabilities_via_cli(tmp_path: Path) -> None:
    comp = Component(
        name="vulnerable-lib",
        version="1.0.0",
        component_type=ComponentType.PYTHON_PACKAGE,
        license_info=build_license_info("MIT", license_texts={"LICENSE": "MIT License"}),
        vulnerabilities=[
            Vulnerability(
                id="GHSA-test-vuln-001",
                summary="Critical RCE vulnerability",
                aliases=["CVE-2024-99999"],
                severity=Severity.CRITICAL,
                component_name="vulnerable-lib",
                component_version="1.0.0",
            )
        ],
    )
    report = AuditReport(
        target_name="test-app",
        target_version="1.0.0",
        mode=AuditMode.SOURCE,
        components=[comp],
    )

    # 1. Without ignore -> fails with VULNERABILITY_FAILURE
    from rhada.auditor import compute_exit_code

    cfg_default = AuditConfig()
    assert compute_exit_code(report, cfg_default) == ExitCode.VULNERABILITY_FAILURE

    # 2. With ignore by primary GHSA ID -> exit code OK (0)
    cfg_ignore_ghsa = AuditConfig(ignore_vulnerabilities={"GHSA-TEST-VULN-001"})
    # Re-tag vulnerability
    v = report.components[0].vulnerabilities[0]
    v.is_ignored = True
    v.ignore_reason = "Manual test exception"
    assert compute_exit_code(report, cfg_ignore_ghsa) == ExitCode.OK

    # 3. Test through run_audit with offline workspace
    ws = tmp_path / "ws_vuln"
    ws.mkdir()
    (ws / "pyproject.toml").write_text(
        """[project]
name = "vuln-test"
version = "0.1.0"
dependencies = ["vulnerable-lib>=1.0.0"]
""",
        encoding="utf-8",
    )
    sp = ws / ".venv" / "Lib" / "site-packages"
    create_dist_info(sp, "vulnerable-lib", "1.0.0", license_str="MIT", top_level=["vulnerable_lib"])

    runner = CliRunner(env={"COLUMNS": "160"})
    res = runner.invoke(
        cli,
        [
            "--project",
            str(ws),
            "--offline",
            "--ignore-vulnerability",
            "CVE-2024-99999",
        ],
    )
    assert res.exit_code == int(ExitCode.OK)


def test_ignore_vulnerabilities_pyproject_with_expiry(tmp_path: Path) -> None:
    from rhada.workspace import load_tool_rhada_config

    ws = tmp_path / "ws_expiry"
    ws.mkdir()
    (ws / "pyproject.toml").write_text(
        """[project]
name = "expiry-test"
version = "0.1.0"

[tool.rhada.ignore-vulnerabilities]
"CVE-2024-EXPIRED" = { reason = "Temporary bypass", expires = "2020-01-01" }
"CVE-2024-ACTIVE" = { reason = "Long-term bypass", expires = "2099-12-31" }
"GHSA-SIMPLE" = "Simple string reason"
""",
        encoding="utf-8",
    )

    cfg = load_tool_rhada_config(ws)
    ignored = cfg["ignore_vulnerabilities"]
    assert "CVE-2024-EXPIRED" not in ignored  # Expired!
    assert "CVE-2024-ACTIVE" in ignored
    assert "GHSA-SIMPLE" in ignored
    assert cfg["ignore_vulnerability_details"]["CVE-2024-ACTIVE"]["reason"] == "Long-term bypass"
    assert cfg["ignore_vulnerability_details"]["GHSA-SIMPLE"]["reason"] == "Simple string reason"


def test_license_text_overrides(tmp_path: Path) -> None:
    ws = tmp_path / "ws_lic_override"
    ws.mkdir()
    custom_lic_file = ws / "custom-mit.txt"
    custom_lic_file.write_text("Copyright 2026 Acme Corp. Custom MIT Text.", encoding="utf-8")

    (ws / "pyproject.toml").write_text(
        """[project]
name = "lic-override-test"
version = "1.0.0"
dependencies = ["unlicensed-wheel>=1.0.0", "inlined-wheel>=1.0.0"]

[tool.rhada.license-files]
unlicensed-wheel = "custom-mit.txt"

[tool.rhada.license-texts]
inlined-wheel = "Copyright (c) 2026 Inlined Corp. Apache-2.0 License."
""",
        encoding="utf-8",
    )
    sp = ws / ".venv" / "Lib" / "site-packages"
    # Create wheels without LICENSE files in dist-info
    create_dist_info(sp, "unlicensed-wheel", "1.0.0", license_str="MIT", top_level=["unlicensed_wheel"])
    create_dist_info(sp, "inlined-wheel", "1.0.0", license_str="Apache-2.0", top_level=["inlined_wheel"])

    config = AuditConfig(project_path=ws, offline=True)
    report = run_audit(config)

    # 1. No LIC-MISSING-TEXT findings because both wheels have overridden license texts
    missing_findings = [f for f in report.compliance_findings if f.rule_id == "LIC-MISSING-TEXT"]
    assert len(missing_findings) == 0

    # 2. Verify texts are injected into the components
    comp_unlicensed = next(c for c in report.components if c.name == "unlicensed-wheel")
    assert "custom-mit.txt" in comp_unlicensed.license_info.license_texts
    assert "Custom MIT Text" in comp_unlicensed.license_info.license_texts["custom-mit.txt"]

    comp_inlined = next(c for c in report.components if c.name == "inlined-wheel")
    assert "LICENSE" in comp_inlined.license_info.license_texts
    assert "Inlined Corp" in comp_inlined.license_info.license_texts["LICENSE"]

    # 3. Verify THIRD_PARTY_NOTICES contains the overridden texts
    notices_txt = generate_third_party_notices(report)
    assert "Custom MIT Text" in notices_txt
    assert "Inlined Corp" in notices_txt


def test_markdown_notices_generation(tmp_path: Path) -> None:
    c1 = Component(
        name="super-auth",
        version="3.2.1",
        component_type=ComponentType.PYTHON_PACKAGE,
        homepage="https://example.com/super-auth",
        license_info=build_license_info(
            declared_raw="MIT",
            license_texts={"LICENSE": "MIT License Copyright (c) 2026 Super Auth authors"},
        ),
        is_bundled=True,
    )
    c2 = Component(
        name="lgpl-helper",
        version="1.0.0",
        component_type=ComponentType.PYTHON_PACKAGE,
        homepage="https://example.com/lgpl-helper",
        license_info=build_license_info(
            declared_raw="LGPL-3.0-only",
            license_texts={"COPYING": "LGPL 3.0 license terms"},
        ),
        is_bundled=True,
    )

    report = AuditReport(
        target_name="md-app",
        target_version="1.0.0",
        mode=AuditMode.SOURCE,
        layout=DistributionLayout.SOURCE_WORKSPACE,
        components=[c1, c2],
    )

    md = generate_third_party_notices_markdown(report)
    assert "# Third-Party Software Notices" in md
    assert "- **Application:** md-app (1.0.0)" in md
    assert "## Component Summary" in md
    assert "| 2 | **super-auth** | `3.2.1` | Python Package | `MIT` |" in md
    assert "LGPL Compliance & Source Code Offer (LGPL-3.0-only)" in md
    assert "Verbatim Licence (LICENSE)" in md
    assert "MIT License Copyright (c) 2026 Super Auth authors" in md

    # Test write_third_party_notices with .md extension
    out_file = tmp_path / "NOTICES.md"
    write_third_party_notices(report, out_file)
    assert out_file.read_text(encoding="utf-8").startswith("# Third-Party Software Notices")


def test_sbom_diff_engine(tmp_path: Path) -> None:
    # Baseline Report JSON
    base_file = tmp_path / "base_report.json"
    base_data = {
        "components": [
            {
                "name": "requests",
                "version": "2.28.0",
                "license_info": {"spdx_id": "Apache-2.0"},
                "vulnerabilities": [{"id": "CVE-2023-1111"}],
            },
            {
                "name": "old-tool",
                "version": "0.5.0",
                "license_info": {"spdx_id": "MIT"},
                "vulnerabilities": [],
            },
            {
                "name": "static-lib",
                "version": "1.0.0",
                "license_info": {"spdx_id": "MIT"},
                "vulnerabilities": [],
            },
        ]
    }
    base_file.write_text(json.dumps(base_data), encoding="utf-8")

    # Target Report JSON:
    # - requests upgraded to 2.31.0, CVE-2023-1111 resolved
    # - old-tool removed
    # - static-lib changed license from MIT to GPL-3.0-only
    # - new-package added (v1.0.0, MIT, with CVE-2024-2222)
    target_file = tmp_path / "target_report.json"
    target_data = {
        "components": [
            {
                "name": "requests",
                "version": "2.31.0",
                "license_info": {"spdx_id": "Apache-2.0"},
                "vulnerabilities": [],
            },
            {
                "name": "static-lib",
                "version": "1.0.0",
                "license_info": {"spdx_id": "GPL-3.0-only"},
                "vulnerabilities": [],
            },
            {
                "name": "new-package",
                "version": "1.0.0",
                "license_info": {"spdx_id": "MIT"},
                "vulnerabilities": [{"id": "CVE-2024-2222"}],
            },
        ]
    }
    target_file.write_text(json.dumps(target_data), encoding="utf-8")

    diff_res = compare_sboms(base_file, target_file)
    assert diff_res.has_changes is True
    assert len(diff_res.added_components) == 1
    assert diff_res.added_components[0].name == "new-package"

    assert len(diff_res.removed_components) == 1
    assert diff_res.removed_components[0].name == "old-tool"

    assert len(diff_res.modified_components) == 2
    req_mod = next(c for c in diff_res.modified_components if c.name == "requests")
    assert req_mod.change_type == "upgraded"
    assert req_mod.old_version == "2.28.0"
    assert req_mod.new_version == "2.31.0"

    static_mod = next(c for c in diff_res.modified_components if c.name == "static-lib")
    assert static_mod.change_type == "license_changed"
    assert static_mod.old_license == "MIT"
    assert static_mod.new_license == "GPL-3.0-only"

    assert "CVE-2024-2222" in diff_res.new_vulnerabilities
    assert "CVE-2023-1111" in diff_res.resolved_vulnerabilities

    # CLI test for diff command
    runner = CliRunner(env={"COLUMNS": "160"})
    res_cli = runner.invoke(cli, ["diff", str(base_file), str(target_file)])
    assert res_cli.exit_code == 0
    assert "+ ADDED" in res_cli.output
    assert "- REMOVED" in res_cli.output
    assert "^ UPGRADE" in res_cli.output
    assert "~ MODIFIED" in res_cli.output
    assert "NEW VULNERABILITY" in res_cli.output
    assert "RESOLVED" in res_cli.output

    # JSON output test
    res_json = runner.invoke(cli, ["diff", str(base_file), str(target_file), "--format", "json"])
    assert res_json.exit_code == 0
    diff_json = json.loads(res_json.output)
    assert diff_json["added_count"] == 1
    assert diff_json["removed_count"] == 1
    assert diff_json["modified_count"] == 2
    assert "CVE-2024-2222" in diff_json["new_vulnerabilities"]

    # Exit code gates test
    res_fail_vuln = runner.invoke(cli, ["diff", str(base_file), str(target_file), "--fail-on-new-vuln"])
    assert res_fail_vuln.exit_code == 1

    res_fail_changes = runner.invoke(cli, ["diff", str(base_file), str(target_file), "--fail-on-changes"])
    assert res_fail_changes.exit_code == 1
