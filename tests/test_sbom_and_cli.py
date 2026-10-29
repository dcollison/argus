"""Unit tests for CycloneDX 1.5, SPDX 2.3 SBOM generation, and CLI exit code gates."""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from rhada.cli import app, cli
from rhada.models import (
    AuditMode,
    AuditReport,
    Component,
    ComponentType,
    DistributionLayout,
    ExitCode,
    Severity,
    Vulnerability,
)
from rhada.sbom import generate_cyclonedx_sbom, generate_spdx_sbom, serialize_sbom
from rhada.spdx import build_license_info
from tests.helpers import build_synthetic_elf64, create_dist_info


def test_cyclonedx_and_spdx_sbom_schemas() -> None:
    comp = Component(
        name="urllib3",
        version="2.0.7",
        component_type=ComponentType.PYTHON_PACKAGE,
        hashes={"SHA256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"},
        license_info=build_license_info(
            declared_raw="MIT",
            license_texts={"LICENSE.txt": "Copyright (c) 2023 Andrey Petrov\nMIT License..."},
        ),
        vulnerabilities=[
            Vulnerability(
                id="GHSA-34jh-p97f-mpxf",
                summary="Cookie leakage on cross-origin redirect",
                severity=Severity.HIGH,
                cvss_score=7.5,
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                fixed_versions=["2.0.8"],
                component_name="urllib3",
                component_version="2.0.7",
            )
        ],
    )
    report = AuditReport(
        target_name="payment-gateway",
        target_version="1.0.0",
        mode=AuditMode.SOURCE,
        layout=DistributionLayout.SOURCE_WORKSPACE,
        components=[comp],
    )

    # 1. CycloneDX 1.5
    cdx = generate_cyclonedx_sbom(report)
    assert cdx["bomFormat"] == "CycloneDX"
    assert cdx["specVersion"] == "1.5"
    assert cdx["metadata"]["component"]["name"] == "payment-gateway"
    assert len(cdx["components"]) == 1
    assert cdx["components"][0]["purl"] == "pkg:pypi/urllib3@2.0.7"
    assert cdx["components"][0]["licenses"][0]["license"]["id"] == "MIT"
    assert cdx["components"][0]["hashes"][0] == {
        "alg": "SHA-256",
        "content": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    }
    assert len(cdx["vulnerabilities"]) == 1
    assert cdx["vulnerabilities"][0]["id"] == "GHSA-34jh-p97f-mpxf"

    # 2. SPDX 2.3
    spdx = generate_spdx_sbom(report)
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert spdx["dataLicense"] == "CC0-1.0"
    assert spdx["SPDXID"] == "SPDXRef-DOCUMENT"
    assert len(spdx["packages"]) == 2  # Root application + urllib3
    pkg_urllib3 = spdx["packages"][1]
    assert pkg_urllib3["name"] == "urllib3"
    assert pkg_urllib3["licenseDeclared"] == "MIT"
    assert any(r["relationshipType"] == "DEPENDS_ON" for r in spdx["relationships"])

    # Verify serialize_sbom JSON validity
    raw_cdx = serialize_sbom(report, fmt="cyclonedx")
    assert json.loads(raw_cdx)["bomFormat"] == "CycloneDX"
    raw_spdx = serialize_sbom(report, fmt="spdx")
    assert json.loads(raw_spdx)["spdxVersion"] == "SPDX-2.3"


def test_cli_end_to_end_and_exit_codes(tmp_path: Path) -> None:
    ws = tmp_path / "proj"
    ws.mkdir()
    (ws / "pyproject.toml").write_text(
        """
[project]
name = "acme-service"
version = "2.0.0"
dependencies = ["clean-pkg>=1.0.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    sp = ws / ".venv" / "Lib" / "site-packages"
    create_dist_info(
        sp,
        "clean-pkg",
        "1.0.0",
        license_str="MIT",
        top_level=["clean_pkg"],
        license_files={
            "LICENSE": "Copyright (c) 2024 Acme\nPermission is hereby granted, free of charge, to any person obtaining a copy"
        },
    )

    runner = CliRunner()
    sbom_path = tmp_path / "out.cdx.json"
    notices_path = tmp_path / "THIRD_PARTY_NOTICES"
    report_path = tmp_path / "report.json"

    # 1. Clean offline source audit -> ExitCode.OK (0)
    res_ok = runner.invoke(
        cli,
        [
            "--project",
            str(ws),
            "--offline",
            "--sbom",
            str(sbom_path),
            "--notices",
            str(notices_path),
            "--report-json",
            str(report_path),
        ],
    )
    assert res_ok.exit_code == int(ExitCode.OK), res_ok.output
    assert sbom_path.is_file()
    assert notices_path.is_file()
    assert report_path.is_file()

    # 2. License policy failure (--deny-license MIT) -> ExitCode.LICENSE_FAILURE (2)
    res_lic = runner.invoke(
        cli,
        [
            "audit",
            "--project",
            str(ws),
            "--offline",
            "--deny-license",
            "MIT",
            "--format",
            "json",
        ],
    )
    assert res_lic.exit_code == int(ExitCode.LICENSE_FAILURE)
    parsed_json = json.loads(res_lic.output)
    assert parsed_json["summary"]["exit_code"] == int(ExitCode.LICENSE_FAILURE)

    # 3. Binary linkage failure (--fail-on-linkage with missing .so) -> ExitCode.LINKAGE_FAILURE (4)
    dist_dir = tmp_path / "broken.dist"
    dist_dir.mkdir()
    broken_elf = build_synthetic_elf64(
        is_executable=True,
        needed_libs=["libmissing_custom.so.1"],
    )
    (dist_dir / "acme-service.bin").write_bytes(broken_elf)

    res_link = runner.invoke(
        cli,
        [
            "audit",
            "--project",
            str(ws),
            "--dist",
            str(dist_dir),
            "--offline",
            "--fail-on-linkage",
        ],
    )
    assert res_link.exit_code == int(ExitCode.LINKAGE_FAILURE)

    # 4. Subcommands: sbom, notices, inspect-elf
    res_sbom_sub = runner.invoke(cli, ["sbom", "--project", str(ws), "--format", "spdx", "--offline"])
    assert res_sbom_sub.exit_code == 0
    assert json.loads(res_sbom_sub.output)["spdxVersion"] == "SPDX-2.3"

    res_notices_sub = runner.invoke(cli, ["notices", "--project", str(ws)])
    assert res_notices_sub.exit_code == 0
    assert "clean-pkg" in res_notices_sub.output

    res_elf_sub = runner.invoke(cli, ["inspect-elf", str(dist_dir)])
    assert res_elf_sub.exit_code == 0
    assert "libmissing_custom.so.1" in json.loads(res_elf_sub.output)["unresolved_dependencies"]

    # 5. Non-existent path -> ExitCode.USAGE_OR_IO_ERROR (5)
    res_bad = runner.invoke(cli, ["audit", "--project", str(tmp_path / "does-not-exist")])
    assert res_bad.exit_code == int(ExitCode.USAGE_OR_IO_ERROR)

    # 6. British English CLI flag aliases (--deny-licence, --fail-on-licence)
    res_brit = runner.invoke(
        app,
        [
            "audit",
            "--project",
            str(ws),
            "--offline",
            "--deny-licence",
            "MIT",
            "--fail-on-licence",
            "high",
            "--format",
            "json",
        ],
    )
    assert res_brit.exit_code == int(ExitCode.LICENSE_FAILURE)


def test_sbom_malformed_urls_and_same_named_components() -> None:
    from rhada.models import LicenseInfo

    py_openssl = Component(
        name="openssl",
        version="3.2.1",
        component_type=ComponentType.PYTHON_PACKAGE,
        homepage="http://[invalid-ipv6",
        license_info=LicenseInfo(declared_raw="Custom", spdx_id="Invalid Expression OR ???"),
        vulnerabilities=[
            Vulnerability(
                id="CVE-2024-0001",
                summary="Python binding issue",
                references=["not a valid url", "https://osv.dev/vulnerability/CVE-2024-0001"],
                component_name="openssl",
                component_version="3.2.1",
            )
        ],
    )
    nat_openssl = Component(
        name="openssl",
        version="3.2.1",
        component_type=ComponentType.NATIVE_LIBRARY,
        homepage="UNKNOWN",
        license_info=LicenseInfo(declared_raw="Proprietary", spdx_id="LicenseRef-Proprietary"),
        vulnerabilities=[
            Vulnerability(
                id="CVE-2024-0002",
                summary="Native library issue",
                component_name="openssl",
                component_version="3.2.1",
            )
        ],
    )
    report = AuditReport(
        target_name="dual-app",
        target_version="1.0.0",
        mode=AuditMode.COMPILED_DIST,
        layout=DistributionLayout.STANDALONE_DIR,
        components=[py_openssl, nat_openssl],
    )

    cdx = generate_cyclonedx_sbom(report)
    assert len(cdx["components"]) == 2
    root_dep_entry = next(d for d in cdx["dependencies"] if d["ref"] == "pkg:generic/dual-app@1.0.0")
    assert set(root_dep_entry["dependsOn"]) == {
        "pkg:pypi/openssl@3.2.1",
        "pkg:generic/openssl@3.2.1",
    }
    vulns_by_id = {v["id"]: v for v in cdx["vulnerabilities"]}
    assert vulns_by_id["CVE-2024-0001"]["affects"] == [{"ref": "pkg:pypi/openssl@3.2.1"}]
    assert vulns_by_id["CVE-2024-0002"]["affects"] == [{"ref": "pkg:generic/openssl@3.2.1"}]
    assert vulns_by_id["CVE-2024-0001"]["advisories"] == [{"url": "https://osv.dev/vulnerability/CVE-2024-0001"}]
    for comp_entry in cdx["components"]:
        assert "externalReferences" not in comp_entry

    spdx = generate_spdx_sbom(report)
    assert len(spdx["packages"]) == 3
    for pkg_entry in spdx["packages"][1:]:
        assert pkg_entry["downloadLocation"] == "NOASSERTION"


def test_cli_version_and_help_and_unicode_notices(tmp_path: Path) -> None:
    runner = CliRunner()

    def strip_ansi(text: str) -> str:
        return re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", text)

    # Test --version output
    res_ver = runner.invoke(cli, ["--version"])
    assert res_ver.exit_code == 0
    assert "rhada, version" in res_ver.output

    # Test --help output
    res_help = runner.invoke(cli, ["--help"])
    assert res_help.exit_code == 0
    assert "Rhada: Legal compliance" in res_help.output
    assert "Disclaimer:" in res_help.output

    res_audit_help = runner.invoke(cli, ["audit", "--help"])
    assert res_audit_help.exit_code == 0
    clean_audit_help = re.sub(r"\x1b\[[0-9;]*[a-zA-Z]", "", res_audit_help.output)
    assert "--allow-licence" in clean_audit_help

    # Test Unicode notices output to stdout without charmap/cp1252 crashing
    ws = tmp_path / "unicode_pkg"
    ws.mkdir()
    (ws / "pyproject.toml").write_text(
        """
[project]
name = "unicode-app"
version = "1.0.0"
dependencies = ["unicode-pkg>=1.0.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    sp = ws / ".venv" / "Lib" / "site-packages"
    create_dist_info(
        sp,
        "unicode-pkg",
        "1.0.0",
        license_str="MIT",
        top_level=["unicode_pkg"],
        license_files={"LICENSE": "Copyright (c) 2024 Michał Wędrowny \u0144 \u2713 \u00a9\nMIT License"},
    )
    res_notices = runner.invoke(cli, ["notices", "--project", str(ws)])
    assert res_notices.exit_code == 0
    assert "Michał Wędrowny" in res_notices.output or "\u0144" in res_notices.output

    # Test invoking audit with plural --allow-licences alias
    res_alias = runner.invoke(cli, ["audit", "--project", str(ws), "--offline", "--allow-licences", "MIT,Apache-2.0"])
    assert res_alias.exit_code == 0

    # Test audit CLI with Corporate Internal Licence
    internal_ws = tmp_path / "internal_pkg_ws"
    internal_ws.mkdir()
    (internal_ws / "pyproject.toml").write_text(
        """
[project]
name = "internal-app"
version = "1.0.0"
dependencies = ["acme-internal-service>=1.0.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    int_sp = internal_ws / ".venv" / "Lib" / "site-packages"
    create_dist_info(
        int_sp,
        "acme-internal-service",
        "1.0.0",
        license_str="",
        top_level=["acme_internal_service"],
        license_files={"LICENSE": "Acme Corp Internal Licence. All rights reserved."},
    )

    # Without allow-licence -> failure
    res_no_allow = runner.invoke(cli, ["audit", "--project", str(internal_ws), "--offline"])
    assert res_no_allow.exit_code == 2
    assert "LICENSE_FAILURE" in strip_ansi(res_no_allow.output)

    # With --allow-licence using human-readable raw title
    res_allow_raw = runner.invoke(
        cli,
        ["audit", "--project", str(internal_ws), "--offline", "--allow-licence", "Acme Corp Internal Licence"],
    )
    assert res_allow_raw.exit_code == 0
    assert "Status: PASSED" in strip_ansi(res_allow_raw.output)
    assert "No legal or licence compliance violations detected." in strip_ansi(res_allow_raw.output)

    # With --allow-licence using SPDX ID
    res_allow_spdx = runner.invoke(
        cli,
        ["audit", "--project", str(internal_ws), "--offline", "--allow-licence", "LicenseRef-Acme-Corp-Internal"],
    )
    assert res_allow_spdx.exit_code == 0
    assert "Status: PASSED" in strip_ansi(res_allow_spdx.output)


def test_cyclonedx_custom_licenseref_and_spdx_originator() -> None:
    from rhada.models import (
        AuditMode,
        AuditReport,
        BundlerType,
        Component,
        ComponentType,
        DistributionLayout,
    )
    from rhada.sbom import generate_cyclonedx_sbom, generate_spdx_sbom
    from rhada.spdx import build_license_info

    comp_custom = Component(
        name="custom-plugin",
        version="1.0.0",
        component_type=ComponentType.PYTHON_PACKAGE,
        is_bundled=True,
        author="Acme Corporation <devs@acme.com>",
        license_info=build_license_info("LicenseRef-Custom-Enterprise"),
    )
    comp_compound = Component(
        name="dual-tool",
        version="2.0.0",
        component_type=ComponentType.PYTHON_PACKAGE,
        is_bundled=True,
        author="Person: Jane Doe <jane@example.com>",
        license_info=build_license_info("MIT OR LicenseRef-Custom-Enterprise"),
    )

    report = AuditReport(
        target_name="test-app",
        target_version="1.0.0",
        mode=AuditMode.COMPILED_DIST,
        bundler_type=BundlerType.NUITKA,
        layout=DistributionLayout.MONOLITHIC_BINARY,
        components=[comp_custom, comp_compound],
    )

    # CycloneDX output verification
    cdx = generate_cyclonedx_sbom(report)
    cdx_comps = {c["name"]: c for c in cdx["components"]}

    # LicenseRef-Custom-Enterprise should be emitted under license.id, not license.name
    custom_lics = cdx_comps["custom-plugin"]["licenses"]
    assert len(custom_lics) == 1
    assert "license" in custom_lics[0]
    assert custom_lics[0]["license"]["id"] == "LicenseRef-Custom-Enterprise"

    # Compound expression with LicenseRef should be emitted as expression
    compound_lics = cdx_comps["dual-tool"]["licenses"]
    assert len(compound_lics) == 1
    assert "expression" in compound_lics[0]
    assert compound_lics[0]["expression"] == "MIT OR LicenseRef-Custom-Enterprise"

    # SPDX output verification
    spdx = generate_spdx_sbom(report)
    spdx_pkgs = {p["name"]: p for p in spdx["packages"]}

    # Acme Corporation should be recognized as Organization, formatted with email in parentheses
    orig_acme = spdx_pkgs["custom-plugin"]["originator"]
    assert orig_acme == "Organization: Acme Corporation (devs@acme.com)"

    # Pre-prefixed Person: Jane Doe should not have duplicate prefix
    orig_jane = spdx_pkgs["dual-tool"]["originator"]
    assert orig_jane == "Person: Jane Doe (jane@example.com)"


def test_cli_distribution_file_inventory_verbose_and_full(tmp_path: Path) -> None:
    ws = tmp_path / "app_ws"
    ws.mkdir()
    (ws / "pyproject.toml").write_text(
        """[project]
name = "inventory-app"
version = "1.0.0"
dependencies = []
""",
        encoding="utf-8",
    )

    dist_dir = tmp_path / "inventory-app.dist"
    dist_dir.mkdir()
    (dist_dir / "inventory-app.exe").write_bytes(b"MZapp")
    (dist_dir / "python313.dll").write_bytes(b"MZpy")
    (dist_dir / "vcruntime140.dll").write_bytes(b"MZvc")
    (dist_dir / "report.xml").write_text("<report/>", encoding="utf-8")

    runner = CliRunner(env={"COLUMNS": "160"})

    # 1. Normal run (without verbose): summary includes Distribution File Coverage
    res_normal = runner.invoke(
        cli,
        [
            "--project",
            str(ws),
            "--dist",
            str(dist_dir),
            "--offline",
        ],
    )
    assert res_normal.exit_code == int(ExitCode.OK), res_normal.output
    assert "Distribution File Coverage" in res_normal.output
    assert "100.0%" in res_normal.output
    assert "Distribution File Accounting & Inventory" not in res_normal.output

    # 2. Verbose run (--verbose): includes full file inventory table
    res_verbose = runner.invoke(
        cli,
        [
            "--project",
            str(ws),
            "--dist",
            str(dist_dir),
            "--offline",
            "--verbose",
        ],
    )
    assert res_verbose.exit_code == int(ExitCode.OK), res_verbose.output
    assert "Distribution File Accounting & Inventory" in res_verbose.output
    assert "inventory-app.exe" in res_verbose.output
    assert "report.xml" in res_verbose.output
    assert "application-binary" in res_verbose.output
    assert "python-runtime" in res_verbose.output
    assert "compiler-abi" in res_verbose.output
    assert "data-metadata" in res_verbose.output

    # 3. Full flag alias (--full) produces identical verbose table
    res_full = runner.invoke(
        cli,
        [
            "--project",
            str(ws),
            "--dist",
            str(dist_dir),
            "--offline",
            "--full",
        ],
    )
    assert res_full.exit_code == int(ExitCode.OK), res_full.output
    assert "Distribution File Accounting & Inventory" in res_full.output

    # 4. JSON output format includes file_inventory dictionary
    res_json = runner.invoke(
        cli,
        [
            "--project",
            str(ws),
            "--dist",
            str(dist_dir),
            "--offline",
            "--format",
            "json",
        ],
    )
    assert res_json.exit_code == int(ExitCode.OK), res_json.output
    report_dict = json.loads(res_json.output)
    assert "file_inventory" in report_dict
    inv = report_dict["file_inventory"]
    assert inv["total_files"] == 4
    assert inv["classified_count"] == 4
    assert inv["unaccounted_count"] == 0
    assert inv["coverage_percent"] == 100.0


def test_cli_internal_and_ignore_package_flags(tmp_path: Path) -> None:
    ws = tmp_path / "cli_ws"
    ws.mkdir()
    (ws / "pyproject.toml").write_text(
        """[project]
name = "cli-test-app"
version = "1.0.0"
dependencies = ["corp-utils>=1.0.0", "legacy-lib>=0.1.0"]
""",
        encoding="utf-8",
    )
    sp = ws / ".venv" / "Lib" / "site-packages"
    create_dist_info(sp, "corp-utils", "1.0.0", license_str="Proprietary", top_level=["corp_utils"])
    create_dist_info(sp, "legacy-lib", "0.1.0", license_str="GPL-3.0-only", top_level=["legacy_lib"])

    runner = CliRunner(env={"COLUMNS": "160"})

    # 1. Without flags -> fails on GPL-3.0 deny policy
    res_fail = runner.invoke(
        cli,
        [
            "--project",
            str(ws),
            "--offline",
            "--deny-license",
            "GPL-3.0-only",
        ],
    )
    assert res_fail.exit_code != int(ExitCode.OK)

    # 2. With --internal-package "corp-*" and --ignore-package "legacy-lib" -> passes OK (0)
    res_pass = runner.invoke(
        cli,
        [
            "--project",
            str(ws),
            "--offline",
            "--internal-package",
            "corp-*",
            "--ignore-package",
            "legacy-lib",
            "--deny-license",
            "GPL-3.0-only",
        ],
    )
    assert res_pass.exit_code == int(ExitCode.OK), res_pass.output
    assert "internal package" in res_pass.output


def test_cli_allow_extra_licence_flags(tmp_path: Path) -> None:
    ws = tmp_path / "cli_extra_ws"
    ws.mkdir()
    (ws / "pyproject.toml").write_text(
        """[project]
name = "extra-licence-app"
version = "1.0.0"
dependencies = ["mit-helper>=1.0.0", "custom-sdk>=2.0.0"]
""",
        encoding="utf-8",
    )
    sp = ws / ".venv" / "Lib" / "site-packages"
    create_dist_info(sp, "mit-helper", "1.0.0", license_str="MIT", top_level=["mit_helper"])
    create_dist_info(sp, "custom-sdk", "2.0.0", license_str="Proprietary", top_level=["custom_sdk"])

    runner = CliRunner(env={"COLUMNS": "160"})

    # 1. Default run flags custom-sdk as LIC-PROPRIETARY (ExitCode.LICENSE_FAILURE = 2)
    res_default = runner.invoke(cli, ["--project", str(ws), "--offline"])
    assert res_default.exit_code == int(ExitCode.LICENSE_FAILURE), res_default.output
    assert "LIC-PROPRIETARY" in res_default.output

    # 2. Strict --allow-licence "Proprietary" flags mit-helper as LIC-POLICY-NOT-ALLOWED
    res_strict = runner.invoke(cli, ["--project", str(ws), "--offline", "--allow-licence", "Proprietary"])
    assert res_strict.exit_code == int(ExitCode.LICENSE_FAILURE), res_strict.output
    assert "LIC-POLICY-NOT-ALLOWED" in res_strict.output

    # 3. Supplemental --allow-extra-licence "Proprietary" passes OK (0) without flagging MIT
    for flag in ("--allow-extra-licence", "--allow-extra-license", "--allow-extra-licences", "--allow-extra-licenses"):
        res_extra = runner.invoke(cli, ["--project", str(ws), "--offline", flag, "Proprietary"])
        assert res_extra.exit_code == int(ExitCode.OK), f"Failed with {flag}: {res_extra.output}"
        assert "LIC-POLICY-NOT-ALLOWED" not in res_extra.output
        assert "LIC-PROPRIETARY" not in res_extra.output
