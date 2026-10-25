"""Unit tests for CycloneDX 1.5, SPDX 2.3 SBOM generation, and CLI exit code gates."""

from __future__ import annotations

import json
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
        license_files={"LICENSE": "Copyright (c) 2024 Acme\nPermission is hereby granted, free of charge, to any person obtaining a copy"},
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
    assert vulns_by_id["CVE-2024-0001"]["advisories"] == [
        {"url": "https://osv.dev/vulnerability/CVE-2024-0001"}
    ]
    for comp_entry in cdx["components"]:
        assert "externalReferences" not in comp_entry

    spdx = generate_spdx_sbom(report)
    assert len(spdx["packages"]) == 3
    for pkg_entry in spdx["packages"][1:]:
        assert pkg_entry["downloadLocation"] == "NOASSERTION"


def test_cli_version_and_help_and_unicode_notices(tmp_path: Path) -> None:
    runner = CliRunner()

    # Test --version output
    res_ver = runner.invoke(cli, ["--version"])
    assert res_ver.exit_code == 0
    assert "rhada, version" in res_ver.output

    # Test --help output
    res_help = runner.invoke(cli, ["--help"])
    assert res_help.exit_code == 0
    assert "Rhada: Legal compliance" in res_help.output

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


