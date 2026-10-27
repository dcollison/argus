"""Edge case, boundary value, and error-path tests across all Rhada modules."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from rhada.auditor import run_audit
from rhada.compliance import evaluate_compliance
from rhada.dist import inspect_compiled_distribution
from rhada.elf import (
    _match_known_native_profile,
    is_elf_file,
    parse_elf_binary,
    parse_elf_bytes,
    verify_binary_linkage,
)
from rhada.models import (
    AuditConfig,
    AuditMode,
    BundlerType,
    Component,
    ComponentType,
    DistributionLayout,
    ExitCode,
    LicenseRiskCategory,
    LinkageStatus,
    Severity,
)
from rhada.osv import (
    OsvClient,
    compute_cvss_v3_score,
    parse_osv_vulnerability,
    score_to_severity,
)
from rhada.reporter import format_report_text
from rhada.sbom import serialize_sbom
from rhada.spdx import (
    build_license_info,
    classify_single_spdx,
    infer_spdx_from_license_text,
    normalize_single_license,
    parse_spdx_expression,
)
from rhada.workspace import (
    _parse_setup_cfg,
    _read_text_safe,
    inspect_workspace,
    normalize_pkg_name,
    parse_req_name,
)
from tests.helpers import build_synthetic_elf64, create_dist_info


def test_empty_workspace_and_posix_venv_layout(tmp_path: Path) -> None:
    # 1. Completely empty directory
    empty_dir = tmp_path / "empty"
    empty_dir.mkdir()
    ws_empty = inspect_workspace(empty_dir)
    assert ws_empty.project_name == "empty"
    assert ws_empty.components == {}

    # 2. Workspace with POSIX .venv/lib/python3.12/site-packages, RECORD, Project-URL, License-File, no uv.lock
    posix_ws = tmp_path / "posix_proj"
    posix_ws.mkdir()
    (posix_ws / "pyproject.toml").write_text(
        """
[project]
name = "posix-service"
version = "0.9.0"
license = { text = "BSD-2-Clause" }
dependencies = ["pyyaml>=6.0", "uninstalled-dep>=1.0"]

[project.optional-dependencies]
dev = ["ruff>=0.4.0"]

[tool.uv]
dev-dependencies = ["mypy>=1.10.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )

    posix_sp = posix_ws / ".venv" / "lib" / "python3.12" / "site-packages"
    dist_dir = create_dist_info(
        posix_sp,
        "PyYAML",
        "6.0.1",
        classifiers=["License :: OSI Approved :: MIT License"],
        homepage="",
    )
    # Add Project-URL, License-File, and RECORD to test those code paths
    meta_path = dist_dir / "METADATA"
    meta_text = meta_path.read_text(encoding="utf-8")
    meta_text += "Project-URL: Repository, https://github.com/yaml/pyyaml\nLicense-File: LICENSE\n"
    meta_path.write_text(meta_text, encoding="utf-8")
    (dist_dir / "LICENSE").write_text(
        "Copyright (c) 2017-2024 Ingy döt Net\nPermission is hereby granted, free of charge, to any person obtaining a copy",
        encoding="utf-8",
    )
    (dist_dir / "RECORD").write_text(
        "yaml/__init__.py,sha256=abc,123\n_yaml.cpython-312-x86_64-linux-gnu.so,sha256=def,456\n",
        encoding="utf-8",
    )

    ws = inspect_workspace(posix_ws, include_dev=False)
    assert ws.project_name == "posix-service"
    assert ws.project_license == "BSD-2-Clause"
    assert "pyyaml" in ws.components
    assert "uninstalled-dep" in ws.components
    pyyaml_comp = ws.components["pyyaml"]
    assert pyyaml_comp.homepage == "https://github.com/yaml/pyyaml"
    assert "yaml" in pyyaml_comp.top_level_modules
    assert "_yaml" in pyyaml_comp.top_level_modules
    assert pyyaml_comp.license_info.spdx_id == "MIT"


def test_spdx_heuristics_and_text_inference_exhaustive() -> None:
    assert normalize_single_license("GNU General Public License v2") == "GPL-2.0-only"
    assert normalize_single_license("GNU General Public License v2 or later") == "GPL-2.0-or-later"
    assert normalize_single_license("GNU General Public License v3") == "GPL-3.0-only"
    assert normalize_single_license("GNU Lesser General Public License v3+") == "LGPL-3.0-or-later"
    assert normalize_single_license("Mozilla Public License 2.0") == "MPL-2.0"
    assert normalize_single_license("Zero-Clause BSD") == "0BSD"
    assert normalize_single_license("Simplified BSD") == "BSD-2-Clause"
    assert normalize_single_license("Python Software Foundation License") == "PSF-2.0"
    assert normalize_single_license("The Unlicense") == "Unlicense"
    assert normalize_single_license("Public Domain") == "Public-Domain"
    assert normalize_single_license("Proprietary Commercial") == "LicenseRef-Proprietary"

    assert infer_spdx_from_license_text("Apache License, Version 2.0") == "Apache-2.0"
    assert infer_spdx_from_license_text("GNU Affero General Public License") == "AGPL-3.0-or-later"
    assert infer_spdx_from_license_text("GNU Lesser General Public License Version 3") == "LGPL-3.0-or-later"
    assert infer_spdx_from_license_text("GNU Lesser General Public License Version 2.1") == "LGPL-2.1-or-later"
    assert infer_spdx_from_license_text("GNU General Public License Version 2") == "GPL-2.0-or-later"
    assert infer_spdx_from_license_text("GNU General Public License ... runtime library exception") == "GPL-3.0-with-GCC-exception"
    assert infer_spdx_from_license_text("Mozilla Public License Version 2.0") == "MPL-2.0"
    assert (
        infer_spdx_from_license_text(
            "Permission to use, copy, modify, and/or distribute this software for any purpose ... "
            "above copyright notice and this permission notice appear in all copies"
        )
        == "ISC"
    )
    assert (
        infer_spdx_from_license_text("Permission to use, copy, modify, and/or distribute this software for any purpose")
        == "0BSD"
    )
    assert (
        infer_spdx_from_license_text("Redistribution and use in source and binary forms, with or without modification")
        == "BSD-2-Clause"
    )
    assert infer_spdx_from_license_text("Python Software Foundation License Version 2") == "PSF-2.0"
    assert (
        infer_spdx_from_license_text("This is free and unencumbered software released into the public domain")
        == "Unlicense"
    )

    assert classify_single_spdx("Unlicense") == LicenseRiskCategory.PUBLIC_DOMAIN
    assert classify_single_spdx("LicenseRef-Proprietary") == LicenseRiskCategory.PROPRIETARY

    # Multiple classifiers with AND/OR in raw expression
    _spdx_m, cat_m, is_dual_m, _ = parse_spdx_expression(
        "Dual: MIT or Apache",
        classifiers=[
            "License :: OSI Approved :: MIT License",
            "License :: OSI Approved :: Apache Software License",
        ],
    )
    assert is_dual_m is True
    assert cat_m == LicenseRiskCategory.PERMISSIVE


def test_elf_static_and_invalid_inputs(tmp_path: Path) -> None:
    not_elf = tmp_path / "readme.txt"
    not_elf.write_text("hello world", encoding="utf-8")
    assert is_elf_file(not_elf) is False

    with pytest.raises(ValueError, match="Not an ELF file"):
        parse_elf_bytes(b"not-an-elf")

    static_bytes = build_synthetic_elf64(
        is_executable=True,
        static_only=True,
        interpreter=None,
    )
    static_bin = tmp_path / "static-app"
    static_bin.write_bytes(static_bytes)

    info = parse_elf_binary(static_bin)
    assert info.is_statically_linked is True
    linkage = verify_binary_linkage([info])
    assert linkage.is_self_contained is True
    assert linkage.linkage_issues[0].status == LinkageStatus.STATIC


def test_pyinstaller_standalone_directory_and_combined_policy_failure(tmp_path: Path) -> None:
    ws_dir = tmp_path / "app_ws"
    ws_dir.mkdir()
    (ws_dir / "pyproject.toml").write_text(
        """
[project]
name = "pyi-app"
version = "1.0.0"
dependencies = ["gpl-pkg>=1.0.0", "proprietary-pkg>=1.0.0", "mystery-pkg>=1.0.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    sp = ws_dir / ".venv" / "Lib" / "site-packages"
    create_dist_info(sp, "gpl-pkg", "1.0.0", license_str="GPL-3.0-only", top_level=["gpl_pkg"])
    create_dist_info(sp, "proprietary-pkg", "1.0.0", license_str="Proprietary", top_level=["proprietary_pkg"])
    create_dist_info(sp, "mystery-pkg", "1.0.0", license_str="UNKNOWN", top_level=["mystery_pkg"])

    # Create PyInstaller standalone directory with _internal/
    dist_dir = tmp_path / "dist" / "pyi-app"
    internal = dist_dir / "_internal"
    internal.mkdir(parents=True)
    (internal / "base_library.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    (internal / "gpl_pkg.pyc").write_bytes(b"\x00" * 16)
    (internal / "proprietary_pkg.pyc").write_bytes(b"\x00" * 16)
    (internal / "mystery_pkg.pyc").write_bytes(b"\x00" * 16)

    # Mock OSV returning a CRITICAL vulnerability for gpl-pkg
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": "CVE-2026-0001",
                                    "summary": "Critical vulnerability in gpl-pkg",
                                    "database_specific": {"severity": "CRITICAL", "cvss_score": 9.8},
                                }
                            ]
                        },
                        {"vulns": []},
                        {"vulns": []},
                    ]
                },
            )
        return httpx.Response(404)

    mock_client = httpx.Client(transport=httpx.MockTransport(handler))
    cfg = AuditConfig(
        project_path=ws_dir,
        dist_path=dist_dir,
        offline=False,
        fail_on_severity=Severity.HIGH,
        fail_on_license=Severity.HIGH,
    )
    report = run_audit(cfg, http_client=mock_client)
    assert report.bundler_type == BundlerType.PYINSTALLER
    assert report.layout == DistributionLayout.STANDALONE_DIR
    # Both vulnerability failure and license failure -> COMBINED_POLICY_FAILURE (3)
    assert report.exit_code == ExitCode.COMBINED_POLICY_FAILURE

    # Verify plain-text report rendering includes vulnerabilities, compliance findings, and linkage
    txt = format_report_text(report)
    assert "CVE-2026-0001" in txt
    assert "LIC-COP-STRONG" in txt
    assert "LIC-PROPRIETARY" in txt
    assert "LIC-UNKNOWN" in txt


def test_osv_network_failure_graceful_warning() -> None:
    def failing_handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("Simulated offline network failure")

    mock_client = httpx.Client(transport=httpx.MockTransport(failing_handler))
    comp = Component(name="httpx", version="0.27.0", component_type=ComponentType.PYTHON_PACKAGE)
    osv = OsvClient(http_client=mock_client)
    warnings = osv.audit_components([comp])
    assert len(warnings) == 1
    assert "OSV.dev vulnerability query failed" in warnings[0]


def test_misc_helper_edge_cases() -> None:
    assert normalize_pkg_name("") == ""
    assert parse_req_name("") == ""
    assert parse_req_name("invalid requirement === ???") == "invalid"
    assert compute_cvss_v3_score("") is None
    assert compute_cvss_v3_score("8.4") == 8.4
    assert compute_cvss_v3_score("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P") is None
    assert compute_cvss_v3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N") == 0.0
    assert score_to_severity(None) == Severity.MEDIUM
    assert score_to_severity(0.0) == Severity.NONE
    assert score_to_severity(2.5) == Severity.LOW
    assert score_to_severity(5.0) == Severity.MEDIUM
    assert score_to_severity(7.5) == Severity.HIGH
    assert score_to_severity(9.5) == Severity.CRITICAL

    with pytest.raises(ValueError, match="Unsupported SBOM format"):
        from rhada.models import AuditReport

        serialize_sbom(
            AuditReport(target_name="x", target_version="1.0", mode=AuditMode.SOURCE),
            fmt="invalid-format",
        )


def test_nested_compound_spdx_expressions_and_with_exceptions() -> None:
    # 1. (MIT OR Apache-2.0) AND GPL-3.0-only -> must evaluate as STRONG_COPYLEFT (not PERMISSIVE!)
    spdx_1, cat_1, is_dual_1, choices_1 = parse_spdx_expression("(MIT OR Apache-2.0) AND GPL-3.0-only")
    assert spdx_1 == "(MIT OR Apache-2.0) AND GPL-3.0-only"
    assert cat_1 == LicenseRiskCategory.STRONG_COPYLEFT
    assert is_dual_1 is False
    assert choices_1 == ["MIT", "Apache-2.0", "GPL-3.0-only"]

    # 2. (MIT OR Apache-2.0) AND BSD-3-Clause with allow-list {"MIT", "BSD-3-Clause"} -> permitted!
    lic_2 = build_license_info(
        license_expression="(MIT OR Apache-2.0) AND BSD-3-Clause",
        license_texts={"LICENSE": "MIT and BSD-3-Clause"},
    )
    assert lic_2.spdx_id == "(MIT OR Apache-2.0) AND BSD-3-Clause"
    assert lic_2.risk_category == LicenseRiskCategory.PERMISSIVE
    comp_2 = Component(name="compound-pkg", version="1.0.0", license_info=lic_2)
    findings_ok = evaluate_compliance(
        [comp_2],
        mode=AuditMode.SOURCE,
        layout=DistributionLayout.SOURCE_WORKSPACE,
        config=AuditConfig(allowed_licenses={"MIT", "BSD-3-Clause"}),
    )
    assert not any(f.rule_id == "LIC-POLICY-NOT-ALLOWED" for f in findings_ok)

    findings_fail = evaluate_compliance(
        [comp_2],
        mode=AuditMode.SOURCE,
        layout=DistributionLayout.SOURCE_WORKSPACE,
        config=AuditConfig(allowed_licenses={"MIT"}),
    )
    assert any(f.rule_id == "LIC-POLICY-NOT-ALLOWED" for f in findings_fail)

    # 3. SPDX WITH exceptions
    spdx_llvm, cat_llvm, _, _ = parse_spdx_expression("Apache-2.0 WITH LLVM-exception")
    assert spdx_llvm == "Apache-2.0 WITH LLVM-exception"
    assert cat_llvm == LicenseRiskCategory.PERMISSIVE

    spdx_cp, cat_cp, _, _ = parse_spdx_expression("GPL-2.0-only WITH Classpath-exception-2.0")
    assert spdx_cp == "GPL-2.0-only WITH Classpath-exception-2.0"
    assert cat_cp == LicenseRiskCategory.WEAK_COPYLEFT


def test_corrupted_pyinstaller_carchive_toc_and_hyphenated_dist_info(tmp_path: Path) -> None:
    import struct

    from rhada.dist import PYI_MAGIC, parse_pyinstaller_carchive_toc
    from tests.helpers import build_pyinstaller_carchive_payload

    # 1. Corrupted 88-byte cookie with pkg_len larger than binary / overflowing toc_offset
    bad_cookie_88 = struct.pack(
        "!8sIIii64s",
        PYI_MAGIC,
        999_999,
        500_000,
        200,
        311,
        b"libpython3.11.so".ljust(64, b"\x00"),
    )
    assert parse_pyinstaller_carchive_toc(b"prefix" + bad_cookie_88) == []

    # 2. Corrupted 24-byte cookie with negative toc_offset
    bad_cookie_24 = struct.pack(
        "!8siiii",
        PYI_MAGIC,
        40,
        -20,
        10,
        311,
    )
    assert parse_pyinstaller_carchive_toc(b"x" * 100 + bad_cookie_24) == []

    # 3. Hyphenated .dist-info inside PyInstaller CArchive TOC and Nuitka $$ submodule symbols
    carchive = build_pyinstaller_carchive_payload(
        [
            ("x", "my-cool-pkg-2.3.4.dist-info/METADATA"),
        ]
    )
    elf_bin = build_synthetic_elf64(
        is_executable=True,
        exported_symbols=["modulecode_yaml$$scanner"],
        trailing_payload=carchive,
    )
    bin_path = tmp_path / "app-onefile"
    bin_path.write_bytes(elf_bin)

    res = inspect_compiled_distribution(bin_path)
    assert res.discovered_distributions.get("my-cool-pkg") == "2.3.4"
    assert "my" not in res.discovered_distributions
    assert "yaml" in res.bundled_modules
    assert "yaml$$scanner" not in res.bundled_modules


def test_multi_version_uv_lock_and_purl_refresh(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "multi-ver-app"
version = "1.0.0"
dependencies = ["pyyaml>=6.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        """
version = 1

[[package]]
name = "multi-ver-app"
version = "1.0.0"
source = { virtual = "." }
dependencies = [{ name = "pyyaml" }]

[[package]]
name = "pyyaml"
version = "6.0.1"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "platform-dep-a" }]

[[package]]
name = "pyyaml"
version = "6.0.2"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "platform-dep-b" }]

[[package]]
name = "platform-dep-a"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "platform-dep-b"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }
""".strip()
        + "\n",
        encoding="utf-8",
    )

    # Install 6.0.1 in .venv (with unknown version in METADATA initially to test PURL refresh)
    sp = tmp_path / ".venv" / "Lib" / "site-packages"
    dist_dir = sp / "my-hyphen-pkg-1.5.0.dist-info"
    dist_dir.mkdir(parents=True)
    (dist_dir / "METADATA").write_text("Metadata-Version: 2.1\nLicense: MIT\n", encoding="utf-8")

    create_dist_info(sp, "PyYAML", "6.0.1", license_str="MIT")

    ws = inspect_workspace(tmp_path)
    # Must match the installed .venv version 6.0.1 rather than being overwritten by 6.0.2
    assert ws.components["pyyaml"].version == "6.0.1"
    assert ws.components["pyyaml"].purl == "pkg:pypi/pyyaml@6.0.1"
    # Merged dependencies from both platform entries in uv.lock
    assert "platform-dep-a" in ws.components
    assert "platform-dep-b" in ws.components
    # Fallback stem parsing for hyphenated .dist-info without Name/Version headers
    assert "my-hyphen-pkg" in ws.components
    assert ws.components["my-hyphen-pkg"].version == "1.5.0"
    assert ws.components["my-hyphen-pkg"].purl == "pkg:pypi/my-hyphen-pkg@1.5.0"


def test_dev_only_transitive_deps_and_reversed_extra_markers(tmp_path: Path) -> None:
    from typer.testing import CliRunner

    from rhada.cli import cli
    from rhada.models import ComponentScope

    # Project with zero runtime dependencies and dev-only pytest -> pluggy transitive dependency
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "stdlib-only-tool"
version = "1.0.0"
dependencies = []

[dependency-groups]
dev = ["pytest>=8.0.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (tmp_path / "uv.lock").write_text(
        """
version = 1

[[package]]
name = "stdlib-only-tool"
version = "1.0.0"
source = { virtual = "." }

[package.dev-dependencies]
dev = [{ name = "pytest" }]

[[package]]
name = "pytest"
version = "8.2.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [{ name = "pluggy" }]

[[package]]
name = "pluggy"
version = "1.5.0"
source = { registry = "https://pypi.org/simple" }
""".strip()
        + "\n",
        encoding="utf-8",
    )

    sp = tmp_path / ".venv" / "Lib" / "site-packages"
    create_dist_info(
        sp,
        "pytest",
        "8.2.0",
        license_str="MIT",
        requires_dist=["pluggy>=1.5", "hypothesis>=6.0 ; 'dev' == extra"],
    )
    create_dist_info(sp, "pluggy", "1.5.0", license_str="MIT")

    ws = inspect_workspace(tmp_path, include_dev=False)
    assert ws.components["pytest"].scope == ComponentScope.DEV_EXCLUDED
    assert ws.components["pytest"].is_bundled is False
    assert ws.components["pluggy"].scope == ComponentScope.DEV_EXCLUDED
    assert ws.components["pluggy"].is_bundled is False

    # Also verify without uv.lock (.venv only) that reversed extra marker ('dev' == extra) is ignored
    # and transitive dev dep pluggy is excluded when dependencies = []
    (tmp_path / "uv.lock").unlink()
    ws_no_lock = inspect_workspace(tmp_path, include_dev=False)
    assert "hypothesis" not in ws_no_lock.components["pytest"].dependencies
    assert ws_no_lock.components["pluggy"].scope == ComponentScope.DEV_EXCLUDED
    assert ws_no_lock.components["pluggy"].is_bundled is False

    # Verify inspect-elf returns ExitCode.USAGE_OR_IO_ERROR (5) on non-existent target
    runner = CliRunner()
    res_missing = runner.invoke(cli, ["inspect-elf", str(tmp_path / "no-such-binary")])
    assert res_missing.exit_code == int(ExitCode.USAGE_OR_IO_ERROR)


def test_compound_spdx_multiword_unknown_and_metadata_placeholders(tmp_path: Path) -> None:
    from rhada.models import LicenseInfo, Vulnerability
    from rhada.spdx import evaluate_spdx_denylist

    # 1. Multi-word licence names inside compound AND expression must not be misclassified as permissive MIT
    spdx_mw, cat_mw, is_dual_mw, choices_mw = parse_spdx_expression("MIT License AND GPLv3")
    assert spdx_mw == "MIT AND GPL-3.0-only"
    assert cat_mw == LicenseRiskCategory.STRONG_COPYLEFT
    assert is_dual_mw is False
    assert choices_mw == ["MIT", "GPL-3.0-only"]

    # 2. Conjunctive expression with an unrecognised leaf must not silently match the known half
    spdx_unk, cat_unk, is_dual_unk, choices_unk = parse_spdx_expression("MIT AND CustomUnrecognisedClause")
    assert spdx_unk == "NOASSERTION"
    assert cat_unk == LicenseRiskCategory.UNKNOWN
    assert is_dual_unk is False
    assert choices_unk == []

    # 3. Redundant identical leaves and compact slash expressions
    spdx_dup, cat_dup, is_dual_dup, choices_dup = parse_spdx_expression("Zlib OR Zlib")
    assert spdx_dup == "Zlib"
    assert cat_dup == LicenseRiskCategory.PERMISSIVE
    assert is_dual_dup is False
    assert choices_dup == ["Zlib"]

    spdx_slash, cat_slash, is_dual_slash, choices_slash = parse_spdx_expression("MIT/Apache-2.0")
    assert spdx_slash == "MIT OR Apache-2.0"
    assert cat_slash == LicenseRiskCategory.PERMISSIVE
    assert is_dual_slash is True
    assert choices_slash == ["MIT", "Apache-2.0"]

    # 4. Deny-list AST evaluation on compound expressions
    assert evaluate_spdx_denylist("MIT AND GPL-3.0-only", {"GPL-3.0-ONLY"}) is True
    assert evaluate_spdx_denylist("MIT OR GPL-3.0-only", {"GPL-3.0-ONLY"}) is False
    assert evaluate_spdx_denylist("MIT OR GPL-3.0-only", {"MIT", "GPL-3.0-ONLY"}) is True

    comp_and = Component(
        name="conjunctive-pkg",
        version="1.0.0",
        license_info=LicenseInfo(
            declared_raw="MIT AND GPL-3.0-only",
            spdx_id="MIT AND GPL-3.0-only",
            risk_category=LicenseRiskCategory.STRONG_COPYLEFT,
        ),
    )
    findings = evaluate_compliance(
        [comp_and],
        mode=AuditMode.SOURCE,
        layout=DistributionLayout.SOURCE_WORKSPACE,
        config=AuditConfig(denied_licenses={"GPL-3.0-only"}),
    )
    assert any(f.rule_id == "LIC-POLICY-DENIED" for f in findings)

    # 5. METADATA 'Home-page: UNKNOWN' and 'Author: UNKNOWN' placeholders
    sp = tmp_path / ".venv" / "Lib" / "site-packages"
    dist_dir = create_dist_info(
        sp,
        "placeholder-pkg",
        "1.0.0",
        license_str="MIT",
        homepage="UNKNOWN",
        author="UNKNOWN",
    )
    meta_file = dist_dir / "METADATA"
    meta_file.write_text(
        meta_file.read_text(encoding="utf-8") + "Project-URL: Homepage, https://example.org/placeholder\n",
        encoding="utf-8",
    )
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "app"\nversion = "1.0.0"\ndependencies = ["placeholder-pkg>=1.0.0"]\n',
        encoding="utf-8",
    )
    ws = inspect_workspace(tmp_path)
    p_comp = ws.components["placeholder-pkg"]
    assert p_comp.homepage == "https://example.org/placeholder"
    assert p_comp.author == ""

    # 6. Vulnerability.remediation semantic PEP 440 version sorting
    v = Vulnerability(
        id="CVE-2026-1111",
        summary="Test",
        fixed_versions=["2.10.0", "2.2.0"],
        component_name="demo",
        component_version="2.0.0",
    )
    assert v.remediation == "Upgrade demo to version >= 2.2.0, 2.10.0"


def test_native_profile_prefix_boundary_matching() -> None:
    # Exact and delimited matches
    prof_zlib = _match_known_native_profile("libz")
    assert prof_zlib is not None
    assert prof_zlib.canonical_name == "zlib"

    prof_zlib_ver = _match_known_native_profile("libz-1.2.11")
    assert prof_zlib_ver is not None
    assert prof_zlib_ver.canonical_name == "zlib"

    prof_crypto = _match_known_native_profile("libcrypto")
    assert prof_crypto is not None
    assert prof_crypto.canonical_name == "openssl"

    # Distinct libraries sharing prefix must not collide
    assert _match_known_native_profile("libzmq") is None
    assert _match_known_native_profile("libzip") is None
    assert _match_known_native_profile("libzbar") is None
    assert _match_known_native_profile("libcryptopp") is None


def test_setup_cfg_percent_interpolation_resilience(tmp_path: Path) -> None:
    cfg_file = tmp_path / "setup.cfg"
    cfg_file.write_text(
        "[metadata]\nname = demo\nversion = 1.0.0\ndescription = 100% pure python\n",
        encoding="utf-8",
    )
    res = _parse_setup_cfg(cfg_file)
    assert res["name"] == "demo"
    assert res["version"] == "1.0.0"
    assert res["description"] == "100% pure python"


def test_utf8_bom_resilience(tmp_path: Path) -> None:
    bom_file = tmp_path / "METADATA"
    # Write UTF-8 with BOM prefix
    bom_content = b"\xef\xbb\xbfName: bom-pkg\nVersion: 2.0.0\nSummary: BOM test\n"
    bom_file.write_bytes(bom_content)
    text = _read_text_safe(bom_file)
    assert not text.startswith("\ufeff")
    assert "Name: bom-pkg" in text


def test_cvss_v4_scoring_and_parsing() -> None:
    v4_vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    score = compute_cvss_v3_score(v4_vector)
    assert score is not None
    assert score >= 9.0

    raw_advisory = {
        "id": "GHSA-v4-critical",
        "summary": "Critical Remote Code Execution",
        "severity": [{"type": "CVSS_V4", "score": v4_vector}],
    }
    vuln = parse_osv_vulnerability(raw_advisory, "demo-package", "1.0.0")
    assert vuln.severity == Severity.CRITICAL
    assert vuln.cvss_score is not None
    assert vuln.cvss_score >= 9.0
    assert vuln.cvss_vector == v4_vector


def test_record_traversal_protection(tmp_path: Path) -> None:
    sp_dir = tmp_path / "site-packages"
    sp_dir.mkdir(parents=True)
    dist_dir = sp_dir / "evil_pkg-1.0.0.dist-info"
    dist_dir.mkdir(parents=True)

    # Outside file that should NOT be traversed to
    secret_file = tmp_path / "secret.dll"
    secret_file.write_bytes(b"MZ\x90\x00not-real")

    # RECORD containing paths attempting directory traversal
    record_file = dist_dir / "RECORD"
    record_file.write_text(
        "../../secret.dll,sha256=xxx,123\n"
        "sub/../../secret.dll,sha256=xxx,123\n"
        "C:/windows/system32/calc.exe,sha256=xxx,123\n",
        encoding="utf-8",
    )
    meta_file = dist_dir / "METADATA"
    meta_file.write_text("Metadata-Version: 2.1\nName: evil-pkg\nVersion: 1.0.0\n", encoding="utf-8")

    from rhada.workspace import _discover_dist_native_libraries
    pkg_comp = Component(name="evil-pkg", version="1.0.0")
    results = _discover_dist_native_libraries(dist_dir, pkg_comp)
    # None of the traversed paths should be loaded as native components
    assert len(results) == 0


def test_parse_req_name_direct_urls_and_archives() -> None:
    assert parse_req_name("git+https://github.com/org/proj.git#egg=proj") == "proj"
    assert parse_req_name("git+https://github.com/org/my-cool-package.git") == "my-cool-package"
    assert parse_req_name("wheels/foo_bar-1.0-py3-none-any.whl") == "foo-bar"
    assert parse_req_name("dist/cool-lib-2.3.4.tar.gz") == "cool-lib"
    assert parse_req_name("requests>=2.0.0 ; sys_platform == 'win32'") == "requests"
    assert parse_req_name("Flask[async] >= 2.0") == "flask"







def test_parse_nuitka_source_directives(tmp_path: Path) -> None:
    from rhada.workspace import parse_nuitka_source_directives

    main_py = tmp_path / "main.py"
    main_py.write_text(
        '# nuitka-project: --include-package=cryptography --enable-plugin=numpy\n'
        '# nuitka-project: --include-package-data=certifi\n'
        '# nuitka-project: --include-data-files="configs/*.json=configs/"\n'
        '# nuitka-project:\n'
        '#    --include-module=engine.worker\n'
        '#    --include-package=sqlalchemy\n'
        '# nuitka-project-if sys.platform != "nonexistent_os":\n'
        '#    --include-package=pytest\n'
        '# nuitka-project-if sys.platform == "nonexistent_os":\n'
        '#    --include-package=should_be_skipped\n'
        'import os\n'
        'print("hello")\n',
        encoding="utf-8",
    )

    directives = parse_nuitka_source_directives(main_py)
    assert "cryptography" in directives["include_packages"]
    assert "sqlalchemy" in directives["include_packages"]
    assert "pytest" in directives["include_packages"]
    assert "should_be_skipped" not in directives["include_packages"]
    assert "numpy" in directives["plugins"]
    assert "certifi" in directives["include_package_data"]
    assert "engine.worker" in directives["include_modules"]
    assert any("configs/*.json=configs/" in opt for opt in directives["include_data_files"])


def test_inspect_workspace_nuitka_directives_and_dist_correlation(tmp_path: Path) -> None:
    from rhada.dist import DistInspectionResult, correlate_workspace_and_dist
    from rhada.models import BundlerType, ComponentScope, DistributionLayout
    from rhada.workspace import inspect_workspace

    ws_dir = tmp_path / "proj"
    ws_dir.mkdir()
    (ws_dir / "pyproject.toml").write_text(
        '[project]\nname = "my-app"\nversion = "1.0.0"\ndependencies = []\n',
        encoding="utf-8",
    )
    (ws_dir / "main.py").write_text(
        '# nuitka-project: --include-package=cryptography\n'
        '# nuitka-project: --enable-plugin=numpy\n',
        encoding="utf-8",
    )

    ws = inspect_workspace(ws_dir)
    assert "cryptography" in ws.direct_runtime_deps
    assert "numpy" in ws.direct_runtime_deps
    assert "cryptography" in ws.nuitka_directives.get("include_packages", [])

    # Stub component in ws.components
    assert "cryptography" in ws.components
    assert ws.components["cryptography"].scope == ComponentScope.REQUIRED

    # Mock dist result without discovered distributions (e.g. monolithic binary)
    dist_res = DistInspectionResult(
        layout=DistributionLayout.MONOLITHIC_BINARY,
        bundler_type=BundlerType.NUITKA,
    )
    active, _excluded = correlate_workspace_and_dist(ws, dist_res)
    active_names = {c.name for c in active}
    assert "cryptography" in active_names


def test_build_resolved_dependency_version_sanitization() -> None:
    from packaging.version import Version

    from rhada.models import Component, ComponentType
    from rhada.osv import _build_resolved_dependency

    # Standard clean semver
    c1 = Component(name="requests", version="2.31.0", component_type=ComponentType.PYTHON_PACKAGE)
    rd1 = _build_resolved_dependency(c1)
    assert rd1 is not None
    assert rd1.version == Version("2.31.0")

    # Leading 'v'
    c2 = Component(name="urllib3", version="v1.26.15", component_type=ComponentType.PYTHON_PACKAGE)
    rd2 = _build_resolved_dependency(c2)
    assert rd2 is not None
    assert rd2.version == Version("1.26.15")

    # Non-PEP-440 suffix or snapshot (e.g. 2.1.0-alpha+build.123)
    c3 = Component(name="custom-pkg", version="2.1.0-custom-snapshot", component_type=ComponentType.PYTHON_PACKAGE)
    rd3 = _build_resolved_dependency(c3)
    assert rd3 is not None
    assert rd3.version == Version("2.1.0")

    # Pure date version
    c4 = Component(name="date-pkg", version="20240101", component_type=ComponentType.PYTHON_PACKAGE)
    rd4 = _build_resolved_dependency(c4)
    assert rd4 is not None
    assert rd4.version == Version("20240101")

    # Unknown or empty version
    c5 = Component(name="unknown-pkg", version="unknown", component_type=ComponentType.PYTHON_PACKAGE)
    assert _build_resolved_dependency(c5) is None


def test_parse_setup_py_annotated_assignments_and_literals(tmp_path: Path) -> None:
    from rhada.workspace import _parse_setup_py

    setup_py = tmp_path / "setup.py"
    setup_py.write_text(
        "from setuptools import setup\n\n"
        "NAME: str = 'my-annotated-tool'\n"
        "VERSION: str = '3.4.1'\n"
        "DESCRIPTION = 'Modern tool with annotated setup.py'\n"
        "REQUIREMENTS = ['click>=8.0', 'pydantic>=2.0']\n\n"
        "setup(\n"
        "    name=NAME,\n"
        "    version=VERSION,\n"
        "    description=DESCRIPTION,\n"
        "    license='MIT',\n"
        "    install_requires=REQUIREMENTS,\n"
        "    extras_require={'dev': ['pytest', 'ruff']},\n"
        ")\n",
        encoding="utf-8",
    )

    data = _parse_setup_py(setup_py)
    assert data["name"] == "my-annotated-tool"
    assert data["version"] == "3.4.1"
    assert data["description"] == "Modern tool with annotated setup.py"
    assert data["license"] == "MIT"
    assert data["dependencies"] == ["click>=8.0", "pydantic>=2.0"]
    assert data["optional-dependencies"]["dev"] == ["pytest", "ruff"]
