"""Unit tests for ELF binary parsing, linkage verification, Nuitka, and PyInstaller distributions."""

from __future__ import annotations

from pathlib import Path

from rhada.dist import (
    build_distribution_file_inventory,
    correlate_workspace_and_dist,
    inspect_compiled_distribution,
)
from rhada.elf import (
    _parse_elf_struct_fallback,
    elf_to_native_component,
    is_elf_file,
    parse_elf_binary,
    verify_binary_linkage,
)
from rhada.models import (
    BundlerType,
    Component,
    ComponentType,
    DistributionFileCategory,
    DistributionLayout,
    LicenseRiskCategory,
    LinkageStatus,
)
from rhada.workspace import inspect_workspace
from tests.helpers import (
    build_pyinstaller_carchive_payload,
    build_synthetic_elf64,
    create_dist_info,
)


def test_parse_elf64_and_struct_fallback(tmp_path: Path) -> None:
    elf_bytes = build_synthetic_elf64(
        is_executable=False,
        soname="libssl.so.3",
        needed_libs=["libcrypto.so.3", "libc.so.6"],
        runpath="$ORIGIN",
        exported_symbols=["SSL_new", "OPENSSL_init_ssl"],
        rodata_strings=["OpenSSL 3.2.1 30 Jan 2024"],
    )
    so_file = tmp_path / "libssl.so.3"
    so_file.write_bytes(elf_bytes)

    assert is_elf_file(so_file) is True
    info = parse_elf_binary(so_file)
    assert info.soname == "libssl.so.3"
    assert "libcrypto.so.3" in info.needed_libs
    assert "libc.so.6" in info.needed_libs
    assert info.runpath == "$ORIGIN"
    assert info.architecture == "x86_64"
    assert info.bits == 64
    assert info.detected_library_name == "openssl"
    assert info.detected_version == "3.2.1"

    # Also verify pure-Python struct fallback works on the same bytes
    fallback = _parse_elf_struct_fallback(elf_bytes, str(so_file), info.sha256)
    assert fallback.architecture == "x86_64"
    assert fallback.bits == 64
    assert fallback.detected_library_name == "openssl"
    assert fallback.detected_version == "3.2.1"

    # Native component conversion
    comp = elf_to_native_component(info, is_monolithic=False)
    assert comp is not None
    assert comp.name == "openssl"
    assert comp.version == "3.2.1"
    assert comp.license_info.spdx_id == "Apache-2.0"
    assert comp.license_info.risk_category == LicenseRiskCategory.PERMISSIVE


def test_verify_binary_linkage_bundled_system_missing_and_insecure_rpath(tmp_path: Path) -> None:
    # Main app binary needing bundled libz.so.1, system libc.so.6, and missing libunbundled.so.9
    app_bytes = build_synthetic_elf64(
        is_executable=True,
        needed_libs=["libz.so.1", "libc.so.6", "libunbundled.so.9"],
        rpath="/tmp/insecure-build-dir:$ORIGIN",
    )
    libz_bytes = build_synthetic_elf64(
        is_executable=False,
        soname="libz.so.1",
        needed_libs=["libc.so.6"],
        rodata_strings=["zlib version 1.3.1"],
    )

    app_path = tmp_path / "app.bin"
    libz_path = tmp_path / "libz.so.1"
    app_path.write_bytes(app_bytes)
    libz_path.write_bytes(libz_bytes)

    b_app = parse_elf_binary(app_path)
    b_libz = parse_elf_binary(libz_path)

    report = verify_binary_linkage([b_app, b_libz], dist_root=tmp_path)
    assert "libz.so.1" in report.resolved_dependencies
    assert "libc.so.6" in report.system_abi_dependencies
    assert report.unresolved_dependencies == ["libunbundled.so.9"]
    assert len(report.insecure_rpaths) == 1
    assert report.is_self_contained is False

    by_lib = {i.needed_lib: i.status for i in report.linkage_issues}
    assert by_lib["libz.so.1"] == LinkageStatus.BUNDLED
    assert by_lib["libc.so.6"] == LinkageStatus.SYSTEM_ABI
    assert by_lib["libunbundled.so.9"] == LinkageStatus.MISSING_EXTERNAL


def test_nuitka_standalone_dist_correlates_and_excludes_dev_tools(tmp_path: Path) -> None:
    # 1. Setup workspace with runtime (httpx, cryptography) + dev/build (pytest, nuitka)
    ws_dir = tmp_path / "workspace"
    ws_dir.mkdir()
    (ws_dir / "pyproject.toml").write_text(
        """
[project]
name = "secure-agent"
version = "0.5.0"
dependencies = ["httpx>=0.27.0", "cryptography>=42.0.0"]

[dependency-groups]
dev = ["pytest>=8.0.0", "nuitka>=2.1.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    sp = ws_dir / ".venv" / "Lib" / "site-packages"
    create_dist_info(sp, "httpx", "0.27.0", license_str="BSD-3-Clause", top_level=["httpx"])
    create_dist_info(
        sp, "cryptography", "42.0.5", license_expression="Apache-2.0 OR BSD-3-Clause", top_level=["cryptography"]
    )
    create_dist_info(sp, "pytest", "8.1.1", license_str="MIT", top_level=["pytest"])
    create_dist_info(sp, "nuitka", "2.1.2", license_str="Apache-2.0", top_level=["nuitka"])

    # 2. Setup Nuitka standalone directory (.dist) with compilation-report.xml, C extension, and libgmp.so.10
    dist_dir = tmp_path / "secure-agent.dist"
    dist_dir.mkdir()
    (dist_dir / "compilation-report.xml").write_text(
        """<?xml version="1.0" encoding="utf8"?>
<nuitka-compilation-report nuitka_version="2.1.2">
  <module name="httpx" kind="compiled_module" distribution="httpx" />
  <module name="cryptography" kind="compiled_module" distribution="cryptography" />
  <module name="pytest" kind="excluded" reason="excluded" />
  <distributions>
    <distribution name="httpx" version="0.27.0" />
    <distribution name="cryptography" version="42.0.5" />
  </distributions>
</nuitka-compilation-report>
""",
        encoding="utf-8",
    )

    main_bin = build_synthetic_elf64(
        is_executable=True,
        needed_libs=["libgmp.so.10", "libc.so.6"],
        runpath="$ORIGIN",
        exported_symbols=["modulecode_httpx", "modulecode_cryptography"],
        rodata_strings=["__nuitka_version__"],
    )
    (dist_dir / "secure-agent.bin").write_bytes(main_bin)

    gmp_so = build_synthetic_elf64(
        is_executable=False,
        soname="libgmp.so.10",
        needed_libs=["libc.so.6"],
        rodata_strings=["GNU MP Library version 6.3.0"],
    )
    (dist_dir / "libgmp.so.10").write_bytes(gmp_so)

    ws = inspect_workspace(ws_dir)
    dist_res = inspect_compiled_distribution(dist_dir)

    assert dist_res.bundler_type == BundlerType.NUITKA
    assert dist_res.layout == DistributionLayout.STANDALONE_DIR
    assert dist_res.linkage_report.is_self_contained is True

    active, excluded = correlate_workspace_and_dist(ws, dist_res)
    active_names = {c.name: c for c in active}
    excluded_names = {c.name for c in excluded}

    assert "httpx" in active_names
    assert "cryptography" in active_names
    assert "gmp" in active_names
    assert active_names["gmp"].version == "6.3.0"
    assert active_names["gmp"].license_info.spdx_id == "LGPL-3.0-or-later"

    # Dev/build tools must be excluded from the compiled bundle
    assert "pytest" in excluded_names
    assert "nuitka" in excluded_names
    assert "pytest" not in active_names
    assert "nuitka" not in active_names


def test_pyinstaller_monolithic_onefile_binary_inspection(tmp_path: Path) -> None:
    # Build a PyInstaller monolithic onefile ELF executable with an embedded MEI CArchive TOC
    carchive = build_pyinstaller_carchive_payload(
        [
            ("m", "click"),
            ("b", "markupsafe/_speedups.cpython-311-x86_64-linux-gnu.so"),
            ("b", "libssl.so.3"),
            ("x", "click-8.1.7.dist-info/METADATA"),
        ]
    )
    onefile_elf = build_synthetic_elf64(
        is_executable=True,
        needed_libs=["libc.so.6", "libdl.so.2"],
        rodata_strings=["pyi-runtime-tmpdir", "OpenSSL 3.1.4"],
        trailing_payload=carchive,
    )
    bin_path = tmp_path / "cli-onefile"
    bin_path.write_bytes(onefile_elf)

    res = inspect_compiled_distribution(bin_path)
    assert res.bundler_type == BundlerType.PYINSTALLER
    assert res.layout == DistributionLayout.MONOLITHIC_BINARY
    assert "click" in res.bundled_modules
    assert "markupsafe" in res.bundled_modules
    assert res.discovered_distributions.get("click") == "8.1.7"
    assert any(n.name == "openssl" and n.version == "3.1.4" for n in res.native_components)


def test_nuitka_compilation_report_first_party_and_nested_modules(tmp_path: Path) -> None:
    # Workspace project
    proj_dir = tmp_path / "my_app"
    proj_dir.mkdir()
    (proj_dir / "pyproject.toml").write_text(
        """[project]
name = "my_app"
version = "1.0.0"
dependencies = ["httpx>=0.27.0"]

[tool.hatch.build.targets.wheel]
packages = ["my_pkg"]
""",
        encoding="utf-8",
    )
    src_pkg = proj_dir / "my_pkg" / "nested"
    src_pkg.mkdir(parents=True)
    (proj_dir / "my_pkg" / "__init__.py").write_text("", encoding="utf-8")
    (src_pkg / "__init__.py").write_text("def run(): pass\n", encoding="utf-8")

    ws = inspect_workspace(proj_dir)
    assert "my_pkg" in ws.project_modules
    assert "my_pkg.nested" in ws.project_modules

    dist_dir = tmp_path / "my_app.dist"
    dist_dir.mkdir()
    (dist_dir / "report.xml").write_text(
        """<?xml version="1.0" encoding="utf8"?>
<nuitka-compilation-report nuitka_version="2.1.2">
  <module name="__main__" kind="PythonMainModule" usage="root_module" source_path="${cwd}/entrypoint.py" />
  <module name="my_pkg" kind="CompiledPythonPackage" source_path="${cwd}/my_pkg/__init__.py" />
  <module name="my_pkg.nested" kind="CompiledPythonPackage" source_path="${cwd}/my_pkg/nested/__init__.py" />
  <module name="httpx" kind="compiled_module" distribution="httpx" source_path="${sys.prefix}/Lib/site-packages/httpx/__init__.py" />
  <distributions>
    <distribution name="httpx" version="0.27.0" />
  </distributions>
</nuitka-compilation-report>
""",
        encoding="utf-8",
    )

    res = inspect_compiled_distribution(dist_dir, compilation_report_path=dist_dir / "report.xml")
    assert "my_pkg" in res.project_modules
    assert "my_pkg.nested" in res.project_modules
    assert "my_pkg" not in res.bundled_modules
    assert "my_pkg.nested" not in res.bundled_modules
    assert "httpx" in res.bundled_modules

    active, _excluded = correlate_workspace_and_dist(ws, res)
    active_names = {c.name for c in active}
    assert "httpx" in active_names
    assert "my-pkg" not in active_names
    assert "my-pkg-nested" not in active_names
    assert "my_pkg" not in active_names
    assert "my_pkg.nested" not in active_names


def test_build_distribution_file_inventory(tmp_path: Path) -> None:
    dist_dir = tmp_path / "app.dist"
    dist_dir.mkdir()

    # Application binary
    (dist_dir / "app.exe").write_bytes(b"MZapp binary")

    # Python runtime and stdlib
    (dist_dir / "python313.dll").write_bytes(b"MZpython runtime")
    (dist_dir / "select.pyd").write_bytes(b"MZselect extension")

    # Compiler ABI
    (dist_dir / "vcruntime140.dll").write_bytes(b"MZmsvc runtime")

    # Native library
    (dist_dir / "libcrypto-3-x64.dll").write_bytes(b"MZopenssl crypto")

    # Python package
    pkg_dir = dist_dir / "requests"
    pkg_dir.mkdir()
    (pkg_dir / "__init__.py").write_text("# requests\n", encoding="utf-8")

    # Metadata
    (dist_dir / "compilation-report.xml").write_text("<report/>", encoding="utf-8")

    # Unaccounted mystery file
    (dist_dir / "mystery.bin").write_bytes(b"\x00\x01\x02")

    components = [
        Component(
            name="requests",
            version="2.31.0",
            component_type=ComponentType.PYTHON_PACKAGE,
            top_level_modules=["requests"],
        ),
    ]
    native_components = [
        Component(
            name="openssl",
            version="3.0.0",
            component_type=ComponentType.NATIVE_LIBRARY,
            bundled_files=["libcrypto-3-x64.dll"],
        )
    ]

    inventory = build_distribution_file_inventory(
        dist_path=dist_dir,
        target_name="app",
        target_version="1.0.0",
        components=components,
        native_components=native_components,
    )

    assert inventory.total_files == 8
    assert inventory.classified_count == 7
    assert len(inventory.unaccounted_files) == 1
    assert inventory.coverage_percent == 87.5
    assert [f.path for f in inventory.unaccounted_files] == ["mystery.bin"]

    cat_map = {f.path: f.category for f in inventory.files}
    assert cat_map["app.exe"] == DistributionFileCategory.APPLICATION_BINARY
    assert cat_map["python313.dll"] == DistributionFileCategory.PYTHON_RUNTIME
    assert cat_map["select.pyd"] == DistributionFileCategory.PYTHON_RUNTIME
    assert cat_map["vcruntime140.dll"] == DistributionFileCategory.COMPILER_ABI
    assert cat_map["libcrypto-3-x64.dll"] == DistributionFileCategory.NATIVE_LIBRARY
    assert cat_map["requests/__init__.py"] == DistributionFileCategory.PYTHON_PACKAGE
    assert cat_map["compilation-report.xml"] == DistributionFileCategory.DATA_OR_METADATA
    assert cat_map["mystery.bin"] == DistributionFileCategory.UNACCOUNTED
