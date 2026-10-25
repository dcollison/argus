"""Tests for Windows PE (.exe, .dll, .pyd) support and NumPy/SciPy scientific Python auditing."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from rhada.auditor import run_audit
from rhada.cli import cli
from rhada.compliance import generate_third_party_notices
from rhada.dist import correlate_workspace_and_dist, inspect_compiled_distribution
from rhada.elf import (
    elf_to_native_component,
    is_binary_file,
    is_pe_file,
    parse_binary,
    parse_elf_bytes,
    parse_pe_binary,
    parse_pe_bytes,
    verify_binary_linkage,
)
from rhada.models import (
    AuditConfig,
    AuditMode,
    AuditReport,
    BundlerType,
    DistributionLayout,
    ExitCode,
    LicenseRiskCategory,
    LinkageStatus,
    Severity,
)
from rhada.workspace import _inspect_dist_info, inspect_workspace
from tests.helpers import (
    build_pyinstaller_carchive_payload,
    build_synthetic_elf64,
    build_synthetic_pe64,
    create_dist_info,
)


def test_parse_pe64_imports_delay_loads_exports_and_utf16_version(tmp_path: Path) -> None:
    pe_bytes = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="libssl-3-x64.dll",
        needed_libs=["libcrypto-3-x64.dll", "KERNEL32.dll", "WS2_32.dll", "VCRUNTIME140.dll"],
        delay_load_libs=["CRYPT32.dll"],
        exported_symbols=["SSL_new", "OPENSSL_init_ssl"],
        utf16_strings=["FileVersion", "OpenSSL 3.3.1 4 Jun 2024"],
    )
    dll_path = tmp_path / "libssl-3-x64.dll"
    dll_path.write_bytes(pe_bytes)

    assert is_pe_file(dll_path) is True
    assert is_binary_file(dll_path) is True

    info = parse_pe_binary(dll_path)
    assert info.binary_format == "PE"
    assert info.architecture == "x86_64"
    assert info.bits == 64
    assert info.is_shared_object is True
    assert info.is_executable is False
    assert info.soname == "libssl-3-x64.dll"
    assert "libcrypto-3-x64.dll" in info.needed_libs
    assert "KERNEL32.dll" in info.needed_libs
    assert "CRYPT32.dll" in info.needed_libs
    assert info.detected_library_name == "openssl"
    assert info.detected_version == "3.3.1"

    comp = elf_to_native_component(info, is_monolithic=False)
    assert comp is not None
    assert comp.name == "openssl"
    assert comp.version == "3.3.1"
    assert comp.ecosystem == "Windows"
    assert comp.license_info.spdx_id == "Apache-2.0"


def test_windows_pe_linkage_case_insensitive_system_abi_and_missing(tmp_path: Path) -> None:
    app_exe = build_synthetic_pe64(
        is_executable=True,
        needed_libs=[
            "PYTHON312.DLL",
            "LIBSSL-3-X64.DLL",
            "KERNEL32.dll",
            "api-ms-win-crt-runtime-l1-1-0.dll",
            "VCRUNTIME140.dll",
            "missing_custom.dll",
        ],
    )
    py_dll = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="python312.dll",
        needed_libs=["KERNEL32.dll", "ucrtbase.dll"],
        rodata_strings=["3.12.4 (tags/v3.12.4:8e8a4ba)"],
    )
    ssl_dll = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="libssl-3-x64.dll",
        needed_libs=["KERNEL32.dll"],
        rodata_strings=["OpenSSL 3.2.2"],
    )

    exe_path = tmp_path / "app.exe"
    py_path = tmp_path / "python312.dll"
    ssl_path = tmp_path / "libssl-3-x64.dll"
    exe_path.write_bytes(app_exe)
    py_path.write_bytes(py_dll)
    ssl_path.write_bytes(ssl_dll)

    b_exe = parse_binary(exe_path)
    b_py = parse_binary(py_path)
    b_ssl = parse_binary(ssl_path)

    report = verify_binary_linkage([b_exe, b_py, b_ssl], dist_root=tmp_path)
    assert report.is_self_contained is False
    assert "PYTHON312.DLL" in report.resolved_dependencies
    assert "LIBSSL-3-X64.DLL" in report.resolved_dependencies
    assert "KERNEL32.dll" in report.system_abi_dependencies
    assert "api-ms-win-crt-runtime-l1-1-0.dll" in report.system_abi_dependencies
    assert "VCRUNTIME140.dll" in report.system_abi_dependencies
    assert report.unresolved_dependencies == ["missing_custom.dll"]

    by_lib = {i.needed_lib: i.status for i in report.linkage_issues}
    assert by_lib["PYTHON312.DLL"] == LinkageStatus.BUNDLED
    assert by_lib["LIBSSL-3-X64.DLL"] == LinkageStatus.BUNDLED
    assert by_lib["KERNEL32.dll"] == LinkageStatus.SYSTEM_ABI
    assert by_lib["missing_custom.dll"] == LinkageStatus.MISSING_EXTERNAL


def test_numpy_and_scipy_workspace_license_and_record_handling(tmp_path: Path) -> None:
    """
    Verify that NumPy and SciPy workspaces with multi-section LICENSE.txt files,
    LICENSES_bundled.txt appendices, large RECORD files (>256 KB), .libs directories,
    and Windows Scripts/f2py.exe are accurately parsed as BSD-3-Clause without
    polluting top_level_modules.
    """
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "scientific-solver"
version = "1.2.0"
dependencies = ["numpy>=2.0.0", "scipy>=1.14.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )

    sp = tmp_path / ".venv" / "Lib" / "site-packages"
    numpy_license_text = (
        "Copyright (c) 2005-2024, NumPy Developers.\n"
        "All rights reserved.\n\n"
        "Redistribution and use in source and binary forms, with or without\n"
        "modification, are permitted provided that the following conditions are\n"
        "met:\n"
        "    * Redistributions of source code must retain the above copyright\n"
        "       notice, this list of conditions and the following disclaimer.\n"
        "    * Redistributions in binary form must reproduce the above\n"
        "       copyright notice, this list of conditions and the following\n"
        "       disclaimer in the documentation and/or other materials provided\n"
        "       with the distribution.\n"
        "    * Neither the name of the NumPy Developers nor the names of any\n"
        "       contributors may be used to endorse or promote products derived\n"
        "       from this software without specific prior written permission.\n\n"
        + ("=" * 80 + "\n")
        + "Name: OpenBLAS\nFiles: numpy.libs/libscipy_openblas64_*.dll\nLicense: BSD-3-Clause\n"
        + "Name: libgfortran\nLicense: GNU General Public License Version 3 with GCC Runtime Library Exception\n"
    )
    scipy_bundled_licenses = (
        "SciPy bundles the following third-party libraries:\n"
        "- Qhull (BSD-3-Clause)\n"
        "- SuperLU (BSD-3-Clause)\n"
        "- ARPACK-NG (BSD-3-Clause)\n"
        "- HiGHS (MIT)\n"
        "- libquadmath (GNU Lesser General Public License Version 2.1)\n"
    )
    scipy_primary_license = (
        "Copyright (c) 2001-2002 Enthought, Inc. 2003-2024, SciPy Developers.\n"
        "All rights reserved.\n\n"
        "Redistribution and use in source and binary forms, with or without\n"
        "modification, are permitted provided that the following conditions\n"
        "are met:\n"
        "1. Redistributions of source code must retain the above copyright\n"
        "   notice, this list of conditions and the following disclaimer.\n"
        "2. Redistributions in binary form must reproduce the above\n"
        "   copyright notice, this list of conditions and the following\n"
        "   disclaimer in the documentation and/or other materials provided\n"
        "   with the distribution.\n"
        "3. Neither the name of Enthought nor the names of the SciPy Developers\n"
        "   may be used to endorse or promote products derived from this\n"
        "   software without specific prior written permission.\n"
    )

    np_dist = create_dist_info(
        sp,
        "numpy",
        "2.1.3",
        license_str=numpy_license_text,
        classifiers=["License :: OSI Approved :: BSD License"],
        license_files={"LICENSE.txt": numpy_license_text},
    )
    # Write a RECORD with .libs and Windows Scripts/ entries
    (np_dist / "RECORD").write_text(
        "../../Scripts/f2py.exe,sha256=111,1024\n"
        "Scripts/numpy-config.exe,sha256=222,1024\n"
        "numpy/__init__.py,sha256=333,512\n"
        "numpy/_core/_multiarray_umath.cp312-win_amd64.pyd,sha256=444,2048\n"
        "numpy.libs/.load-order-numpy-2.1.3,sha256=555,64\n"
        "numpy.libs/libscipy_openblas64_-ff651d7f.dll,sha256=666,4096\n",
        encoding="utf-8",
    )

    sp_dist = create_dist_info(
        sp,
        "scipy",
        "1.14.1",
        license_str="BSD-3-Clause",
        requires_dist=["numpy>=1.23.5"],
        license_files={
            "LICENSES_bundled.txt": scipy_bundled_licenses,
            "LICENSE.txt": scipy_primary_license,
        },
    )
    # Create a large RECORD (>300 KB) to verify it is not truncated before reading all modules
    large_record_lines = [
        f"scipy/ submod_{i}/file_{i}.py,sha256=aaa,100" for i in range(6000)
    ]
    large_record_lines.append("scipy/linalg/cython_blas.cp312-win_amd64.pyd,sha256=bbb,2048")
    large_record_lines.append("scipy.libs/libscipy_openblas64_-ff651d7f.dll,sha256=ccc,4096")
    (sp_dist / "RECORD").write_text("\n".join(large_record_lines) + "\n", encoding="utf-8")

    ws = inspect_workspace(tmp_path)
    assert "numpy" in ws.components
    assert "scipy" in ws.components

    np_comp = ws.components["numpy"]
    sp_comp = ws.components["scipy"]

    assert np_comp.license_info.spdx_id == "BSD-3-Clause"
    assert np_comp.license_info.risk_category == LicenseRiskCategory.PERMISSIVE
    assert np_comp.top_level_modules == ["numpy"]
    assert "numpy.libs" not in np_comp.top_level_modules
    assert "Scripts" not in np_comp.top_level_modules

    assert sp_comp.license_info.spdx_id == "BSD-3-Clause"
    assert sp_comp.license_info.risk_category == LicenseRiskCategory.PERMISSIVE
    assert sp_comp.top_level_modules == ["scipy"]
    assert "scipy.libs" not in sp_comp.top_level_modules


def test_scipy_cython_extension_with_many_exports_and_auditwheel_libs(tmp_path: Path) -> None:
    """
    Verify that:
    1. A Cython extension (e.g. cython_blas) exporting >150 Fortran/BLAS wrapper symbols
       still retains `PyInit_cython_blas` at the front of `exported_symbols_sample`.
    2. Stripped Cython `.so` files inside package subdirectories (`scipy/linalg/cython_blas.so`)
       are classified as Python extensions belonging to `scipy`, NOT third-party native libraries.
    3. Multi-hash auditwheel libraries in `scipy.libs/` (`libscipy_openblas64_`, `libgfortran`,
       `libquadmath`) are identified with their canonical names, versions, and SPDX licences.
    """
    many_symbols = [f"srotmg_wrapper_{i}" for i in range(200)] + ["PyInit_cython_blas"]
    elf_bytes = build_synthetic_elf64(
        is_executable=False,
        soname="cython_blas.cpython-312-x86_64-linux-gnu.so",
        needed_libs=["libscipy_openblas64_-ff651d7f.so", "libc.so.6"],
        exported_symbols=many_symbols,
    )
    info = parse_elf_bytes(elf_bytes, "scipy/linalg/cython_blas.cpython-312-x86_64-linux-gnu.so")
    assert "PyInit_cython_blas" in info.exported_symbols_sample
    assert elf_to_native_component(info) is None

    # Also test PE .pyd with >200 symbols
    pe_bytes = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="cython_blas.cp312-win_amd64.pyd",
        needed_libs=["libscipy_openblas64_-ff651d7f.dll", "python312.dll", "KERNEL32.dll"],
        exported_symbols=many_symbols,
    )
    pe_info = parse_pe_bytes(pe_bytes, "scipy/linalg/cython_blas.cp312-win_amd64.pyd")
    assert "PyInit_cython_blas" in pe_info.exported_symbols_sample
    assert elf_to_native_component(pe_info) is None

    # Create a standalone Linux distribution directory with stripped scipy/linalg/cython_blas.so
    # and scipy.libs/ containing multi-hash auditwheel shared libraries
    dist_dir = tmp_path / "solver.dist"
    (dist_dir / "scipy" / "linalg").mkdir(parents=True)
    (dist_dir / "scipy.libs").mkdir(parents=True)

    stripped_cython_so = build_synthetic_elf64(
        is_executable=False,
        needed_libs=[
            "libscipy_openblas64_-ff651d7f.so",
            "libgfortran-040039e1-0352e75f.so.5.0.0",
            "libc.so.6",
        ],
        exported_symbols=[],  # stripped!
    )
    (dist_dir / "scipy" / "linalg" / "cython_blas.so").write_bytes(stripped_cython_so)

    openblas_so = build_synthetic_elf64(
        is_executable=False,
        soname="libscipy_openblas64_-ff651d7f.so",
        needed_libs=["libgfortran-040039e1-0352e75f.so.5.0.0", "libc.so.6"],
        rodata_strings=["OpenBLAS 0.3.27"],
    )
    (dist_dir / "scipy.libs" / "libscipy_openblas64_-ff651d7f.so").write_bytes(openblas_so)

    gfortran_so = build_synthetic_elf64(
        is_executable=False,
        soname="libgfortran-040039e1-0352e75f.so.5.0.0",
        needed_libs=["libquadmath-96973f99-934c22de.so.0.0.0", "libc.so.6"],
        rodata_strings=["GCC: (GNU) 13.2.0"],
    )
    (dist_dir / "scipy.libs" / "libgfortran-040039e1-0352e75f.so.5.0.0").write_bytes(gfortran_so)

    quadmath_so = build_synthetic_elf64(
        is_executable=False,
        soname="libquadmath-96973f99-934c22de.so.0.0.0",
        needed_libs=["libc.so.6"],
    )
    (dist_dir / "scipy.libs" / "libquadmath-96973f99-934c22de.so.0.0.0").write_bytes(quadmath_so)

    res = inspect_compiled_distribution(dist_dir)
    assert "scipy" in res.bundled_modules
    assert res.linkage_report.is_self_contained is True

    nat_by_name = {c.name: c for c in res.native_components}
    assert "cython_blas" not in nat_by_name
    assert "openblas" in nat_by_name
    assert nat_by_name["openblas"].version == "0.3.27"
    assert nat_by_name["openblas"].license_info.spdx_id == "BSD-3-Clause"
    assert nat_by_name["openblas"].license_info.risk_category == LicenseRiskCategory.PERMISSIVE

    assert "libgfortran" in nat_by_name
    assert nat_by_name["libgfortran"].version == "13.2.0"
    assert nat_by_name["libgfortran"].license_info.spdx_id == "GPL-3.0-with-GCC-exception"
    assert nat_by_name["libgfortran"].license_info.risk_category == LicenseRiskCategory.PERMISSIVE

    assert "libquadmath" in nat_by_name
    assert nat_by_name["libquadmath"].license_info.spdx_id == "LGPL-2.1-or-later"
    assert nat_by_name["libquadmath"].license_info.risk_category == LicenseRiskCategory.WEAK_COPYLEFT
    assert nat_by_name["libquadmath"].has_dynamic_relinking is True


def test_windows_pyinstaller_standalone_and_onefile_with_delvewheel_numpy_scipy(tmp_path: Path) -> None:
    """
    End-to-end audit of a Windows project using NumPy and SciPy compiled with:
    1. PyInstaller standalone directory (`_internal/` with `.exe`, `.pyd`, `numpy.libs/.load-order-*`, `.dll`)
    2. PyInstaller monolithic onefile `.exe` (embedded CArchive TOC with `.pyd` and `.dll`)
    """
    ws_dir = tmp_path / "win_sci_ws"
    ws_dir.mkdir()
    (ws_dir / "pyproject.toml").write_text(
        """
[project]
name = "win-matrix-app"
version = "2.0.0"
dependencies = ["numpy>=2.1.0", "scipy>=1.14.0"]

[dependency-groups]
dev = ["pytest>=8.0.0", "pyinstaller>=6.0.0", "delvewheel>=1.8.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    sp = ws_dir / ".venv" / "Lib" / "site-packages"
    create_dist_info(sp, "numpy", "2.1.3", license_str="BSD-3-Clause", top_level=["numpy"])
    create_dist_info(sp, "scipy", "1.14.1", license_str="BSD-3-Clause", top_level=["scipy"])
    create_dist_info(sp, "pytest", "8.3.0", license_str="MIT", top_level=["pytest"])
    create_dist_info(sp, "pyinstaller", "6.10.0", license_str="GPL-2.0-or-later", top_level=["PyInstaller"])
    create_dist_info(sp, "delvewheel", "1.8.2", license_str="MIT", top_level=["delvewheel"])

    # --- 1. PyInstaller Standalone Directory on Windows ---
    standalone_dir = tmp_path / "dist" / "win-matrix-app"
    internal = standalone_dir / "_internal"
    (internal / "numpy" / "_core").mkdir(parents=True)
    (internal / "scipy" / "linalg").mkdir(parents=True)
    (internal / "numpy.libs").mkdir(parents=True)
    (internal / "scipy.libs").mkdir(parents=True)

    (internal / "base_library.zip").write_bytes(b"PK\x05\x06" + b"\x00" * 18)
    (internal / "numpy.libs" / ".load-order-numpy-2.1.3").write_text(
        "libscipy_openblas64_-ff651d7f.dll\n",
        encoding="utf-8",
    )
    (internal / "scipy.libs" / ".load-order-scipy-1.14.1").write_text(
        "libscipy_openblas64_-ff651d7f.dll\nlibgfortran-5.dll\nlibquadmath-0.dll\n",
        encoding="utf-8",
    )

    main_exe = build_synthetic_pe64(
        is_executable=True,
        needed_libs=["python312.dll", "KERNEL32.dll", "ADVAPI32.dll", "VCRUNTIME140.dll"],
        rodata_strings=["MEIPASS2", "pyi-runtime-tmpdir"],
    )
    (standalone_dir / "win-matrix-app.exe").write_bytes(main_exe)

    py_dll = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="python312.dll",
        needed_libs=["KERNEL32.dll", "VCRUNTIME140.dll"],
        rodata_strings=["3.12.6"],
    )
    (internal / "python312.dll").write_bytes(py_dll)

    umath_pyd = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="_multiarray_umath.cp312-win_amd64.pyd",
        needed_libs=["python312.dll", "libscipy_openblas64_-ff651d7f.dll", "KERNEL32.dll"],
        exported_symbols=["PyInit__multiarray_umath"],
    )
    (internal / "numpy" / "_core" / "_multiarray_umath.cp312-win_amd64.pyd").write_bytes(umath_pyd)

    fblas_pyd = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="_fblas.cp312-win_amd64.pyd",
        needed_libs=[
            "python312.dll",
            "libscipy_openblas64_-ff651d7f.dll",
            "libgfortran-5.dll",
            "KERNEL32.dll",
        ],
        exported_symbols=["PyInit__fblas"],
    )
    (internal / "scipy" / "linalg" / "_fblas.cp312-win_amd64.pyd").write_bytes(fblas_pyd)

    openblas_dll = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="libscipy_openblas64_-ff651d7f.dll",
        needed_libs=["KERNEL32.dll", "msvcrt.dll"],
        rodata_strings=["OpenBLAS 0.3.27"],
    )
    (internal / "numpy.libs" / "libscipy_openblas64_-ff651d7f.dll").write_bytes(openblas_dll)

    gfortran_dll = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="libgfortran-5.dll",
        needed_libs=["libquadmath-0.dll", "libwinpthread-1.dll", "KERNEL32.dll"],
        rodata_strings=["GCC: (MinGW-W64) 13.2.0"],
    )
    (internal / "scipy.libs" / "libgfortran-5.dll").write_bytes(gfortran_dll)

    quadmath_dll = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="libquadmath-0.dll",
        needed_libs=["KERNEL32.dll", "msvcrt.dll"],
    )
    (internal / "scipy.libs" / "libquadmath-0.dll").write_bytes(quadmath_dll)

    winpthread_dll = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="libwinpthread-1.dll",
        needed_libs=["KERNEL32.dll", "msvcrt.dll"],
    )
    (internal / "scipy.libs" / "libwinpthread-1.dll").write_bytes(winpthread_dll)

    cfg_standalone = AuditConfig(
        project_path=ws_dir,
        dist_path=standalone_dir,
        offline=True,
        fail_on_license=Severity.HIGH,
        fail_on_linkage=True,
    )
    rep_standalone = run_audit(cfg_standalone)
    assert rep_standalone.mode == AuditMode.COMPILED_DIST
    assert rep_standalone.bundler_type == BundlerType.PYINSTALLER
    assert rep_standalone.layout == DistributionLayout.STANDALONE_DIR
    assert rep_standalone.linkage_report is not None
    assert rep_standalone.linkage_report.is_self_contained is True
    # In standalone directory mode, LGPL libquadmath is dynamically linked as a separate DLL,
    # so compliance emits LIC-LGPL-DYNAMIC (MEDIUM) and passes with ExitCode.OK (0)!
    assert any(
        f.rule_id == "LIC-LGPL-DYNAMIC" and f.component_name == "libquadmath"
        for f in rep_standalone.compliance_findings
    )
    assert rep_standalone.exit_code == ExitCode.OK

    bundled_names = {c.name: c for c in rep_standalone.components}
    excluded_names = {c.name for c in rep_standalone.excluded_components}
    assert "numpy" in bundled_names
    assert "scipy" in bundled_names
    assert "openblas" in bundled_names
    assert "libgfortran" in bundled_names
    assert "libquadmath" in bundled_names
    assert "winpthreads" in bundled_names
    assert "python" in bundled_names
    assert "pytest" in excluded_names
    assert "pyinstaller" in excluded_names
    assert "delvewheel" in excluded_names

    # --- 2. PyInstaller Onefile Monolithic .exe on Windows ---
    carchive = build_pyinstaller_carchive_payload(
        [
            ("b", "python312.dll"),
            ("b", "VCRUNTIME140.dll"),
            ("b", "numpy\\_core\\_multiarray_umath.cp312-win_amd64.pyd"),
            ("b", "scipy\\linalg\\_fblas.cp312-win_amd64.pyd"),
            ("x", "numpy.libs\\.load-order-numpy-2.1.3"),
            ("b", "numpy.libs\\libscipy_openblas64_-ff651d7f.dll"),
            ("b", "scipy.libs\\libgfortran-5.dll"),
            ("b", "scipy.libs\\libquadmath-0.dll"),
        ]
    )
    onefile_exe = build_synthetic_pe64(
        is_executable=True,
        needed_libs=["KERNEL32.dll", "USER32.dll", "ADVAPI32.dll"],
        rodata_strings=["pyi-runtime-tmpdir", "OpenBLAS 0.3.27"],
        trailing_payload=carchive,
    )
    onefile_path = tmp_path / "win-matrix-onefile.exe"
    onefile_path.write_bytes(onefile_exe)

    cfg_onefile = AuditConfig(
        project_path=ws_dir,
        dist_path=onefile_path,
        offline=True,
        fail_on_license=Severity.HIGH,
    )
    rep_onefile = run_audit(cfg_onefile)
    assert rep_onefile.bundler_type == BundlerType.PYINSTALLER
    assert rep_onefile.layout == DistributionLayout.MONOLITHIC_BINARY
    onefile_names = {c.name for c in rep_onefile.components}
    assert "numpy" in onefile_names
    assert "scipy" in onefile_names
    assert "openblas" in onefile_names
    assert "libgfortran" in onefile_names
    assert "libquadmath" in onefile_names
    # VCRUNTIME140.dll must not be reported as an unknown third-party library
    assert "vcruntime140" not in onefile_names
    # Because libquadmath is LGPL-2.1-or-later and embedded inside a monolithic onefile .exe,
    # it triggers LIC-LGPL-MONOLITHIC (HIGH severity) -> ExitCode.LICENSE_VIOLATION
    assert any(
        f.rule_id == "LIC-LGPL-MONOLITHIC" and f.component_name == "libquadmath"
        for f in rep_onefile.compliance_findings
    )
    assert rep_onefile.exit_code == ExitCode.LICENSE_FAILURE


def test_windows_nuitka_onefile_pe_and_cli_inspect_binary(tmp_path: Path) -> None:
    nuitka_exe = build_synthetic_pe64(
        is_executable=True,
        needed_libs=["KERNEL32.dll", "WS2_32.dll", "missing_dll_dep.dll"],
        exported_symbols=["_modulecode_numpy", "_modulecode_scipy$$linalg"],
        rodata_strings=["NUITKA_ONEFILE_PARENT", "__nuitka_version__"],
    )
    exe_path = tmp_path / "nuitka_sci.exe"
    exe_path.write_bytes(nuitka_exe)

    res = inspect_compiled_distribution(exe_path)
    assert res.bundler_type == BundlerType.NUITKA
    assert res.layout == DistributionLayout.MONOLITHIC_BINARY
    assert "numpy" in res.bundled_modules
    assert "scipy" in res.bundled_modules
    assert res.linkage_report.unresolved_dependencies == ["missing_dll_dep.dll"]
    # External missing DLL in the executable's PE Import Table must NOT be registered as an embedded library
    assert not any(c.name == "missing_dll_dep" for c in res.native_components)

    # Verify CLI inspect-elf and inspect-binary commands work on Windows PE files
    runner = CliRunner()
    cli_res1 = runner.invoke(cli, ["inspect-elf", str(exe_path)])
    assert cli_res1.exit_code == 0
    payload1 = json.loads(cli_res1.stdout)
    assert payload1["unresolved_dependencies"] == ["missing_dll_dep.dll"]

    cli_res2 = runner.invoke(cli, ["inspect-binary", str(exe_path)])
    assert cli_res2.exit_code == 0
    payload2 = json.loads(cli_res2.stdout)
    assert payload2["elf_binaries"][0]["binary_format"] == "PE"


def test_corrupted_pe_inputs_and_real_windows_system_dll(tmp_path: Path) -> None:
    bad_pe = tmp_path / "bad.dll"
    bad_pe.write_bytes(b"MZ" + b"\x00" * 100)
    assert is_pe_file(bad_pe) is False
    with pytest.raises(ValueError, match="Not a valid PE binary"):
        parse_pe_bytes(b"MZ" + b"\x00" * 100)

    if sys.platform == "win32":
        kernel32 = Path(r"C:\Windows\System32\kernel32.dll")
        if kernel32.is_file():
            assert is_pe_file(kernel32) is True
            k_info = parse_pe_binary(kernel32)
            assert k_info.binary_format == "PE"
            assert k_info.bits in (32, 64)
            assert k_info.is_shared_object is True
            assert len(k_info.exported_symbols_sample) > 0
            assert elf_to_native_component(k_info) is None


def test_intel_mkl_library_detection_version_and_issl_classification(tmp_path: Path) -> None:
    """
    Verify Intel MKL library detection, dotted version extraction (mkl_rt.2.dll),
    proprietary ISSL classification, and linkage resolution.
    """
    mkl_pe = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="mkl_rt.2.dll",
        rodata_strings=[
            "Intel(R) oneAPI Math Kernel Library Version 2024.1.0 Package ID 2024.1.0-build.123",
            "mkl_blas_caxpy",
        ],
    )
    dll_path = tmp_path / "mkl_rt.2.dll"
    dll_path.write_bytes(mkl_pe)

    assert is_pe_file(dll_path) is True
    info = parse_pe_binary(dll_path)
    assert info.detected_library_name == "mkl"
    assert info.detected_version == "2024.1.0"

    comp = elf_to_native_component(info, is_monolithic=False)
    assert comp is not None
    assert comp.name == "mkl"
    assert comp.version == "2024.1.0"
    assert comp.license_info.spdx_id == "LicenseRef-Intel-Simplified-Software-License"
    assert comp.license_info.risk_category == LicenseRiskCategory.PROPRIETARY

    # Verify PE linkage resolves mkl_rt.2.dll when an executable imports it
    exe_pe = build_synthetic_pe64(
        is_executable=True,
        needed_libs=["mkl_rt.2.dll", "KERNEL32.dll"],
    )
    exe_path = tmp_path / "app.exe"
    exe_path.write_bytes(exe_pe)

    b_exe = parse_binary(exe_path)
    b_mkl = parse_binary(dll_path)
    report = verify_binary_linkage([b_exe, b_mkl], dist_root=tmp_path)
    assert report.is_self_contained is True
    assert "mkl_rt.2.dll" in report.resolved_dependencies
    assert report.linkage_issues[0].status == LinkageStatus.BUNDLED

    # Also verify Linux ELF MKL identification
    mkl_elf = build_synthetic_elf64(
        is_executable=False,
        soname="libmkl_rt.so.2",
        rodata_strings=["Intel(R) Math Kernel Library Version 2020.0.4"],
    )
    so_path = tmp_path / "libmkl_rt.so.2"
    so_path.write_bytes(mkl_elf)

    info_elf = parse_binary(so_path)
    assert info_elf.detected_library_name == "mkl"
    assert info_elf.detected_version == "2020.0.4"
    comp_elf = elf_to_native_component(info_elf, is_monolithic=False)
    assert comp_elf is not None
    assert comp_elf.name == "mkl"
    assert comp_elf.license_info.spdx_id == "LicenseRef-Intel-Simplified-Software-License"


def test_submodule_and_extension_correlation_without_dummy_components(tmp_path: Path) -> None:
    """
    Verify that distributions with submodules (numpy.linalg, scipy.special, scipy.sparse)
    and native extension modules (_multiarray_umath, cython_blas, _fblas, lapack_lite)
    correlate cleanly to parent packages without producing spurious dummy components.
    """
    ws_dir = tmp_path / "workspace"
    ws_dir.mkdir()
    (ws_dir / "pyproject.toml").write_text(
        """
[project]
name = "math-engine"
version = "1.0.0"
dependencies = ["numpy>=2.0.0", "scipy>=1.14.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    sp = ws_dir / ".venv" / "Lib" / "site-packages"
    np_dist = create_dist_info(sp, "numpy", "2.1.3", license_str="BSD-3-Clause", top_level=["numpy"])
    (np_dist / "RECORD").write_text(
        "numpy/__init__.py,sha256=111,100\n"
        "numpy/_core/_multiarray_umath.cp312-win_amd64.pyd,sha256=222,2048\n"
        "numpy/linalg/lapack_lite.cp312-win_amd64.pyd,sha256=333,2048\n",
        encoding="utf-8",
    )

    sc_dist = create_dist_info(sp, "scipy", "1.14.1", license_str="BSD-3-Clause", top_level=["scipy"])
    (sc_dist / "RECORD").write_text(
        "scipy/__init__.py,sha256=444,100\n"
        "scipy/special/_ellip_harm_2.cp312-win_amd64.pyd,sha256=555,2048\n"
        "scipy/linalg/cython_blas.cp312-win_amd64.pyd,sha256=666,2048\n"
        "scipy/linalg/_fblas.cp312-win_amd64.pyd,sha256=777,2048\n",
        encoding="utf-8",
    )

    ws = inspect_workspace(ws_dir)
    assert "numpy" in ws.components
    assert "scipy" in ws.components

    # Verify workspace module_to_package mapped known submodules and extensions
    assert ws.module_to_package.get("numpy.linalg") == "numpy"
    assert ws.module_to_package.get("_multiarray_umath") == "numpy"
    assert ws.module_to_package.get("scipy.special") == "scipy"
    assert ws.module_to_package.get("scipy.sparse") == "scipy"
    assert ws.module_to_package.get("cython_blas") == "scipy"
    assert ws.module_to_package.get("_fblas") == "scipy"

    # Create standalone distribution directory containing native extensions
    dist_dir = tmp_path / "standalone_app.dist"
    (dist_dir / "numpy" / "_core").mkdir(parents=True)
    (dist_dir / "numpy" / "linalg").mkdir(parents=True)
    (dist_dir / "scipy" / "special").mkdir(parents=True)
    (dist_dir / "scipy" / "linalg").mkdir(parents=True)

    umath_pyd = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="_multiarray_umath.cp312-win_amd64.pyd",
        needed_libs=["KERNEL32.dll"],
        exported_symbols=["PyInit__multiarray_umath"],
    )
    (dist_dir / "numpy" / "_core" / "_multiarray_umath.cp312-win_amd64.pyd").write_bytes(umath_pyd)

    lapack_pyd = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="lapack_lite.cp312-win_amd64.pyd",
        needed_libs=["KERNEL32.dll"],
        exported_symbols=["PyInit_lapack_lite"],
    )
    (dist_dir / "numpy" / "linalg" / "lapack_lite.cp312-win_amd64.pyd").write_bytes(lapack_pyd)

    ellip_pyd = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="_ellip_harm_2.cp312-win_amd64.pyd",
        needed_libs=["KERNEL32.dll"],
        exported_symbols=["PyInit__ellip_harm_2"],
    )
    (dist_dir / "scipy" / "special" / "_ellip_harm_2.cp312-win_amd64.pyd").write_bytes(ellip_pyd)

    fblas_pyd = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="_fblas.cp312-win_amd64.pyd",
        needed_libs=["KERNEL32.dll"],
        exported_symbols=["PyInit__fblas"],
    )
    (dist_dir / "scipy" / "linalg" / "_fblas.cp312-win_amd64.pyd").write_bytes(fblas_pyd)

    res = inspect_compiled_distribution(dist_dir)
    active, _excluded = correlate_workspace_and_dist(ws, res)

    active_names = {c.name for c in active}
    assert active_names == {"numpy", "scipy"}
    assert not any(
        name in active_names
        for name in (
            "multiarray-umath",
            "_multiarray_umath",
            "lapack-lite",
            "ellip-harm-2",
            "_ellip_harm_2",
            "fblas",
            "_fblas",
            "linalg",
            "special",
        )
    )

    # Verify that bundled_files captures the extensions for each component
    np_comp = next(c for c in active if c.name == "numpy")
    sc_comp = next(c for c in active if c.name == "scipy")
    assert any("_multiarray_umath" in bf for bf in np_comp.bundled_files)
    assert any("lapack_lite" in bf for bf in np_comp.bundled_files)
    assert any("_ellip_harm_2" in bf for bf in sc_comp.bundled_files)
    assert any("_fblas" in bf for bf in sc_comp.bundled_files)


def test_nested_licenses_and_attribution_extraction_to_third_party_notices(tmp_path: Path) -> None:
    """
    Verify that nested licence files in .dist-info/licenses/ (e.g. bundled OpenBLAS, MKL)
    and notice/attribution files are extracted from compiled distributions and correctly
    assembled into THIRD_PARTY_NOTICES.
    """
    ws_dir = tmp_path / "ws_notices"
    ws_dir.mkdir()
    (ws_dir / "pyproject.toml").write_text(
        """
[project]
name = "solver-app"
version = "1.0.0"
dependencies = ["numpy>=2.0.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )

    # Simulate uv.lock where numpy is declared without local .dist-info in workspace
    (ws_dir / "uv.lock").write_text(
        """
version = 1
requires-python = ">=3.12"

[[package]]
name = "solver-app"
version = "1.0.0"
dependencies = [{ name = "numpy" }]

[[package]]
name = "numpy"
version = "2.1.3"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    ws = inspect_workspace(ws_dir)
    assert "numpy" in ws.components
    assert len(ws.components["numpy"].license_info.license_texts) == 0

    # Build standalone compiled distribution that bundles numpy's .dist-info with nested licenses
    dist_dir = tmp_path / "dist_notices"
    dist_info = dist_dir / "numpy-2.1.3.dist-info"
    dist_info.mkdir(parents=True)
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: numpy\nVersion: 2.1.3\nLicense: BSD-3-Clause\n",
        encoding="utf-8",
    )

    licenses_dir = dist_info / "licenses"
    bundled_dir = licenses_dir / "bundled_licenses"
    bundled_dir.mkdir(parents=True)

    numpy_lic = "NumPy primary BSD-3-Clause licence text.\nCopyright (c) NumPy Developers."
    openblas_lic = "OpenBLAS BSD-3-Clause licence text.\nCopyright (c) OpenBLAS Developers."
    mkl_lic = "Intel Simplified Software License.\nCopyright (c) Intel Corporation."
    attribution_txt = "NumPy Attribution and Credits.\nThanks to all contributors."

    (licenses_dir / "LICENSE.txt").write_text(numpy_lic, encoding="utf-8")
    (bundled_dir / "OpenBLAS.txt").write_text(openblas_lic, encoding="utf-8")
    (bundled_dir / "MKL.txt").write_text(mkl_lic, encoding="utf-8")
    (dist_info / "ATTRIBUTION.txt").write_text(attribution_txt, encoding="utf-8")

    # Add dummy numpy compiled file
    (dist_dir / "numpy").mkdir(parents=True)
    (dist_dir / "numpy" / "__init__.py").write_text("# numpy root\n", encoding="utf-8")

    res = inspect_compiled_distribution(dist_dir)
    assert "numpy" in res.discovered_distributions
    assert "numpy" in res.dist_info_components

    active, _excluded = correlate_workspace_and_dist(ws, res)
    assert len(active) == 1
    np_comp = active[0]
    assert np_comp.name == "numpy"

    # Verify that license texts and notice texts were merged from bundled dist-info
    lic_texts = np_comp.license_info.license_texts
    notice_texts = np_comp.license_info.notice_texts

    assert "licenses/LICENSE.txt" in lic_texts
    assert lic_texts["licenses/LICENSE.txt"] == numpy_lic
    assert "licenses/bundled_licenses/OpenBLAS.txt" in lic_texts
    assert lic_texts["licenses/bundled_licenses/OpenBLAS.txt"] == openblas_lic
    assert "licenses/bundled_licenses/MKL.txt" in lic_texts
    assert lic_texts["licenses/bundled_licenses/MKL.txt"] == mkl_lic
    assert "ATTRIBUTION.txt" in notice_texts
    assert notice_texts["ATTRIBUTION.txt"] == attribution_txt

    # Generate third-party notices report
    report = AuditReport(
        target_name="solver-app",
        target_version="1.0.0",
        mode=AuditMode.COMPILED_DIST,
        bundler_type=BundlerType.NUITKA,
        layout=DistributionLayout.STANDALONE_DIR,
        project_path=str(ws_dir),
        dist_path=str(dist_dir),
        components=active,
    )
    notices_output = generate_third_party_notices(report)

    assert "--- Begin licenses/LICENSE.txt ---" in notices_output
    assert numpy_lic in notices_output
    assert "--- End licenses/LICENSE.txt ---" in notices_output

    assert "--- Begin licenses/bundled_licenses/OpenBLAS.txt ---" in notices_output
    assert openblas_lic in notices_output
    assert "--- End licenses/bundled_licenses/OpenBLAS.txt ---" in notices_output

    assert "--- Begin licenses/bundled_licenses/MKL.txt ---" in notices_output
    assert mkl_lic in notices_output
    assert "--- End licenses/bundled_licenses/MKL.txt ---" in notices_output

    assert "--- Begin ATTRIBUTION.txt ---" in notices_output
    assert attribution_txt in notices_output
    assert "--- End ATTRIBUTION.txt ---" in notices_output


def test_pyinstaller_monolithic_submodules_and_no_typecode_pollution(tmp_path: Path) -> None:
    """
    Verify that PyInstaller monolithic Windows executables properly recognise
    NumPy and SciPy submodules from CArchive TOC entries and do not produce
    bogus typecode-prefixed dummy components like bnumpy or bscipy.
    """
    ws_dir = tmp_path / "ws_pyi_mono"
    ws_dir.mkdir()
    (ws_dir / "pyproject.toml").write_text(
        """
[project]
name = "solver-app"
version = "1.0.0"
dependencies = ["numpy>=2.0.0", "scipy>=1.14.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    sp = ws_dir / ".venv" / "Lib" / "site-packages"
    create_dist_info(sp, "numpy", "2.1.3", license_str="BSD-3-Clause")
    create_dist_info(sp, "scipy", "1.14.1", license_str="BSD-3-Clause")
    ws = inspect_workspace(ws_dir)

    toc = [
        ("m", "numpy"),
        ("m", "numpy.linalg"),
        ("m", "numpy.fft"),
        ("m", "scipy"),
        ("m", "scipy.special"),
        ("m", "scipy.sparse"),
        ("b", "numpy/_core/_multiarray_umath.cp312-win_amd64.pyd"),
        ("b", "scipy/linalg/cython_blas.cp312-win_amd64.pyd"),
        ("b", "numpy.libs/libscipy_openblas64_-ff651d7f.dll"),
        ("b", "numpy.libs/mkl_rt.2.dll"),
    ]
    payload = build_pyinstaller_carchive_payload(toc)
    pe_bytes = build_synthetic_pe64(
        is_executable=True,
        needed_libs=["KERNEL32.dll", "VCRUNTIME140.dll"],
        trailing_payload=payload,
    )
    exe_file = tmp_path / "solver.exe"
    exe_file.write_bytes(pe_bytes)

    res = inspect_compiled_distribution(exe_file)
    assert "numpy.linalg" in res.bundled_modules
    assert "numpy.fft" in res.bundled_modules
    assert "scipy.special" in res.bundled_modules
    assert "scipy.sparse" in res.bundled_modules
    assert "bnumpy" not in res.bundled_modules
    assert "bscipy" not in res.bundled_modules

    active, _excluded = correlate_workspace_and_dist(ws, res)
    active_names = {c.name for c in active}
    assert "numpy" in active_names
    assert "scipy" in active_names
    assert "openblas" in active_names
    assert "mkl" in active_names
    assert "bnumpy" not in active_names
    assert "bscipy" not in active_names


def test_standalone_submodules_and_unrecorded_c_extensions(tmp_path: Path) -> None:
    """
    Verify that standalone distributions with submodules (e.g. scipy/special.py, scipy/special/orthogonal.py)
    and unrecorded C extensions inside package directories correlate to parent packages
    without creating spurious dummy components like 'special', 'linalg', or '-my-new-special'.
    """
    ws_dir = tmp_path / "ws_standalone_submods"
    ws_dir.mkdir()
    (ws_dir / "pyproject.toml").write_text(
        """
[project]
name = "solver-app"
version = "1.0.0"
dependencies = ["numpy>=2.0.0", "scipy>=1.14.0"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    sp = ws_dir / ".venv" / "Lib" / "site-packages"
    create_dist_info(sp, "numpy", "2.1.3", license_str="BSD-3-Clause")
    create_dist_info(sp, "scipy", "1.14.1", license_str="BSD-3-Clause")
    ws = inspect_workspace(ws_dir)

    dist_dir = tmp_path / "standalone_app.dist"
    (dist_dir / "scipy" / "special").mkdir(parents=True)
    (dist_dir / "scipy" / "linalg").mkdir(parents=True)
    (dist_dir / "numpy" / "linalg").mkdir(parents=True)

    (dist_dir / "scipy" / "__init__.py").write_text("# scipy root\n", encoding="utf-8")
    (dist_dir / "scipy" / "special.py").write_text("# scipy.special\n", encoding="utf-8")
    (dist_dir / "scipy" / "linalg.py").write_text("# scipy.linalg\n", encoding="utf-8")
    (dist_dir / "scipy" / "special" / "orthogonal.py").write_text("# scipy.special.orthogonal\n", encoding="utf-8")
    (dist_dir / "numpy" / "__init__.py").write_text("# numpy root\n", encoding="utf-8")
    (dist_dir / "numpy" / "linalg.py").write_text("# numpy.linalg\n", encoding="utf-8")

    # Add custom private C-extension inside scipy/special/
    pyd_bytes = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="_my_new_special.pyd",
        needed_libs=["KERNEL32.dll"],
    )
    (dist_dir / "scipy" / "special" / "_my_new_special.cp312-win_amd64.pyd").write_bytes(pyd_bytes)

    res = inspect_compiled_distribution(dist_dir)
    assert "scipy.special" in res.bundled_modules
    assert "scipy.linalg" in res.bundled_modules
    assert "numpy.linalg" in res.bundled_modules
    assert "scipy.special.orthogonal" in res.bundled_modules

    active, _excluded = correlate_workspace_and_dist(ws, res)
    active_names = {c.name for c in active}
    assert active_names == {"numpy", "scipy"}
    assert not any(
        name in active_names
        for name in (
            "special",
            "linalg",
            "orthogonal",
            "_my_new_special",
            "-my-new-special",
            "my-new-special",
        )
    )

    sc_comp = next(c for c in active if c.name == "scipy")
    assert any("orthogonal.py" in bf for bf in sc_comp.bundled_files)
    assert any("_my_new_special" in bf for bf in sc_comp.bundled_files)


def test_dist_info_binary_license_files_and_symlinks_skipped(tmp_path: Path) -> None:
    """
    Verify that binary files (PNG images, PDFs, .DS_Store, compiled binaries) inside
    .dist-info/licenses/ are ignored and do not pollute licence text dictionaries.
    """
    sp = tmp_path / "site-packages"
    sp.mkdir()
    dist_info = create_dist_info(sp, "numpy", "2.1.3", license_str="BSD-3-Clause")

    lic_dir = dist_info / "licenses"
    lic_dir.mkdir(exist_ok=True)
    (lic_dir / "LICENSE.txt").write_text("Legitimate text licence notice.", encoding="utf-8")
    # Binary PNG file with null bytes
    (lic_dir / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01")
    # PDF file
    (lic_dir / "license.pdf").write_bytes(b"%PDF-1.4\x00\x01\x02\x03\xff\xfe")
    # Hidden system file
    (lic_dir / ".DS_Store").write_bytes(b"\x00\x00\x00\x01Bud1\x00")

    comp, _top_mods, _all_mods = _inspect_dist_info(dist_info)
    assert comp is not None
    lic_texts = comp.license_info.license_texts
    assert "licenses/LICENSE.txt" in lic_texts
    assert "licenses/logo.png" not in lic_texts
    assert "licenses/license.pdf" not in lic_texts
    assert "licenses/.DS_Store" not in lic_texts
    assert not any("\x00" in text for text in lic_texts.values())


def test_dotted_extension_module_extraction_in_record(tmp_path: Path) -> None:
    """
    Verify that RECORD files with dotted C-extensions (e.g. core.accel.cp312-win_amd64.pyd)
    and submodules extract all dotted parts without truncating at the first dot.
    """
    sp = tmp_path / "site-packages"
    sp.mkdir()
    dist_info = create_dist_info(sp, "mypkg", "1.0.0", license_str="MIT")
    (dist_info / "RECORD").write_text(
        "mypkg/__init__.py,sha256=111,100\n"
        "mypkg/subpkg/__init__.py,sha256=222,100\n"
        "mypkg/subpkg/core.accel.cp312-win_amd64.pyd,sha256=333,100\n"
        "mypkg/subpkg/helpers.py,sha256=444,100\n",
        encoding="utf-8",
    )
    comp, top_mods, all_mods = _inspect_dist_info(dist_info)
    assert comp is not None
    assert "mypkg" in top_mods
    assert "mypkg.subpkg" in all_mods
    assert "mypkg.subpkg.core.accel" in all_mods
    assert "helpers" not in top_mods
    assert "mypkg.subpkg.helpers" in all_mods


def test_windows_mkl_rt_versioned_linkage_resolution(tmp_path: Path) -> None:
    """
    Verify that a Windows executable importing mkl_rt.2.dll resolves cleanly when mkl_rt.dll
    is bundled, and vice-versa.
    """
    app_exe = build_synthetic_pe64(
        is_executable=True,
        needed_libs=["mkl_rt.2.dll", "KERNEL32.dll", "ucrtbase.dll"],
    )
    mkl_dll = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="mkl_rt.dll",
        needed_libs=["KERNEL32.dll"],
        rodata_strings=["Intel(R) Math Kernel Library Version 2024.2.0"],
    )

    exe_file = tmp_path / "app.exe"
    mkl_file = tmp_path / "mkl_rt.dll"
    exe_file.write_bytes(app_exe)
    mkl_file.write_bytes(mkl_dll)

    b_exe = parse_binary(exe_file)
    b_mkl = parse_binary(mkl_file)

    report = verify_binary_linkage([b_exe, b_mkl], dist_root=tmp_path)
    assert report.is_self_contained is True
    assert "mkl_rt.2.dll" in report.resolved_dependencies
    assert len(report.unresolved_dependencies) == 0

