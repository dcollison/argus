"""Tests for native shared library (.so, .dll) provenance and origin package tracking."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from rhada.auditor import run_audit
from rhada.cli import cli
from rhada.dist import (
    correlate_workspace_and_dist,
    inspect_compiled_distribution,
)
from rhada.elf import (
    infer_binary_provenance,
    parse_binary,
    verify_binary_linkage,
)
from rhada.models import (
    AuditConfig,
    AuditMode,
    Component,
    ComponentScope,
    ComponentType,
    ElfBinaryInfo,
    LicenseInfo,
)
from rhada.reporter import format_report_text
from rhada.sbom import generate_cyclonedx_sbom, generate_spdx_sbom
from rhada.workspace import inspect_workspace
from tests.helpers import (
    build_pyinstaller_carchive_payload,
    build_synthetic_elf64,
    build_synthetic_pe64,
    create_dist_info,
)


def test_infer_binary_provenance_patterns() -> None:
    """Verify inference across delvewheel, auditwheel, dedicated dirs, and system ABI."""
    # 1. Delvewheel load-order marker token
    pkg, prov = infer_binary_provenance("d:/app/.load-order-scipy-1.14.0", ".load-order-scipy-1.14.0")
    assert pkg == "scipy"
    assert prov == "vendored-in-wheel:scipy"

    # 2. Delvewheel Windows folder <pkg>.libs
    pkg, prov = infer_binary_provenance(
        "d:/app/_internal/numpy.libs/libopenblas64_-28852d63.dll",
        "libopenblas64_-28852d63.dll",
    )
    assert pkg == "numpy"
    assert prov == "vendored-in-wheel:numpy"

    # 3. Auditwheel Linux folder <pkg>.libs
    pkg, prov = infer_binary_provenance(
        "/usr/local/lib/python3.11/site-packages/scipy.libs/libgfortran-040039ff.so.5.0.0",
        "libgfortran-040039ff.so.5.0.0",
    )
    assert pkg == "scipy"
    assert prov == "vendored-in-wheel:scipy"

    # 4. Package internal .libs directory (e.g. opencv / cv2)
    pkg, prov = infer_binary_provenance(
        "/opt/venv/lib/python3.11/site-packages/cv2/.libs/libopencv_core.so.4.10.0",
        "libopencv_core.so.4.10.0",
    )
    assert pkg == "cv2"
    assert prov == "vendored-in-wheel:cv2"

    # 5. Package extra-dll directory
    pkg, prov = infer_binary_provenance(
        "d:/venv/Lib/site-packages/scipy/extra-dll/libquadmath-0.dll",
        "libquadmath-0.dll",
    )
    assert pkg == "scipy"
    assert prov == "vendored-in-wheel:scipy"

    # 6. Monolithic PyInstaller TOC virtual path (with ! separator)
    pkg, prov = infer_binary_provenance(
        "/dist/my_app!numpy.libs/libopenblas.so",
        "libopenblas.so",
    )
    assert pkg == "numpy"
    assert prov == "vendored-in-wheel:numpy"

    # 7. System ABI and compiler runtimes
    pkg, prov = infer_binary_provenance("/lib64/libc.so.6", "libc.so.6")
    assert pkg is None
    assert prov == "system-abi:linux"

    pkg, prov = infer_binary_provenance("C:/Windows/System32/KERNEL32.dll", "KERNEL32.dll")
    assert pkg is None
    assert prov == "system-abi:windows"

    pkg, prov = infer_binary_provenance("d:/dist/vcruntime140.dll", "vcruntime140.dll")
    assert pkg is None
    assert prov == "system-abi:windows"


def test_source_workspace_numpy_scipy_libs_and_record(tmp_path: Path) -> None:
    """Verify source workspace inspection discovers vendored native libraries via RECORD and <pkg>.libs."""
    sp_dir = tmp_path / ".venv" / "Lib" / "site-packages"
    sp_dir.mkdir(parents=True)

    # Create pyproject.toml
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "science-app"\nversion = "0.1.0"\ndependencies = ["numpy>=2.0.0", "scipy>=1.14.0"]\n',
        encoding="utf-8",
    )

    # 1. NumPy dist-info and numpy.libs directory
    numpy_dist = create_dist_info(
        sp_dir,
        "numpy",
        "2.0.0",
        license_expression="BSD-3-Clause",
        top_level=["numpy"],
    )
    numpy_libs = sp_dir / "numpy.libs"
    numpy_libs.mkdir()
    openblas_bytes = build_synthetic_elf64(
        is_executable=False,
        soname="libopenblas64_-28852d63.so",
        needed_libs=["libm.so.6", "libc.so.6"],
        rodata_strings=["OpenBLAS 0.3.27"],
    )
    openblas_file = numpy_libs / "libopenblas64_-28852d63.so"
    openblas_file.write_bytes(openblas_bytes)

    # RECORD file in numpy-2.0.0.dist-info
    c_ext_file = sp_dir / "numpy" / "_core" / "_multiarray_umath.cpython-312-x86_64-linux-gnu.so"
    c_ext_file.parent.mkdir(parents=True)
    c_ext_file.write_bytes(build_synthetic_elf64(is_executable=False, soname="_multiarray_umath.so"))

    record_content = (
        f"numpy.libs/libopenblas64_-28852d63.so,sha256=xxx,{len(openblas_bytes)}\n"
        "numpy/_core/_multiarray_umath.cpython-312-x86_64-linux-gnu.so,sha256=yyy,1000\n"
        "numpy/__init__.py,sha256=zzz,100\n"
    )
    (numpy_dist / "RECORD").write_text(record_content, encoding="utf-8")

    # 2. SciPy dist-info with delvewheel load-order and DLLs
    create_dist_info(
        sp_dir,
        "scipy",
        "1.14.0",
        license_expression="BSD-3-Clause",
        top_level=["scipy"],
    )
    scipy_libs = sp_dir / "scipy.libs"
    scipy_libs.mkdir()
    (scipy_libs / ".load-order-scipy-1.14.0").write_text("libgfortran-5.dll\n", encoding="utf-8")
    gfortran_bytes = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="libgfortran-5.dll",
        needed_libs=["KERNEL32.dll"],
        rodata_strings=["GNU Fortran 14.1.0"],
    )
    (scipy_libs / "libgfortran-5.dll").write_bytes(gfortran_bytes)

    ws = inspect_workspace(tmp_path)

    # Check numpy and scipy are present
    assert "numpy" in ws.components
    assert "scipy" in ws.components

    # Check package_libraries mapping
    assert "numpy" in ws.package_libraries
    assert "scipy" in ws.package_libraries
    assert any("openblas" in lib.lower() for lib in ws.package_libraries["numpy"])
    assert any("gfortran" in lib.lower() for lib in ws.package_libraries["scipy"])

    # Check native components
    nat_comps = {c.name: c for c in ws.native_components}
    assert any("openblas" in name.lower() for name in nat_comps)
    blas_comp = next(c for c in ws.native_components if "openblas" in c.name.lower())
    assert blas_comp.origin_package == "numpy"
    assert blas_comp.provenance == "vendored-in-wheel:numpy"
    assert blas_comp.architecture == "x86_64"
    assert blas_comp.component_type == ComponentType.NATIVE_LIBRARY

    fortran_comp = next(c for c in ws.native_components if "gfortran" in c.name.lower())
    assert fortran_comp.origin_package == "scipy"
    assert fortran_comp.provenance == "vendored-in-wheel:scipy"

    # Ensure C extension module was not registered as a separate native library
    assert "_multiarray_umath" not in nat_comps
    assert "multiarray_umath" not in nat_comps

    # Check elf_binaries
    assert len(ws.elf_binaries) >= 2
    blas_binfo = next(b for b in ws.elf_binaries if "openblas" in b.path.lower())
    assert blas_binfo.origin_package == "numpy"
    assert blas_binfo.provenance == "vendored-in-wheel:numpy"


def test_compiled_dist_standalone_dir_provenance(tmp_path: Path) -> None:
    """Verify standalone distribution inspection tracks origins for .libs, .so, and .dll."""
    dist_dir = tmp_path / "myapp.dist"
    dist_dir.mkdir()

    # Main binary
    main_pe = build_synthetic_pe64(
        is_executable=True,
        needed_libs=["python311.dll", "libopenblas.dll", "KERNEL32.dll"],
        exported_symbols=["main"],
    )
    (dist_dir / "myapp.exe").write_bytes(main_pe)

    # NumPy libs subfolder
    np_libs = dist_dir / "numpy.libs"
    np_libs.mkdir()
    blas_pe = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="libopenblas.dll",
        needed_libs=["KERNEL32.dll"],
        rodata_strings=["OpenBLAS 0.3.26"],
    )
    (np_libs / "libopenblas.dll").write_bytes(blas_pe)

    # Pillow libs subfolder
    pil_libs = dist_dir / "pillow.libs"
    pil_libs.mkdir()
    png_pe = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="libpng16.dll",
        needed_libs=["KERNEL32.dll"],
        rodata_strings=["libpng version 1.6.43"],
    )
    (pil_libs / "libpng16.dll").write_bytes(png_pe)

    res = inspect_compiled_distribution(dist_dir)
    assert len(res.native_components) >= 2

    comp_map = {c.name: c for c in res.native_components}
    assert "openblas" in comp_map
    assert comp_map["openblas"].origin_package == "numpy"
    assert comp_map["openblas"].provenance == "vendored-in-wheel:numpy"

    assert "libpng" in comp_map
    assert comp_map["libpng"].origin_package == "pillow"
    assert comp_map["libpng"].provenance == "vendored-in-wheel:pillow"

    # Linkage report
    lr = res.linkage_report
    assert lr is not None
    assert any(orig == "numpy" for orig in lr.binary_origins.values())
    assert any(orig == "pillow" for orig in lr.binary_origins.values())
    assert "numpy" in lr.package_libraries
    assert "pillow" in lr.package_libraries


def test_compiled_dist_monolithic_onefile_provenance(tmp_path: Path) -> None:
    """Verify PyInstaller monolithic onefile inspection extracts native origins from TOC paths."""
    toc = [
        ("m", "numpy/__init__.pyc"),
        ("b", "numpy.libs/libopenblas.so"),
        ("b", "cryptography/hazmat/bindings/_rust.abi3.so"),
        ("b", "cv2/.libs/libopencv_core.so"),
    ]
    archive_bytes = build_pyinstaller_carchive_payload(toc)

    main_elf = build_synthetic_elf64(
        is_executable=True,
        soname="singlefile_app",
        needed_libs=["libc.so.6"],
        trailing_payload=archive_bytes,
    )
    onefile_exe = tmp_path / "singlefile_app"
    onefile_exe.write_bytes(main_elf)

    res = inspect_compiled_distribution(onefile_exe)
    nat_map = {c.name: c for c in res.native_components}

    assert "openblas" in nat_map
    assert nat_map["openblas"].origin_package == "numpy"
    assert nat_map["openblas"].provenance == "vendored-in-wheel:numpy"

    assert "opencv" in nat_map or "libopencv" in nat_map
    cv_comp = nat_map.get("opencv") or nat_map.get("libopencv")
    assert cv_comp is not None
    assert cv_comp.origin_package == "cv2"
    assert cv_comp.provenance == "vendored-in-wheel:cv2"

    # Verify _rust.abi3.so was recognized as module file for cryptography, NOT as native third-party library
    assert "rust" not in nat_map
    assert "_rust" not in nat_map
    assert "cryptography" in res.bundled_modules or any("cryptography" in m for m in res.bundled_modules)


def test_source_only_audit_populates_linkage_report(tmp_path: Path) -> None:
    """Verify running audit in Source-Only mode (dist_path=None) generates binary linkage report."""
    sp_dir = tmp_path / ".venv" / "Lib" / "site-packages"
    sp_dir.mkdir(parents=True)

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "vision-app"\nversion = "1.0.0"\ndependencies = ["pillow>=10.0.0"]\n',
        encoding="utf-8",
    )

    create_dist_info(
        sp_dir,
        "pillow",
        "10.0.0",
        license_expression="HPND",
        top_level=["PIL"],
    )
    pil_libs = sp_dir / "pillow.libs"
    pil_libs.mkdir()
    tiff_pe = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="libtiff-5.dll",
        needed_libs=["KERNEL32.dll"],
        rodata_strings=["LIBTIFF, Version 4.5.1"],
    )
    (pil_libs / "libtiff-5.dll").write_bytes(tiff_pe)

    config = AuditConfig(project_path=tmp_path, dist_path=None, offline=True)
    report = run_audit(config)

    assert report.mode == AuditMode.SOURCE
    assert report.linkage_report is not None
    assert len(report.linkage_report.elf_binaries) >= 1
    assert "pillow" in report.linkage_report.package_libraries
    assert any("libtiff" in lib.lower() for lib in report.linkage_report.package_libraries["pillow"])


def test_cyclonedx_and_spdx_sbom_provenance(tmp_path: Path) -> None:
    """Verify CycloneDX and SPDX SBOM outputs contain provenance properties, sourceInfo, and relationships."""
    blas_comp = Component(
        name="openblas",
        version="0.3.27",
        component_type=ComponentType.NATIVE_LIBRARY,
        scope=ComponentScope.REQUIRED,
        origin_package="numpy",
        provenance="vendored-in-wheel:numpy",
        architecture="x86_64",
        soname="libopenblas.so.0",
        license_info=LicenseInfo(spdx_id="BSD-3-Clause"),
    )
    numpy_comp = Component(
        name="numpy",
        version="2.0.0",
        component_type=ComponentType.PYTHON_PACKAGE,
        scope=ComponentScope.REQUIRED,
        dependencies=["openblas"],
        license_info=LicenseInfo(spdx_id="BSD-3-Clause"),
    )

    report = run_audit(
        AuditConfig(project_path=tmp_path, dist_path=None, offline=True)
    )
    report.components = [numpy_comp, blas_comp]

    # 1. Test CycloneDX 1.5 JSON
    cdx_data = generate_cyclonedx_sbom(report)
    cdx_comps = {c["name"]: c for c in cdx_data.get("components", [])}
    assert "openblas" in cdx_comps
    blas_props = {p["name"]: p["value"] for p in cdx_comps["openblas"].get("properties", [])}

    assert blas_props.get("rhada:origin_package") == "numpy"
    assert blas_props.get("rhada:provenance") == "vendored-in-wheel:numpy"
    assert blas_props.get("rhada:architecture") == "x86_64"
    assert blas_props.get("rhada:soname") == "libopenblas.so.0"

    # Dependency relationships in CycloneDX
    deps = {d["ref"]: d.get("dependsOn", []) for d in cdx_data.get("dependencies", [])}
    np_ref = numpy_comp.purl
    blas_ref = blas_comp.purl
    assert np_ref in deps
    assert blas_ref in deps[np_ref]

    # 2. Test SPDX 2.3 JSON
    spdx_data = generate_spdx_sbom(report)
    pkgs = {p["name"]: p for p in spdx_data.get("packages", [])}
    assert "openblas" in pkgs
    blas_pkg = pkgs["openblas"]

    assert "Vendored by numpy" in blas_pkg.get("comment", "")
    assert "origin_package: numpy" in blas_pkg.get("sourceInfo", "")

    # CONTAINS relationship in SPDX
    rels = spdx_data.get("relationships", [])
    contains_rels = [
        r for r in rels
        if r["relationshipType"] == "CONTAINS"
        and r["relatedSpdxElement"] == blas_pkg["SPDXID"]
    ]
    assert len(contains_rels) >= 1
    assert contains_rels[0]["spdxElementId"] == pkgs["numpy"]["SPDXID"]


def test_reporter_rich_provenance_column(tmp_path: Path) -> None:
    """Verify Rich console report prints Provenance column and linkage vendor mapping."""
    blas_comp = Component(
        name="openblas",
        version="0.3.27",
        component_type=ComponentType.NATIVE_LIBRARY,
        scope=ComponentScope.REQUIRED,
        origin_package="numpy",
        provenance="vendored-in-wheel:numpy",
        architecture="x86_64",
        license_info=LicenseInfo(spdx_id="BSD-3-Clause"),
    )
    numpy_comp = Component(
        name="numpy",
        version="2.0.0",
        component_type=ComponentType.PYTHON_PACKAGE,
        scope=ComponentScope.REQUIRED,
        license_info=LicenseInfo(spdx_id="BSD-3-Clause"),
    )

    report = run_audit(AuditConfig(project_path=tmp_path, dist_path=None, offline=True))
    report.components = [numpy_comp, blas_comp]

    bin_info = ElfBinaryInfo(
        path="d:/numpy.libs/libopenblas.so",
        soname="libopenblas.so",
        origin_package="numpy",
        provenance="vendored-in-wheel:numpy",
    )
    report.linkage_report = verify_binary_linkage([bin_info])

    out = format_report_text(report)
    assert "Provenance" in out
    assert "vendored (numpy)" in out
    assert "Vendored by numpy" in out


def test_cli_inspect_binary_provenance(tmp_path: Path) -> None:
    """Verify inspect-binary CLI command outputs binary_origins and package_libraries."""
    libs_dir = tmp_path / "scipy.libs"
    libs_dir.mkdir()
    gfortran_pe = build_synthetic_pe64(
        is_executable=False,
        export_dll_name="libgfortran-5.dll",
        needed_libs=["KERNEL32.dll"],
    )
    (libs_dir / "libgfortran-5.dll").write_bytes(gfortran_pe)

    runner = CliRunner()
    result = runner.invoke(cli, ["inspect-binary", str(libs_dir)])
    assert result.exit_code == 0

    data = json.loads(result.output)
    assert "binary_origins" in data
    assert "package_libraries" in data
    assert "scipy" in data["package_libraries"]
    assert any("libgfortran-5.dll" in lib for lib in data["package_libraries"]["scipy"])


def test_record_with_corrupted_lines_and_missing_files(tmp_path: Path) -> None:
    """Verify RECORD parsing is robust against corrupted lines, empty lines, and missing files."""
    sp_dir = tmp_path / ".venv" / "Lib" / "site-packages"
    sp_dir.mkdir(parents=True)

    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project]\nname = "robust-app"\nversion = "1.0.0"\ndependencies = ["pillow>=10.4.0"]\n',
        encoding="utf-8",
    )

    pil_dist = create_dist_info(
        sp_dir,
        "pillow",
        "10.4.0",
        license_expression="HPND",
        top_level=["PIL"],
    )

    # Corrupted RECORD with empty lines, incomplete lines, and missing files
    record_lines = [
        "",
        "corrupted_line_without_commas",
        "pillow.libs/libpng16-d2427a7d.so,sha256=47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU=,123456",
        "pillow.libs/libtiff-7a2e88a6.so,sha256=xyz,654321",
        "pillow/__init__.py,sha256=abc,50",
    ]
    (pil_dist / "RECORD").write_text("\n".join(record_lines) + "\n", encoding="utf-8")

    ws = inspect_workspace(tmp_path)
    assert "pillow" in ws.components
    assert "pillow" in ws.package_libraries
    # Both libpng and libtiff should be discovered from RECORD even if the files don't exist on disk
    pil_libs = ws.package_libraries["pillow"]
    assert any("png" in lib.lower() for lib in pil_libs)
    assert any("tiff" in lib.lower() for lib in pil_libs)

    # Check that native components were constructed with profiles
    png_comp = next((c for c in ws.native_components if "png" in c.name.lower()), None)
    assert png_comp is not None
    assert png_comp.origin_package == "pillow"
    assert png_comp.provenance == "vendored-in-wheel:pillow"
    assert png_comp.license_info.spdx_id == "libpng-2.0"


def test_compliance_evaluation_for_permissive_native_licences() -> None:
    """Verify permissive native licences (libpng-2.0, IJG, libtiff) pass compliance."""
    from rhada.compliance import evaluate_compliance
    from rhada.models import DistributionLayout, LicenseRiskCategory
    from rhada.spdx import classify_single_spdx

    assert classify_single_spdx("libpng-2.0") == LicenseRiskCategory.PERMISSIVE
    assert classify_single_spdx("IJG") == LicenseRiskCategory.PERMISSIVE
    assert classify_single_spdx("libtiff") == LicenseRiskCategory.PERMISSIVE

    comp = Component(
        name="libpng",
        version="1.6.43",
        component_type=ComponentType.NATIVE_LIBRARY,
        scope=ComponentScope.REQUIRED,
        origin_package="pillow",
        provenance="vendored-in-wheel:pillow",
        license_info=LicenseInfo(
            spdx_id="libpng-2.0",
            risk_category=LicenseRiskCategory.PERMISSIVE,
            license_texts={"EMBEDDED_NATIVE_LICENSE": "libpng license text..."},
        ),
    )
    findings = evaluate_compliance(
        [comp],
        mode=AuditMode.SOURCE,
        layout=DistributionLayout.SOURCE_WORKSPACE,
        config=AuditConfig(project_path=Path(".")),
    )
    assert len(findings) == 0


def test_correlate_workspace_and_dist_with_flattened_dlls(tmp_path: Path) -> None:
    """Verify correlate_workspace_and_dist cross-references flattened binaries with workspace package_libraries."""
    from rhada.dist import DistInspectionResult
    from rhada.workspace import WorkspaceMetadata

    ws = WorkspaceMetadata(root_path=tmp_path)
    ws_numpy = Component(
        name="numpy",
        version="2.0.0",
        component_type=ComponentType.PYTHON_PACKAGE,
        scope=ComponentScope.REQUIRED,
    )
    ws.components["numpy"] = ws_numpy
    ws.package_libraries["numpy"] = ["libopenblas.dll"]

    dist_res = DistInspectionResult()
    dist_res.discovered_distributions["numpy"] = "2.0.0"
    dist_res.bundled_modules.add("numpy")

    # In a flattened dist (e.g. PyInstaller flat dir or Nuitka flat dir), libopenblas.dll is in root
    flat_blas = Component(
        name="openblas",
        version="0.3.27",
        component_type=ComponentType.NATIVE_LIBRARY,
        scope=ComponentScope.REQUIRED,
        bundled_files=["libopenblas.dll"],
        origin_package=None,  # Not known from flat path alone
    )
    dist_res.native_components.append(flat_blas)

    binfo = ElfBinaryInfo(path="d:/dist/libopenblas.dll", soname="libopenblas.dll")
    dist_res.linkage_report = verify_binary_linkage([binfo])

    active, _excluded = correlate_workspace_and_dist(ws, dist_res)

    blas_active = next(c for c in active if c.name == "openblas")
    assert blas_active.origin_package == "numpy"
    assert blas_active.provenance == "vendored-in-wheel:numpy"
    assert dist_res.linkage_report.binary_origins.get("d:/dist/libopenblas.dll") == "numpy"


def test_infer_binary_provenance_linux_and_windows_absolute_paths() -> None:
    """Verify infer_binary_provenance handles Linux and Windows absolute paths without misattribution."""
    # Linux absolute paths in virtualenvs / containers
    pkg, prov = infer_binary_provenance("/home/user/workspace/numpy/core/libopenblas.so.0", "libopenblas.so.0")
    assert pkg == "numpy"
    assert prov == "vendored-in-wheel:numpy"

    # Windows absolute paths
    pkg, prov = infer_binary_provenance("C:/Users/alice/repo/scipy/linalg/liblapack.dll", "liblapack.dll")
    assert pkg == "scipy"
    assert prov == "vendored-in-wheel:scipy"

    # Deep release build path containing release segment
    pkg, prov = infer_binary_provenance("/opt/build/release/numpy/libfoo.so", "libfoo.so")
    assert pkg == "numpy"
    assert prov == "vendored-in-wheel:numpy"

    # System ABI path on Linux
    pkg, prov = infer_binary_provenance("/usr/lib/x86_64-linux-gnu/libc.so.6", "libc.so.6")
    assert pkg is None
    assert prov == "system-abi:linux"

    # System ABI path on Windows
    pkg, prov = infer_binary_provenance("C:/Windows/System32/kernel32.dll", "kernel32.dll")
    assert pkg is None
    assert prov == "system-abi:windows"

    # Fallback to known native library (mapped to origin package numpy)
    pkg, prov = infer_binary_provenance("/custom/dist/libopenblas.so.0", "libopenblas.so.0")
    assert pkg == "numpy"
    assert prov == "vendored-in-wheel:numpy"


def test_elf_binary_info_licensing_and_copyright_fields(tmp_path: Path) -> None:
    """Verify ElfBinaryInfo holds license_spdx and copyright, and parse_binary populates them."""
    # Test PE parsing with known OpenBLAS profile
    pe_file = tmp_path / "libopenblas.dll"
    pe_file.write_bytes(
        build_synthetic_pe64(export_dll_name="libopenblas.dll", rodata_strings=["OpenBLAS 0.3.27"])
    )
    pe_info = parse_binary(pe_file)
    assert pe_info.detected_library_name == "openblas"
    assert pe_info.license_spdx == "BSD-3-Clause"
    assert "OpenBLAS" in pe_info.copyright
    pe_dict = pe_info.to_dict()
    assert pe_dict["license_spdx"] == "BSD-3-Clause"
    assert "OpenBLAS" in pe_dict["copyright"]

    # Test ELF parsing with known LCMS2 profile
    elf_file = tmp_path / "liblcms2.so.2"
    elf_file.write_bytes(
        build_synthetic_elf64(soname="liblcms2.so.2", rodata_strings=["Little CMS 2.16"])
    )
    elf_info = parse_binary(elf_file)
    assert elf_info.detected_library_name == "lcms2"
    assert elf_info.license_spdx == "MIT"
    assert "Marti Maria" in elf_info.copyright
    elf_dict = elf_info.to_dict()
    assert elf_dict["license_spdx"] == "MIT"
    assert "Marti Maria" in elf_dict["copyright"]


def test_workspace_record_c_extension_rejection(tmp_path: Path) -> None:
    """Verify that on-disk C extensions in RECORD are rejected as native libraries."""
    sp_dir = tmp_path / "site-packages"
    sp_dir.mkdir(parents=True)
    pil_dir = sp_dir / "PIL"
    pil_dir.mkdir()

    # Create a real C-extension file on disk
    cext = pil_dir / "_imaging.cpython-312-x86_64-linux-gnu.so"
    cext.write_bytes(build_synthetic_elf64(needed_libs=["libc.so.6"]))

    dist_dir = create_dist_info(
        sp_dir,
        "Pillow",
        "10.4.0",
        license_str="HPND",
    )
    (dist_dir / "RECORD").write_text(
        "PIL/_imaging.cpython-312-x86_64-linux-gnu.so,sha256=xxx,1234\n",
        encoding="utf-8",
    )

    ws = inspect_workspace(tmp_path)
    # _imaging.cpython-*.so is a C extension, so it should not be registered as a standalone native-library component
    native_names = [c.name for c in ws.components.values() if c.component_type == ComponentType.NATIVE_LIBRARY]
    assert "_imaging" not in native_names
    assert "_imaging.cpython-312-x86_64-linux-gnu" not in native_names


def test_workspace_delvewheel_manifest_parsing(tmp_path: Path) -> None:
    """Verify delvewheel .load-order manifest parsing registers vendored DLLs."""
    sp_dir = tmp_path / "site-packages"
    sp_dir.mkdir(parents=True)
    scipy_dir = sp_dir / "scipy"
    scipy_dir.mkdir()
    scipy_libs = sp_dir / "scipy.libs"
    scipy_libs.mkdir()

    manifest = scipy_libs / ".load-order-scipy-1.14.0"
    manifest.write_text("libopenblas-5.dll\nlibgfortran-5.dll\n", encoding="utf-8")

    dll1 = scipy_libs / "libopenblas-5.dll"
    dll1.write_bytes(build_synthetic_pe64(export_dll_name="libopenblas-5.dll", rodata_strings=["OpenBLAS"]))
    dll2 = scipy_libs / "libgfortran-5.dll"
    dll2.write_bytes(build_synthetic_pe64(export_dll_name="libgfortran-5.dll", rodata_strings=["GCC"]))

    dist_dir = create_dist_info(
        sp_dir,
        "scipy",
        "1.14.0",
        license_str="BSD-3-Clause",
    )
    (dist_dir / "RECORD").write_text(
        "scipy.libs/.load-order-scipy-1.14.0,sha256=xxx,50\n"
        "scipy.libs/libopenblas-5.dll,sha256=xxx,1000\n"
        "scipy.libs/libgfortran-5.dll,sha256=xxx,1000\n",
        encoding="utf-8",
    )

    ws = inspect_workspace(tmp_path)
    assert "scipy" in ws.package_libraries
    assert "libopenblas-5.dll" in ws.package_libraries["scipy"]
    assert "libgfortran-5.dll" in ws.package_libraries["scipy"]

    openblas_comp = next((c for c in ws.components.values() if "openblas" in c.name), None)
    assert openblas_comp is not None
    assert openblas_comp.origin_package == "scipy"
    assert openblas_comp.provenance == "vendored-in-wheel:scipy"


def test_sbom_intra_native_dependency_resolution() -> None:
    """Verify CycloneDX and SPDX SBOM generation links native library dependencies to each other."""
    from rhada.models import AuditReport

    pkg_comp = Component(
        name="scipy",
        version="1.14.0",
        component_type=ComponentType.PYTHON_PACKAGE,
        scope=ComponentScope.REQUIRED,
        dependencies=["openblas", "gfortran"],
    )
    blas_comp = Component(
        name="openblas",
        version="0.3.27",
        component_type=ComponentType.NATIVE_LIBRARY,
        scope=ComponentScope.REQUIRED,
        origin_package="scipy",
        provenance="vendored-in-wheel:scipy",
        bundled_files=["libopenblas.so.0"],
        dependencies=["libgfortran.so.5"],
    )
    gfortran_comp = Component(
        name="gfortran",
        version="13.2.0",
        component_type=ComponentType.NATIVE_LIBRARY,
        scope=ComponentScope.REQUIRED,
        origin_package="scipy",
        provenance="vendored-in-wheel:scipy",
        bundled_files=["libgfortran.so.5"],
    )

    report = AuditReport(
        target_name="testapp",
        target_version="1.0.0",
        mode=AuditMode.SOURCE,
        components=[pkg_comp, blas_comp, gfortran_comp],
    )

    # 1. Test CycloneDX
    cdx = generate_cyclonedx_sbom(report)
    deps = {d["ref"]: d.get("dependsOn", []) for d in cdx.get("dependencies", [])}
    blas_cdx = next(c for c in cdx["components"] if c["name"] == "openblas")
    gfortran_cdx = next(c for c in cdx["components"] if c["name"] == "gfortran")
    blas_ref = blas_cdx["bom-ref"]
    gfortran_ref = gfortran_cdx["bom-ref"]
    assert blas_ref in deps
    assert gfortran_ref in deps[blas_ref]

    # 2. Test SPDX
    spdx = generate_spdx_sbom(report)
    relationships = spdx.get("relationships", [])
    blas_spdx = next(p for p in spdx["packages"] if p["name"] == "openblas")
    gfortran_spdx = next(p for p in spdx["packages"] if p["name"] == "gfortran")
    blas_spdx_id = blas_spdx["SPDXID"]
    gfortran_spdx_id = gfortran_spdx["SPDXID"]
    depends_rels = [
        r
        for r in relationships
        if r.get("relationshipType") == "DEPENDS_ON"
        and r.get("spdxElementId") == blas_spdx_id
        and r.get("relatedSpdxElement") == gfortran_spdx_id
    ]
    assert len(depends_rels) == 1


def test_libuuid_lgpl_and_version_normalization(tmp_path: Path) -> None:
    """Verify libuuid SONAME .so.1 ABI version is normalized to unknown (not 1) and identified as LGPL."""
    from rhada.compliance import evaluate_compliance
    from rhada.elf import _infer_library_identity, elf_to_native_component
    from rhada.models import DistributionLayout, LicenseRiskCategory

    # 1. Test library identity inference
    det_lib, det_ver = _infer_library_identity("libuuid.so.1", "libuuid.so.1", [])
    assert det_lib == "libuuid"
    assert det_ver == "unknown"  # SONAME ABI .so.1 must not be treated as software version 1

    # Dotted SONAME suffix or embedded strings correctly identify versions
    _, det_ver_dotted = _infer_library_identity("libuuid.so.1.3.0", "libuuid.so.1.3.0", [])
    assert det_ver_dotted == "1.3.0"

    _, det_ver_util = _infer_library_identity("libuuid.so.1", "libuuid.so.1", ["util-linux 2.39.3 release banner"])
    assert det_ver_util == "2.39.3"

    _, det_ver_sym = _infer_library_identity("libuuid.so.1", "libuuid.so.1", ["UUID_2.36", "UUID_1.0"])
    assert det_ver_sym == "2.36"

    # 2. Test ELF parsing of synthetic libuuid.so.1
    so_file = tmp_path / "libuuid.so.1"
    so_file.write_bytes(build_synthetic_elf64(soname="libuuid.so.1"))

    info = parse_binary(so_file)
    assert info.detected_library_name == "libuuid"
    assert info.detected_version == "unknown"
    assert info.license_spdx == "LGPL-2.1-or-later"
    assert "Theodore Ts'o" in info.copyright

    # 3. Test Component generation
    comp = elf_to_native_component(info, is_monolithic=False)
    assert comp is not None
    assert comp.name == "libuuid"
    assert comp.version == "unknown"
    assert comp.license_info.spdx_id == "LGPL-2.1-or-later"
    assert comp.license_info.risk_category == LicenseRiskCategory.WEAK_COPYLEFT
    assert "Theodore Ts'o" in comp.license_info.copyright_notices[0]
    assert "util-linux" in comp.homepage

    # 4. Compliance evaluation: Weak copyleft dynamic obligation vs monolithic
    findings_dyn = evaluate_compliance(
        [comp],
        mode=AuditMode.COMPILED_DIST,
        layout=DistributionLayout.STANDALONE_DIR,
        config=AuditConfig(),
    )
    rule_ids_dyn = [f.rule_id for f in findings_dyn]
    assert "LIC-LGPL-DYNAMIC" in rule_ids_dyn
    assert "LIC-NOASSERTION" not in rule_ids_dyn

    comp_mono = elf_to_native_component(info, is_monolithic=True)
    assert comp_mono is not None
    findings_mono = evaluate_compliance(
        [comp_mono],
        mode=AuditMode.COMPILED_DIST,
        layout=DistributionLayout.MONOLITHIC_BINARY,
        config=AuditConfig(),
    )
    rule_ids_mono = [f.rule_id for f in findings_mono]
    assert "LIC-LGPL-MONOLITHIC" in rule_ids_mono
