"""Compiled distribution inspector for Nuitka and PyInstaller (standalone dirs and monolithic binaries)."""

from __future__ import annotations

import re
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

from defusedxml import ElementTree as ET

from rhada.elf import (
    elf_to_native_component,
    extract_printable_strings,
    is_elf_file,
    is_pe_bytes,
    is_pe_file,
    is_system_abi_lib,
    is_windows_msvc_runtime_dll,
    parse_elf_binary,
    parse_pe_binary,
    verify_binary_linkage,
)
from rhada.models import (
    BinaryLinkageReport,
    BundlerType,
    Component,
    ComponentScope,
    ComponentType,
    DistributionLayout,
    ElfBinaryInfo,
)
from rhada.pe import extract_utf16le_strings
from rhada.spdx import KNOWN_NATIVE_LIBRARIES
from rhada.workspace import (
    WorkspaceMetadata,
    _inspect_dist_info,
    extract_extension_module_name,
    normalize_pkg_name,
    split_dist_info_stem,
)

# PyInstaller CArchive magic pattern: "MEI\x0c\x0b\x0a\x0b\x0e"
PYI_MAGIC = b"MEI\x0c\x0b\x0a\x0b\x0e"

# Standard library module names (Python 3.11+) to avoid mistaking stdlib for third-party packages
STDLIB_MODULES: set[str] = set(getattr(sys, "stdlib_module_names", ())) | {
    "__future__",
    "__main__",
    "_abc",
    "_ast",
    "_asyncio",
    "_bisect",
    "_blake2",
    "_Bootstrap",
    "_bz2",
    "_codecs",
    "_collections",
    "_collections_abc",
    "_compat_pickle",
    "_compression",
    "_contextvars",
    "_csv",
    "_ctypes",
    "_curses",
    "_datetime",
    "_decimal",
    "_elementtree",
    "_functools",
    "_hashlib",
    "_heapq",
    "_imp",
    "_io",
    "_json",
    "_locale",
    "_lzma",
    "_markupbase",
    "_md5",
    "_msi",
    "_multibytecodec",
    "_multiprocessing",
    "_opcode",
    "_operator",
    "_osx_support",
    "_overlapped",
    "_pickle",
    "_posixshmem",
    "_posixsubprocess",
    "_py_abc",
    "_pydecimal",
    "_pyio",
    "_queue",
    "_random",
    "_sha1",
    "_sha256",
    "_sha3",
    "_sha512",
    "_signal",
    "_sitebuiltins",
    "_socket",
    "_sqlite3",
    "_sre",
    "_ssl",
    "_stat",
    "_statistics",
    "_string",
    "_strptime",
    "_struct",
    "_symtable",
    "_thread",
    "_threading_local",
    "_tkinter",
    "_tokenize",
    "_tracemalloc",
    "_typing",
    "_uuid",
    "_warnings",
    "_weakref",
    "_weakrefset",
    "_winapi",
    "_wmi",
    "_zoneinfo",
    "base_library",
    "msvcrt",
    "nt",
    "pyimod01_archive",
    "pyimod02_importers",
    "pyimod03_ctypes",
    "pyimod04_pywin32",
    "pyiboot01_bootstrap",
    "struct",
    "winreg",
    "winsound",
}

BUILD_AND_DEV_TOOLS = {
    "nuitka",
    "pyinstaller",
    "pyinstaller-hooks-contrib",
    "altgraph",
    "ordered-set",
    "zstandard",
    "pytest",
    "pytest-cov",
    "coverage",
    "pluggy",
    "iniconfig",
    "ruff",
    "mypy",
    "mypy-extensions",
    "flake8",
    "black",
    "isort",
    "hatchling",
    "hatch",
    "setuptools",
    "wheel",
    "pip",
    "build",
    "twine",
    "cython",
    "meson",
    "meson-python",
    "ninja",
    "delvewheel",
    "auditwheel",
    "patchelf",
    "pefile",
    "pywin32-ctypes",
}


@dataclass(slots=True)
class DistInspectionResult:
    """Result of inspecting a compiled distribution."""

    bundler_type: BundlerType = BundlerType.NONE
    layout: DistributionLayout = DistributionLayout.STANDALONE_DIR
    bundled_modules: set[str] = field(default_factory=set)
    statically_compiled_modules: set[str] = field(default_factory=set)
    discovered_distributions: dict[str, str] = field(default_factory=dict)
    dist_info_components: dict[str, Component] = field(default_factory=dict)
    native_components: list[Component] = field(default_factory=list)
    linkage_report: BinaryLinkageReport = field(default_factory=BinaryLinkageReport)
    module_files: dict[str, list[str]] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def _clean_nuitka_module_symbol(sym: str) -> str:
    """Extract clean Python module identifier from a Nuitka `modulecode_...` symbol."""
    raw_mod = sym.lstrip("_").removeprefix("modulecode_")
    # Nuitka encodes submodule dots as $$ or $ in C/ELF/PE symbol names
    mod_clean = raw_mod.replace("$$", ".").replace("$", ".").strip()
    if all(part.isidentifier() for part in mod_clean.split(".")):
        return mod_clean
    top = mod_clean.split(".", 1)[0].strip()
    return top if top.isidentifier() else ""


def _record_module_file(result: DistInspectionResult, module_name: str, file_path: str) -> None:
    clean_mod = module_name.strip()
    if not clean_mod:
        return
    top = clean_mod.split(".", 1)[0].strip()
    if not top or top in STDLIB_MODULES or not top.isidentifier():
        return
    result.bundled_modules.add(clean_mod)
    files = result.module_files.setdefault(clean_mod, [])
    if file_path not in files:
        files.append(file_path)
    if top != clean_mod:
        result.bundled_modules.add(top)
        top_files = result.module_files.setdefault(top, [])
        if file_path not in top_files:
            top_files.append(file_path)


def _parse_delvewheel_load_order_name(filename: str) -> tuple[str, str] | None:
    """
    Parse delvewheel's `.load-order-<pkg>-<version>` file inside `<pkg>.libs/` on Windows.
    Returns (normalised_pkg_name, version) or None.
    """
    if not filename.startswith(".load-order-"):
        return None
    stem = filename.removeprefix(".load-order-")
    if not stem:
        return None
    raw_name, ver = split_dist_info_stem(stem)
    norm_name = normalize_pkg_name(raw_name)
    if not norm_name:
        return None
    return norm_name, ver


def _is_native_libs_dir_segment(seg: str) -> bool:
    """Return True if a path directory segment is a wheel native library folder (e.g. `numpy.libs`, `scipy.libs`)."""
    lower = seg.lower()
    return lower.endswith(".libs") or lower in {".libs", "extra-dll"}


def parse_nuitka_compilation_report(xml_path: Path, result: DistInspectionResult) -> None:
    """
    Parse Nuitka's compilation-report.xml to extract exact compiled modules and distributions.
    """
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except (ET.ParseError, OSError) as exc:
        result.warnings.append(f"Failed to parse Nuitka compilation report {xml_path}: {exc}")
        return

    result.bundler_type = BundlerType.NUITKA

    # 1. Extract <module name="..." kind="..." distribution="...">
    for mod_elem in root.iter("module"):
        mod_name = (mod_elem.get("name") or "").strip()
        if not mod_name:
            continue
        top = mod_name.split(".", 1)[0]
        if top in STDLIB_MODULES:
            continue
        kind = (mod_elem.get("kind") or "").lower()
        reason = (mod_elem.get("reason") or "").lower()
        if reason == "excluded":
            continue
        _record_module_file(result, mod_name, f"nuitka-report:{mod_name}")
        if "compiled" in kind or "bytecode" in kind or not kind:
            result.statically_compiled_modules.add(top)
            result.statically_compiled_modules.add(mod_name)
        dist_attr = (mod_elem.get("distribution") or "").strip()
        if dist_attr:
            for dpart in dist_attr.split(","):
                dnorm = normalize_pkg_name(dpart.strip())
                if dnorm:
                    result.discovered_distributions.setdefault(dnorm, "unknown")

    # 2. Extract <distributions><distribution name="..." version="...">
    for dist_elem in root.iter("distribution"):
        dname = normalize_pkg_name(dist_elem.get("name") or "")
        dver = (dist_elem.get("version") or "unknown").strip()
        if dname:
            result.discovered_distributions[dname] = dver


def parse_pyinstaller_carchive_toc(binary_bytes: bytes) -> list[tuple[str, str]]:
    """
    Parse PyInstaller's CArchive cookie and TOC from an executable's raw bytes.
    Returns a list of (typecode, entry_name) tuples.
    Supports both PyInstaller 2.1+ (88-byte cookie: !8sIIii64s) and 2.0 (24-byte cookie: !8siiii).
    """
    entries: list[tuple[str, str]] = []
    idx = binary_bytes.rfind(PYI_MAGIC)
    if idx == -1:
        return entries

    # Check if standard 88-byte cookie (!8sIIii64s) or 24-byte cookie (!8siiii)
    remaining = len(binary_bytes) - idx
    toc_offset = -1
    toc_len = 0
    pkg_len = 0

    if remaining >= 88:
        try:
            _, pkg_len, toc_off_u, toc_len_i, _pyver, _ = struct.unpack_from("!8sIIii64s", binary_bytes, idx)
            cookie_end = idx + 88
            archive_start = cookie_end - pkg_len
            if (
                0 <= archive_start <= idx
                and toc_off_u >= 0
                and 0 < toc_len_i <= pkg_len - 88
                and toc_off_u + toc_len_i <= pkg_len - 88
            ):
                toc_offset = archive_start + toc_off_u
                toc_len = toc_len_i
        except struct.error:
            pass

    if toc_offset < 0 and remaining >= 24:
        try:
            _, pkg_len, toc_off_i, toc_len_i, _ = struct.unpack_from("!8siiii", binary_bytes, idx)
            cookie_end = idx + 24
            archive_start = cookie_end - pkg_len
            if (
                0 <= archive_start <= idx
                and toc_off_i >= 0
                and 0 < toc_len_i <= pkg_len - 24
                and toc_off_i + toc_len_i <= pkg_len - 24
            ):
                toc_offset = archive_start + toc_off_i
                toc_len = toc_len_i
        except struct.error:
            pass

    if toc_offset >= 0 and toc_offset + toc_len <= idx and toc_len > 0:
        pos = toc_offset
        end = toc_offset + toc_len
        while pos + 18 <= end:
            try:
                (entry_len, _, _, _, _, typecode_b) = struct.unpack_from("!iIIIBc", binary_bytes, pos)
            except struct.error:
                break
            if entry_len < 18 or pos + entry_len > end:
                break
            name_bytes = binary_bytes[pos + 18 : pos + entry_len].rstrip(b"\x00")
            name_str = name_bytes.decode("utf-8", errors="replace").strip()
            typecode = typecode_b.decode("ascii", errors="replace")
            if name_str:
                entries.append((typecode, name_str))
            pos += entry_len

    return entries


def _inspect_binary_payload_strings(
    raw_bytes: bytes,
    binary_path: str,
    result: DistInspectionResult,
    *,
    is_monolithic: bool = True,
    external_needed: set[str] | None = None,
) -> None:
    """
    Inspect printable strings & symbols inside an ELF or PE executable to detect Nuitka / PyInstaller
    markers, compiled Python modules, and (when monolithic) embedded shared libraries.
    """
    ext_needed_lower = {n.lower() for n in (external_needed or set())}
    strings_list = extract_printable_strings(raw_bytes, limit=8000)
    if is_pe_bytes(raw_bytes):
        seen_strs = set(strings_list)
        for u_str in extract_utf16le_strings(raw_bytes, limit=2000):
            if u_str not in seen_strs:
                seen_strs.add(u_str)
                strings_list.append(u_str)

    joined = "\n".join(strings_list)

    if PYI_MAGIC in raw_bytes or "pyi-runtime-tmpdir" in joined or "MEIPASS" in joined or "pyimod0" in joined:
        result.bundler_type = BundlerType.PYINSTALLER

    if (
        (
            "__nuitka_version__" in joined
            or "NUITKA_ONEFILE_PARENT" in joined
            or "modulecode_" in joined
            or "__constants.bin" in joined
        )
        and result.bundler_type == BundlerType.NONE
    ):
        result.bundler_type = BundlerType.NUITKA

    # Parse PyInstaller TOC if MEI magic is present
    if PYI_MAGIC in raw_bytes:
        toc_entries = parse_pyinstaller_carchive_toc(raw_bytes)
        for typecode, entry_name in toc_entries:
            norm_path = entry_name.replace("\\", "/").lstrip("./")
            fname = Path(norm_path).name
            lower_fname = fname.lower()
            dir_segs = norm_path.split("/")[:-1]
            in_libs_dir = any(_is_native_libs_dir_segment(seg) for seg in dir_segs)

            for seg in dir_segs:
                if seg.endswith(".libs"):
                    pkg_stem = seg.removesuffix(".libs")
                    if pkg_stem and pkg_stem.isidentifier():
                        _record_module_file(result, pkg_stem, f"{binary_path}!{entry_name}")

            # Check for delvewheel .load-order-<pkg>-<ver> metadata inside TOC
            load_order = _parse_delvewheel_load_order_name(fname)
            if load_order is not None:
                dname, dver = load_order
                result.discovered_distributions[dname] = dver
                _record_module_file(result, dname.replace("-", "_"), f"{binary_path}!{entry_name}")
                continue

            # Check for .dist-info metadata inside TOC
            if ".dist-info/" in norm_path:
                dist_seg = next(s for s in norm_path.split("/") if s.endswith(".dist-info"))
                stem = dist_seg.removesuffix(".dist-info")
                raw_dname, dver = split_dist_info_stem(stem)
                dname = normalize_pkg_name(raw_dname)
                if dname:
                    result.discovered_distributions[dname] = dver
            # Check for Windows native shared library (.dll) inside TOC
            elif lower_fname.endswith(".dll"):
                if is_monolithic:
                    _register_embedded_native_lib(
                        fname,
                        f"{binary_path}!{entry_name}",
                        strings_list,
                        result,
                        binary_format="PE",
                    )
            # Check for POSIX native shared library (.so) inside TOC
            elif (typecode in ("b", "x") or ".so" in fname) and (fname.startswith("lib") or in_libs_dir) and ".so" in fname:
                if is_monolithic:
                    _register_embedded_native_lib(
                        fname,
                        f"{binary_path}!{entry_name}",
                        strings_list,
                        result,
                        binary_format="ELF",
                    )
            # Check for Python C-extension (.pyd, .cpython-*.so, .abi3.so) inside TOC
            elif not in_libs_dir and (
                lower_fname.endswith(".pyd") or ".cpython-" in lower_fname or ".abi3.so" in lower_fname
            ):
                ext_name = extract_extension_module_name(fname)
                if "/" in norm_path:
                    pkg_parts = [p for p in dir_segs if p.isidentifier()]
                    if pkg_parts:
                        _record_module_file(result, pkg_parts[0], f"{binary_path}!{entry_name}")
                        for i in range(2, len(pkg_parts) + 1):
                            _record_module_file(result, ".".join(pkg_parts[:i]), f"{binary_path}!{entry_name}")
                        if ext_name:
                            full_ext = f"{'.'.join(pkg_parts)}.{ext_name}"
                            _record_module_file(result, full_ext, f"{binary_path}!{entry_name}")
                if ext_name:
                    leaf = ext_name.split(".")[-1]
                    if leaf.isidentifier():
                        _record_module_file(result, leaf, f"{binary_path}!{entry_name}")
                    if ext_name.isidentifier():
                        _record_module_file(result, ext_name, f"{binary_path}!{entry_name}")
            # Check for Python module or package inside TOC (typecode m/M/s or .py/.pyc)
            elif typecode in ("m", "M", "s") or norm_path.endswith((".pyc", ".pyo", ".py")):
                if "/" in norm_path:
                    pkg_parts = [p for p in dir_segs if p.isidentifier()]
                    if pkg_parts:
                        _record_module_file(result, pkg_parts[0], f"{binary_path}!{entry_name}")
                        for i in range(2, len(pkg_parts) + 1):
                            _record_module_file(result, ".".join(pkg_parts[:i]), f"{binary_path}!{entry_name}")
                        py_stem = fname.rsplit(".", 1)[0]
                        if py_stem.isidentifier() and not py_stem.startswith("__"):
                            full_mod = f"{'.'.join(pkg_parts)}.{py_stem}"
                            _record_module_file(result, full_mod, f"{binary_path}!{entry_name}")
                else:
                    raw_mod = fname.rsplit(".", 1)[0] if fname.endswith((".pyc", ".pyo", ".py")) else fname
                    parts = raw_mod.split(".")
                    if all(p.isidentifier() for p in parts):
                        _record_module_file(result, parts[0], f"{binary_path}!{entry_name}")
                        for i in range(2, len(parts) + 1):
                            _record_module_file(result, ".".join(parts[:i]), f"{binary_path}!{entry_name}")

    if PYI_MAGIC not in raw_bytes:
        # Scan strings for Nuitka compiled module symbols: modulecode_<pkg> or PyInit_<pkg>
        for s in strings_list:
            if s.startswith(("modulecode_", "_modulecode_")):
                mod_clean = _clean_nuitka_module_symbol(s)
                if mod_clean:
                    _record_module_file(result, mod_clean, f"{binary_path}:{s}")
                    result.statically_compiled_modules.add(mod_clean)
            elif s.startswith(("PyInit_", "_PyInit_")):
                mod_clean = s.lstrip("_").removeprefix("PyInit_").split(".", 1)[0]
                if mod_clean and mod_clean.isidentifier():
                    _record_module_file(result, mod_clean, f"{binary_path}:{s}")
            elif ".load-order-" in s:
                s_fname = Path(s.replace("\\", "/")).name
                load_order = _parse_delvewheel_load_order_name(s_fname)
                if load_order is not None:
                    dname, dver = load_order
                    result.discovered_distributions[dname] = dver
                    _record_module_file(result, dname.replace("-", "_"), f"{binary_path}!{s}")
            # Also detect embedded .pyc / .so / .pyd / .dist-info paths in onefile payloads
            elif ".dist-info" in s:
                m = re.search(r"([A-Za-z0-9_.-]+?)-(\d+\.\d+[A-Za-z0-9_.-]*)\.dist-info", s)
                if m:
                    dname = normalize_pkg_name(m.group(1))
                    if dname:
                        result.discovered_distributions[dname] = m.group(2)
            elif (".cpython-" in s and s.endswith(".so")) or s.lower().endswith(".pyd"):
                clean_s = s.replace("\\", "/").lstrip("./")
                dir_segs = clean_s.split("/")[:-1]
                ext_name = extract_extension_module_name(Path(clean_s).name)
                if dir_segs:
                    pkg_parts = [p for p in dir_segs if p.isidentifier() and not p.startswith(("pyi", "_pyi"))]
                    if pkg_parts:
                        _record_module_file(result, pkg_parts[0], f"{binary_path}!{clean_s}")
                        for i in range(2, len(pkg_parts) + 1):
                            _record_module_file(result, ".".join(pkg_parts[:i]), f"{binary_path}!{clean_s}")
                        if ext_name:
                            full_ext = f"{'.'.join(pkg_parts)}.{ext_name}"
                            _record_module_file(result, full_ext, f"{binary_path}!{clean_s}")
                if ext_name:
                    leaf = ext_name.split(".")[-1]
                    if leaf.isidentifier() and not leaf.startswith(("pyi", "_pyi")):
                        _record_module_file(result, leaf, f"{binary_path}!{clean_s}")
                    if ext_name.isidentifier() and not ext_name.startswith(("pyi", "_pyi")):
                        _record_module_file(result, ext_name, f"{binary_path}!{clean_s}")
            elif is_monolithic and re.match(r"^lib[a-zA-Z0-9_+-]+\.so(?:\.\d+)*$", Path(s.replace("\\", "/")).name):
                lib_fname = Path(s.replace("\\", "/")).name
                if not is_system_abi_lib(lib_fname) and lib_fname.lower() not in ext_needed_lower:
                    _register_embedded_native_lib(
                        lib_fname,
                        f"{binary_path}!{lib_fname}",
                        strings_list,
                        result,
                        binary_format="ELF",
                    )
            elif is_monolithic and re.match(r"^[a-zA-Z0-9_+.-]+\.dll$", Path(s.replace("\\", "/")).name, re.IGNORECASE):
                dll_fname = Path(s.replace("\\", "/")).name
                if (
                    not is_system_abi_lib(dll_fname)
                    and not is_windows_msvc_runtime_dll(dll_fname)
                    and dll_fname.lower() not in ext_needed_lower
                ):
                    _register_embedded_native_lib(
                        dll_fname,
                        f"{binary_path}!{dll_fname}",
                        strings_list,
                        result,
                        binary_format="PE",
                    )


def _register_embedded_native_lib(
    lib_filename: str,
    virtual_path: str,
    strings_list: list[str],
    result: DistInspectionResult,
    *,
    binary_format: str = "ELF",
) -> None:
    """Create or merge a native library Component discovered inside a monolithic binary."""
    if is_system_abi_lib(lib_filename) or is_windows_msvc_runtime_dll(lib_filename):
        return

    from rhada.elf import _infer_library_identity, _match_known_native_profile, infer_binary_provenance

    det_name, det_ver = _infer_library_identity(lib_filename, lib_filename, strings_list)
    if det_name in ("libc", "libm", "libdl", "libpthread", "librt", "ld"):
        return

    orig_pkg, prov = infer_binary_provenance(virtual_path, lib_filename)
    prof = _match_known_native_profile(det_name) if det_name else None
    spdx_id = prof.spdx_id if prof else "NOASSERTION"
    cop_notice = prof.copyright_notice if prof else ""

    fmt = "PE" if lib_filename.lower().endswith(".dll") else binary_format
    fake_elf = ElfBinaryInfo(
        path=virtual_path,
        soname=lib_filename,
        is_executable=False,
        is_shared_object=True,
        is_statically_linked=True,
        ident_strings=strings_list[:50],
        detected_library_name=det_name,
        detected_version=det_ver,
        binary_format=fmt,
        origin_package=orig_pkg,
        provenance=prov,
        license_spdx=spdx_id,
        copyright=cop_notice,
    )

    comp = elf_to_native_component(fake_elf, is_monolithic=True, origin_package=orig_pkg, provenance=prov)
    if comp:
        _merge_native_component(result.native_components, comp)


def _merge_native_component(target_list: list[Component], new_comp: Component) -> None:
    """Deduplicate and merge native components by canonical name."""
    for existing in target_list:
        if existing.name == new_comp.name:
            if existing.version == "unknown" and new_comp.version != "unknown":
                existing.version = new_comp.version
                existing.refresh_purl()
            if not new_comp.is_statically_compiled:
                existing.is_statically_compiled = False
            if new_comp.has_dynamic_relinking:
                existing.has_dynamic_relinking = True
            if existing.origin_package is None and new_comp.origin_package is not None:
                existing.origin_package = new_comp.origin_package
                existing.provenance = new_comp.provenance
            if new_comp.architecture and not existing.architecture:
                existing.architecture = new_comp.architecture
            if new_comp.soname and not existing.soname:
                existing.soname = new_comp.soname
            for bf in new_comp.bundled_files:
                if bf not in existing.bundled_files:
                    existing.bundled_files.append(bf)
            for ev in new_comp.discovery_evidence:
                if ev not in existing.discovery_evidence:
                    existing.discovery_evidence.append(ev)
            return
    target_list.append(new_comp)


def _inspect_exported_module_symbols(
    symbols: list[str],
    binary_label: str,
    result: DistInspectionResult,
) -> None:
    """Extract Nuitka `modulecode_*` and Python `PyInit_*` module symbols from a binary's export list."""
    for sym in symbols:
        clean_sym = sym.lstrip("_")
        if clean_sym.startswith("modulecode_"):
            mod = _clean_nuitka_module_symbol(sym)
            if mod:
                _record_module_file(result, mod, f"{binary_label}:{sym}")
                result.statically_compiled_modules.add(mod)
            result.bundler_type = BundlerType.NUITKA
        elif clean_sym.startswith("PyInit_"):
            mod = clean_sym.removeprefix("PyInit_").split(".", 1)[0]
            if mod and mod.isidentifier():
                _record_module_file(result, mod, f"{binary_label}:{sym}")


def inspect_compiled_distribution(
    dist_path: Path,
    compilation_report_path: Path | None = None,
) -> DistInspectionResult:
    """
    Inspect a compiled Nuitka or PyInstaller distribution (either a standalone directory
    or a monolithic binary) to discover bundled Python modules, distributions, native
    shared libraries, and ELF/PE binary linkage.
    """
    dist_path = dist_path.resolve()
    result = DistInspectionResult()

    if not dist_path.exists():
        raise FileNotFoundError(f"Distribution path does not exist: {dist_path}")

    # Check explicit or adjacent Nuitka compilation report XML
    if compilation_report_path is not None:
        parse_nuitka_compilation_report(compilation_report_path, result)

    if dist_path.is_file():
        result.layout = DistributionLayout.MONOLITHIC_BINARY
        elf_binaries: list[ElfBinaryInfo] = []
        raw_bytes = dist_path.read_bytes()

        if is_elf_file(dist_path):
            elf_info = parse_elf_binary(dist_path)
            elf_binaries.append(elf_info)
            _inspect_exported_module_symbols(elf_info.exported_symbols_sample, dist_path.name, result)
        elif is_pe_file(dist_path):
            pe_info = parse_pe_binary(dist_path)
            elf_binaries.append(pe_info)
            _inspect_exported_module_symbols(pe_info.exported_symbols_sample, dist_path.name, result)

        ext_needed = {lib for b in elf_binaries for lib in b.needed_libs}
        _inspect_binary_payload_strings(
            raw_bytes,
            str(dist_path),
            result,
            is_monolithic=True,
            external_needed=ext_needed,
        )

        if result.bundler_type == BundlerType.NONE and elf_binaries:
            result.bundler_type = (
                BundlerType.GENERIC_PE if elf_binaries[0].binary_format == "PE" else BundlerType.GENERIC_ELF
            )

        # Check adjacent compilation-report.xml if not explicitly provided
        if compilation_report_path is None:
            for candidate_xml in (
                dist_path.parent / "compilation-report.xml",
                dist_path.parent / "nuitka-compilation-report.xml",
            ):
                if candidate_xml.is_file():
                    parse_nuitka_compilation_report(candidate_xml, result)
                    break

        result.linkage_report = verify_binary_linkage(elf_binaries, dist_root=None)
        return result

    # Standalone directory mode
    result.layout = DistributionLayout.STANDALONE_DIR
    elf_binaries = []

    # Check for Nuitka compilation-report.xml inside the directory or its parent
    if compilation_report_path is None:
        for candidate_xml in (
            dist_path / "compilation-report.xml",
            dist_path / "nuitka-compilation-report.xml",
            dist_path.parent / "compilation-report.xml",
        ):
            if candidate_xml.is_file():
                parse_nuitka_compilation_report(candidate_xml, result)
                break

    # Detect PyInstaller vs Nuitka markers in directory
    if (dist_path / "_internal").is_dir() or list(dist_path.rglob("base_library.zip")):
        result.bundler_type = BundlerType.PYINSTALLER
    elif (
        (dist_path.name.endswith(".dist") or list(dist_path.glob("__constants*")))
        and result.bundler_type == BundlerType.NONE
    ):
        result.bundler_type = BundlerType.NUITKA

    # 1. Inspect any bundled *.dist-info directories (common in PyInstaller standalone dirs)
    for dist_info_dir in sorted(dist_path.rglob("*.dist-info")):
        if not dist_info_dir.is_dir():
            continue
        comp, _top_mods, all_mods = _inspect_dist_info(dist_info_dir)
        if comp:
            result.dist_info_components[comp.name] = comp
            result.discovered_distributions[comp.name] = comp.version
            for mod in all_mods:
                _record_module_file(result, mod, str(dist_info_dir.relative_to(dist_path)))

    # 2. Walk all files in the standalone distribution directory
    for file_path in sorted(dist_path.rglob("*")):
        if not file_path.is_file() or file_path.is_symlink():
            continue
        rel_path = str(file_path.relative_to(dist_path)).replace("\\", "/")
        fname = file_path.name
        lower_fname = fname.lower()

        # Skip files inside .dist-info (already processed)
        if ".dist-info/" in rel_path:
            continue

        # Strip leading _internal/ prefix used by PyInstaller >= 6.0 when inferring module hierarchy
        logical_rel = rel_path.removeprefix("_internal/")
        dir_segs = logical_rel.split("/")[:-1]
        in_native_libs_dir = any(_is_native_libs_dir_segment(seg) for seg in dir_segs)

        # Record any package inferred from `<pkg>.libs/` directories (auditwheel / delvewheel)
        for seg in dir_segs:
            if seg.endswith(".libs"):
                pkg_stem = seg.removesuffix(".libs")
                if pkg_stem and pkg_stem.isidentifier():
                    _record_module_file(result, pkg_stem, rel_path)

        # Check delvewheel `.load-order-<pkg>-<version>` files
        load_order = _parse_delvewheel_load_order_name(fname)
        if load_order is not None:
            dname, dver = load_order
            result.discovered_distributions[dname] = dver
            _record_module_file(result, dname.replace("-", "_"), rel_path)
            continue

        # Inspect ELF and Windows PE binaries (executables, Python C-extensions, and native .so/.dll libraries)
        is_elf = is_elf_file(file_path)
        is_pe = False if is_elf else is_pe_file(file_path)
        if is_elf or is_pe:
            try:
                bin_info = parse_elf_binary(file_path) if is_elf else parse_pe_binary(file_path)
                elf_binaries.append(bin_info)
            except (OSError, ValueError) as exc:
                fmt_label = "ELF" if is_elf else "PE"
                result.warnings.append(f"Failed to parse {fmt_label} binary {rel_path}: {exc}")
                continue

            is_main_exe = bin_info.is_executable or (
                is_elf and not lower_fname.endswith(".so") and ".so." not in lower_fname
            ) or (is_pe and lower_fname.endswith(".exe"))

            # If main executable, also inspect its embedded strings/TOC (e.g. PyInstaller bootloader or Nuitka main binary)
            if is_main_exe:
                _inspect_exported_module_symbols(bin_info.exported_symbols_sample, rel_path, result)
                raw_b = file_path.read_bytes()
                _inspect_binary_payload_strings(raw_b, rel_path, result, is_monolithic=False)
                if not bin_info.is_shared_object:
                    continue

            # Check if it's a Python C-extension module (.pyd, .cpython-*.so, .abi3.so, exports PyInit_*,
            # or a non-lib .so inside a package directory such as scipy/linalg/cython_blas.so)
            has_pyinit = any(s.lstrip("_").startswith("PyInit_") for s in bin_info.exported_symbols_sample)
            is_py_ext = not in_native_libs_dir and (
                lower_fname.endswith(".pyd")
                or ".cpython-" in lower_fname
                or ".cp3" in lower_fname
                or ".abi3." in lower_fname
                or has_pyinit
                or (
                    is_elf
                    and "/" in logical_rel
                    and not lower_fname.startswith("lib")
                    and (bin_info.detected_library_name or "") not in KNOWN_NATIVE_LIBRARIES
                )
            )
            if is_py_ext:
                ext_name = extract_extension_module_name(fname)
                if "/" in logical_rel:
                    pkg_parts = [p for p in dir_segs if p.isidentifier()]
                    if pkg_parts:
                        _record_module_file(result, pkg_parts[0], rel_path)
                        for i in range(2, len(pkg_parts) + 1):
                            _record_module_file(result, ".".join(pkg_parts[:i]), rel_path)
                        if ext_name:
                            full_ext = f"{'.'.join(pkg_parts)}.{ext_name}"
                            _record_module_file(result, full_ext, rel_path)
                    if ext_name:
                        leaf = ext_name.split(".")[-1]
                        if leaf.isidentifier():
                            _record_module_file(result, leaf, rel_path)
                        if ext_name.isidentifier():
                            _record_module_file(result, ext_name, rel_path)
                else:
                    if ext_name:
                        parts = ext_name.split(".")
                        if all(p.isidentifier() for p in parts):
                            _record_module_file(result, parts[0], rel_path)
                            for i in range(2, len(parts) + 1):
                                _record_module_file(result, ".".join(parts[:i]), rel_path)
                if (
                    result.bundler_type == BundlerType.NONE
                    and not (dist_path / "_internal").is_dir()
                    and any(s.lstrip("_").startswith("modulecode_") for s in bin_info.exported_symbols_sample)
                ):
                    # Nuitka standalone directories place compiled module .so/.pyd files directly
                    result.bundler_type = BundlerType.NUITKA
                    mod_lead = pkg_parts[0] if ("/" in logical_rel and pkg_parts) else (ext_name.split(".")[0] if ext_name else fname.split(".", 1)[0])
                    result.statically_compiled_modules.add(mod_lead)
            else:
                # Native shared library (.so or .dll)
                nat_comp = elf_to_native_component(bin_info, is_monolithic=False)
                if nat_comp:
                    _merge_native_component(result.native_components, nat_comp)
            continue

        # Non-ELF/PE Python bytecode / source / archives
        if lower_fname.endswith((".pyc", ".pyo", ".py")):
            if "/" in logical_rel:
                pkg_parts = [p for p in dir_segs if p.isidentifier()]
                if pkg_parts:
                    _record_module_file(result, pkg_parts[0], rel_path)
                    for i in range(2, len(pkg_parts) + 1):
                        _record_module_file(result, ".".join(pkg_parts[:i]), rel_path)
                    py_stem = fname.rsplit(".", 1)[0]
                    if py_stem.isidentifier() and not py_stem.startswith("__"):
                        full_mod = f"{'.'.join(pkg_parts)}.{py_stem}"
                        _record_module_file(result, full_mod, rel_path)
            else:
                py_stem = fname.rsplit(".", 1)[0]
                parts = py_stem.split(".")
                if all(p.isidentifier() for p in parts):
                    _record_module_file(result, parts[0], rel_path)
                    for i in range(2, len(parts) + 1):
                        _record_module_file(result, ".".join(parts[:i]), rel_path)
        elif lower_fname.endswith(".pyz"):
            result.bundler_type = BundlerType.PYINSTALLER

    if result.bundler_type == BundlerType.NONE and elf_binaries:
        result.bundler_type = (
            BundlerType.GENERIC_PE if elf_binaries[0].binary_format == "PE" else BundlerType.GENERIC_ELF
        )

    result.linkage_report = verify_binary_linkage(elf_binaries, dist_root=dist_path)
    return result


def _resolve_pkg_for_module(
    mod_name: str,
    ws: WorkspaceMetadata,
    file_paths: list[str] | None = None,
) -> str | None:
    """
    Resolve a module, submodule, or native extension name to its owning package name.
    Checks exact name, lowercase name, normalisation, dotted parent hierarchies,
    and associated file path directory structures.
    """
    pkg = ws.module_to_package.get(mod_name) or ws.module_to_package.get(mod_name.lower())
    if pkg:
        return pkg

    cand = normalize_pkg_name(mod_name)
    if cand in ws.components:
        return cand

    if "." in mod_name:
        parts = mod_name.split(".")
        for i in range(len(parts) - 1, 0, -1):
            parent = ".".join(parts[:i])
            pkg = ws.module_to_package.get(parent) or ws.module_to_package.get(parent.lower())
            if pkg:
                return pkg
            cand_parent = normalize_pkg_name(parent)
            if cand_parent in ws.components:
                return cand_parent

    if file_paths:
        for fpath in file_paths:
            clean_fp = fpath.split("!", 1)[-1].replace("\\", "/").lstrip("./")
            clean_fp = clean_fp.removeprefix("_internal/")
            dir_segs = [s for s in clean_fp.split("/")[:-1] if s and not _is_native_libs_dir_segment(s)]
            for seg in dir_segs:
                pkg = ws.module_to_package.get(seg) or ws.module_to_package.get(seg.lower())
                if pkg:
                    return pkg
                cand_seg = normalize_pkg_name(seg)
                if cand_seg in ws.components:
                    return cand_seg

    return None


def correlate_workspace_and_dist(
    ws: WorkspaceMetadata,
    dist_result: DistInspectionResult,
    include_dev: bool = False,
) -> tuple[list[Component], list[Component]]:
    """
    Correlate workspace dependencies with the discovered compiled distribution artefacts.
    Returns (active_bundled_components, excluded_dev_or_unbundled_components).
    """
    active: list[Component] = []
    excluded: list[Component] = []

    is_monolithic = dist_result.layout == DistributionLayout.MONOLITHIC_BINARY

    # Map bundled module names to normalised package names using workspace mapping
    matched_pkg_names: set[str] = set(dist_result.discovered_distributions.keys())
    pkg_bundled_files: dict[str, list[str]] = {}

    for mod_name in dist_result.bundled_modules:
        mod_files = dist_result.module_files.get(mod_name, [])
        pkg_name = _resolve_pkg_for_module(mod_name, ws, mod_files)
        if pkg_name:
            matched_pkg_names.add(pkg_name)
            for fpath in mod_files:
                flist = pkg_bundled_files.setdefault(pkg_name, [])
                if fpath not in flist:
                    flist.append(fpath)

    # 1. Process all packages known in the workspace
    for pname, ws_comp in sorted(ws.components.items()):
        if ws_comp.component_type != ComponentType.PYTHON_PACKAGE:
            continue
        in_dist = pname in matched_pkg_names and (include_dev or pname not in BUILD_AND_DEV_TOOLS)
        if in_dist:
            ws_comp.is_bundled = True
            ws_comp.scope = ComponentScope.REQUIRED
            if pname in dist_result.discovered_distributions:
                dver = dist_result.discovered_distributions[pname]
                if dver != "unknown" and ws_comp.version == "unknown":
                    ws_comp.version = dver
                    ws_comp.refresh_purl()
            # Merge richer metadata and licence texts from bundled .dist-info in dist dir
            if pname in dist_result.dist_info_components:
                dcomp = dist_result.dist_info_components[pname]
                if ws_comp.license_info.spdx_id == "NOASSERTION" and dcomp.license_info.spdx_id != "NOASSERTION":
                    merged_texts = dict(dcomp.license_info.license_texts)
                    for k, v in ws_comp.license_info.license_texts.items():
                        merged_texts.setdefault(k, v)
                    merged_notices = dict(dcomp.license_info.notice_texts)
                    for k, v in ws_comp.license_info.notice_texts.items():
                        merged_notices.setdefault(k, v)
                    ws_comp.license_info = dcomp.license_info
                    ws_comp.license_info.license_texts = merged_texts
                    ws_comp.license_info.notice_texts = merged_notices
                else:
                    for k, text in dcomp.license_info.license_texts.items():
                        if k not in ws_comp.license_info.license_texts:
                            ws_comp.license_info.license_texts[k] = text
                    for k, text in dcomp.license_info.notice_texts.items():
                        if k not in ws_comp.license_info.notice_texts:
                            ws_comp.license_info.notice_texts[k] = text
                    for cp in dcomp.license_info.copyright_notices:
                        if cp not in ws_comp.license_info.copyright_notices:
                            ws_comp.license_info.copyright_notices.append(cp)
            ws_comp.bundled_files = pkg_bundled_files.get(pname, [])
            is_static_mod = any(
                m in dist_result.statically_compiled_modules for m in ws_comp.top_level_modules
            )
            ws_comp.is_statically_compiled = is_monolithic or is_static_mod
            ws_comp.has_dynamic_relinking = not is_monolithic and not is_static_mod
            ev_tag = f"bundled:{dist_result.bundler_type.value}"
            if ev_tag not in ws_comp.discovery_evidence:
                ws_comp.discovery_evidence.append(ev_tag)
            active.append(ws_comp)
        else:
            ws_comp.is_bundled = False
            ws_comp.scope = ComponentScope.DEV_EXCLUDED
            excluded.append(ws_comp)

    # 2. Include any packages discovered directly in the distribution that were not in the workspace
    for pname, dver in sorted(dist_result.discovered_distributions.items()):
        if pname in ws.components or (not include_dev and pname in BUILD_AND_DEV_TOOLS):
            continue
        if pname in dist_result.dist_info_components:
            comp = dist_result.dist_info_components[pname]
        else:
            comp = Component(
                name=pname,
                version=dver,
                component_type=ComponentType.PYTHON_PACKAGE,
                scope=ComponentScope.REQUIRED,
                ecosystem="PyPI",
                discovery_evidence=[f"dist:{dist_result.bundler_type.value}"],
            )
        comp.is_bundled = True
        comp.bundled_files = pkg_bundled_files.get(pname, [])
        comp.is_statically_compiled = is_monolithic
        comp.has_dynamic_relinking = not is_monolithic
        active.append(comp)

    # 3. Also check if any bundled_modules were not in workspace or discovered_distributions
    handled_modules: set[str] = set()
    for c in active:
        handled_modules.update(c.top_level_modules)
        handled_modules.add(c.name)
        handled_modules.add(c.name.replace("-", "_"))
        for mod, pkg in ws.module_to_package.items():
            if pkg == c.name:
                handled_modules.add(mod)
                handled_modules.add(mod.lower())

    for mod_name in sorted(dist_result.bundled_modules):
        if mod_name in handled_modules or mod_name in STDLIB_MODULES:
            continue
        mod_files = dist_result.module_files.get(mod_name, [])
        resolved_pkg = _resolve_pkg_for_module(mod_name, ws, mod_files)
        if resolved_pkg and any(c.name == resolved_pkg for c in active):
            for c in active:
                if c.name == resolved_pkg:
                    for fpath in mod_files:
                        if fpath not in c.bundled_files:
                            c.bundled_files.append(fpath)
            continue
        # Private underscore modules (_foo) are internal implementation modules, not packages
        if mod_name.startswith("_"):
            continue
        norm_mod = normalize_pkg_name(mod_name)
        if (not include_dev and norm_mod in BUILD_AND_DEV_TOOLS) or any(c.name == norm_mod for c in active):
            continue
        is_static_mod = mod_name in dist_result.statically_compiled_modules
        comp = Component(
            name=norm_mod,
            version="unknown",
            component_type=ComponentType.PYTHON_PACKAGE,
            scope=ComponentScope.REQUIRED,
            ecosystem="PyPI",
            top_level_modules=[mod_name],
            bundled_files=dist_result.module_files.get(mod_name, []),
            is_bundled=True,
            is_statically_compiled=is_monolithic or is_static_mod,
            has_dynamic_relinking=not is_monolithic and not is_static_mod,
            discovery_evidence=[f"bundled-module:{mod_name}"],
        )
        active.append(comp)

    # 4. Append all discovered native shared libraries
    for nat_comp in dist_result.native_components:
        if not nat_comp.origin_package:
            for pkg_name, lib_list in ws.package_libraries.items():
                if nat_comp.name in lib_list or any(nat_comp.name in Path(bf).name for bf in nat_comp.bundled_files):
                    nat_comp.origin_package = pkg_name
                    nat_comp.provenance = f"vendored-in-wheel:{pkg_name}"
                    break
            if not nat_comp.origin_package and nat_comp.name in ws.components:
                ws_nat = ws.components[nat_comp.name]
                if ws_nat.origin_package:
                    nat_comp.origin_package = ws_nat.origin_package
                    nat_comp.provenance = ws_nat.provenance
            if not nat_comp.origin_package:
                from rhada.elf import infer_binary_provenance

                cand_bf = nat_comp.bundled_files[0] if nat_comp.bundled_files else ""
                inf_pkg, inf_prov = infer_binary_provenance(cand_bf, nat_comp.name)
                if inf_pkg and any(c.name == inf_pkg for c in active):
                    nat_comp.origin_package = inf_pkg
                    nat_comp.provenance = inf_prov
        if nat_comp.name in ws.components:
            ws_nat = ws.components[nat_comp.name]
            if nat_comp.license_info.spdx_id == "NOASSERTION" and ws_nat.license_info.spdx_id != "NOASSERTION":
                nat_comp.license_info = ws_nat.license_info
        active.append(nat_comp)

    # Cross-reference linkage report binaries with workspace package_libraries
    if dist_result.linkage_report:
        for b in dist_result.linkage_report.binaries:
            if not b.origin_package:
                b_leaf = Path(b.path).name
                for pkg_name, lib_list in ws.package_libraries.items():
                    if b_leaf in lib_list or (b.detected_library_name and b.detected_library_name in lib_list):
                        b.origin_package = pkg_name
                        b.provenance = f"vendored-in-wheel:{pkg_name}"
                        dist_result.linkage_report.binary_origins[b.path] = pkg_name
                        if b_leaf not in dist_result.linkage_report.package_libraries.setdefault(pkg_name, []):
                            dist_result.linkage_report.package_libraries[pkg_name].append(b_leaf)
                        break
                if not b.origin_package:
                    from rhada.elf import infer_binary_provenance

                    inf_b_pkg, inf_b_prov = infer_binary_provenance(b.path, b_leaf)
                    if inf_b_pkg and any(c.name == inf_b_pkg for c in active):
                        b.origin_package = inf_b_pkg
                        b.provenance = inf_b_prov
                        dist_result.linkage_report.binary_origins[b.path] = inf_b_pkg
                        if b_leaf not in dist_result.linkage_report.package_libraries.setdefault(inf_b_pkg, []):
                            dist_result.linkage_report.package_libraries[inf_b_pkg].append(b_leaf)
        for issue in dist_result.linkage_report.issues:
            if not issue.origin_package and issue.binary_path in dist_result.linkage_report.binary_origins:
                issue.origin_package = dist_result.linkage_report.binary_origins[issue.binary_path]
                issue.provenance = f"vendored-in-wheel:{issue.origin_package}"

    return active, excluded
