"""ELF binary parser, native shared library identifier, and binary linkage verifier."""

from __future__ import annotations

import contextlib
import hashlib
import io
import re
import struct
from pathlib import Path

from rhada.models import (
    BinaryLinkageReport,
    Component,
    ComponentScope,
    ComponentType,
    ElfBinaryInfo,
    LicenseInfo,
    LinkageIssue,
    LinkageStatus,
    Severity,
)
from rhada.pe import (
    is_pe_bytes,
    is_pe_file,
    is_windows_compiler_runtime_dll,
    is_windows_msvc_runtime_dll,
    is_windows_system_dll,
    parse_pe_bytes,
)
from rhada.pe import (
    parse_pe_binary as parse_pe_binary,
)
from rhada.spdx import (
    KNOWN_LIBRARY_TO_PACKAGE,
    KNOWN_NATIVE_LIBRARIES,
    KNOWN_PYTHON_PACKAGES,
    MODULE_TO_KNOWN_PACKAGE,
    NativeLibraryProfile,
    classify_single_spdx,
)

try:
    from elftools.common.exceptions import ELFError
    from elftools.elf.dynamic import DynamicSection
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection

    HAS_PYELFTOOLS = True
except ImportError:  # pragma: no cover
    HAS_PYELFTOOLS = False
    ELFError = Exception  # type: ignore[misc,assignment]

ELF_MAGIC = b"\x7fELF"

# Standard Linux base system ABI libraries expected to be provided by the target OS
SYSTEM_ABI_PREFIXES = (
    "linux-vdso.so",
    "ld-linux",
    "ld-musl",
    "libc.so",
    "libm.so",
    "libdl.so",
    "libpthread.so",
    "librt.so",
    "libutil.so",
    "libresolv.so",
    "libnss_",
    "libnsl.so",
    "libcrypt.so",
    "libanl.so",
    "libBrokenLocale.so",
)

# Compiler runtime libraries commonly present on target systems (warn as LOW if not bundled)
COMPILER_RUNTIME_PREFIXES = (
    "libgcc_s.so",
    "libstdc++.so",
    "libgomp.so",
    "libatomic.so",
    "libgfortran.so",
    "libquadmath.so",
)

MACHINE_MAP: dict[int | str, str] = {
    "EM_X86_64": "x86_64",
    "EM_386": "x86",
    "EM_AARCH64": "aarch64",
    "EM_ARM": "arm",
    "EM_RISCV": "riscv",
    "EM_PPC64": "ppc64",
    "EM_S390": "s390x",
    62: "x86_64",
    3: "x86",
    183: "aarch64",
    40: "arm",
    243: "riscv",
    21: "ppc64",
    22: "s390x",
}

PRINTABLE_STR_RE = re.compile(rb"[\x20-\x7e]{4,200}")

# Version extraction patterns from binary strings and SONAMEs
VERSION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("openblas", re.compile(r"\bOpenBLAS\s+v?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("lapack", re.compile(r"\bLAPACK\s+(?:version\s+)?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("libgfortran", re.compile(r"\b(?:GNU\s+Fortran|GCC:)\s+(?:\([^)]*\)\s+)?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("fftw", re.compile(r"\bfftw-(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("qhull", re.compile(r"\bQhull\s+(\d{4}\.\d+(?:\.\d+)?|\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("openssl", re.compile(r"\bOpenSSL\s+(\d+\.\d+\.\d+[a-z0-9-]*)", re.IGNORECASE)),
    ("zlib", re.compile(r"(?:\bzlib\s+version\s+|\bdeflate\s+)(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("sqlite3", re.compile(r"\bSQLite\s+version\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("expat", re.compile(r"\bexpat_(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("xz", re.compile(r"\b(?:XZ\s+Utils|liblzma)\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("zstd", re.compile(r"\bzstd\s+v?(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("bzip2", re.compile(r"\bbzip2/libbzip2\s+version\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("libffi", re.compile(r"\blibffi\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("gmp", re.compile(r"\bGNU\s+MP\s+Library\s+version\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("mkl", re.compile(r"\bIntel(?:\(R\))?\s+(?:oneAPI\s+)?(?:Math\s+Kernel\s+Library|MKL)\s+(?:Version\s+)?(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("readline", re.compile(r"\bReadline\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("python", re.compile(r"\bPython\s+(\d+\.\d+\.\d+)", re.IGNORECASE)),
    ("libuuid", re.compile(r"\butil-linux\s+(\d+\.\d+(?:\.\d+)?)", re.IGNORECASE)),
    ("libuuid", re.compile(r"\bUUID_(\d+\.\d+)", re.IGNORECASE)),
]

SONAME_VERSION_RE = re.compile(r"^(lib[a-zA-Z0-9_+-]+?)(?:-(\d+(?:\.\d+)+))?\.so(?:\.(\d+(?:\.\d+)*))?$")
DLL_VERSION_RE = re.compile(r"^([a-zA-Z0-9_+]+?)(?:[-_.](\d+(?:[._]\d+)*))?\.dll$", re.IGNORECASE)

_SORTED_KNOWN_NATIVE_LIBS: list[tuple[str, NativeLibraryProfile]] = sorted(
    KNOWN_NATIVE_LIBRARIES.items(),
    key=lambda kv: len(kv[0]),
    reverse=True,
)


def is_elf_file(path: Path) -> bool:
    """Return True if path is a regular file starting with the 0x7fELF magic header."""
    try:
        if not path.is_file() or path.is_symlink():
            return False
        with path.open("rb") as f:
            magic = f.read(4)
        return magic == ELF_MAGIC
    except OSError:
        return False


def is_binary_file(path: Path) -> bool:
    """Return True if path is a regular ELF or Windows PE binary file."""
    return is_elf_file(path) or is_pe_file(path)


def normalize_pkg_name(name: str) -> str:
    """Normalise a Python package name per PEP 503."""
    if not name:
        return ""
    try:
        from packaging.utils import canonicalize_name

        return str(canonicalize_name(name))
    except (ValueError, TypeError):
        return re.sub(r"[-_.]+", "-", name).lower().strip("-")


SYSTEM_GENERIC_SEGMENTS: frozenset[str] = frozenset({
    "bin",
    "scripts",
    "include",
    "share",
    "__pycache__",
    "lib",
    "lib64",
    "lib32",
    "usr",
    "etc",
    "var",
    "opt",
    "dist",
    "build",
    "windows",
    "system32",
    "syswow64",
    "home",
    "users",
    "user",
    "root",
    "tmp",
    "temp",
    "appdata",
    "local",
    "roaming",
    "program files",
    "program files (x86)",
    "mnt",
    "media",
    "srv",
    "run",
    "dev",
    "target",
    "release",
    "debug",
    "output",
    "artifacts",
    "deploy",
    "out",
    "venv",
    ".venv",
    "env",
    ".env",
    "virtualenvs",
})


def infer_binary_provenance(
    path_str: str,
    file_name: str | None = None,
    *,
    is_system: bool = False,
    is_compiler_runtime: bool = False,
    bundler: str | None = None,
) -> tuple[str | None, str]:
    """
    Determine the origin Python package and provenance string for a binary (.so or .dll).
    Returns (origin_package, provenance).
    """
    fname = file_name or Path(path_str.replace("\\", "/")).name
    f_lower = fname.lower()
    is_win = f_lower.endswith((".dll", ".drv", ".ocx")) or is_windows_system_dll(fname)

    if is_system or is_system_abi_lib(fname):
        return None, "system-abi:windows" if is_win else "system-abi:linux"

    clean_p = path_str.replace("\\", "/").strip().lstrip("./")
    if "!" in clean_p:
        clean_p = clean_p.split("!", 1)[-1].lstrip("./")

    segments = [s for s in clean_p.split("/") if s and s != "."]

    # 1. Delvewheel load order token (.load-order-<pkg>-<version>)
    for token in (fname, *segments):
        if token.startswith(".load-order-"):
            stem = token.removeprefix(".load-order-")
            raw_pkg = stem.split("-", 1)[0]
            norm_pkg = normalize_pkg_name(raw_pkg)
            if norm_pkg:
                return norm_pkg, f"vendored-in-wheel:{norm_pkg}"

    dir_segs = segments[:-1] if len(segments) > 1 else []

    # 2. Check directory segments for dedicated vendor folders (<pkg>.libs, <pkg>.dylibs, or nested vendor dirs)
    for idx, seg in enumerate(dir_segs):
        seg_lower = seg.lower()
        if seg_lower.endswith((".libs", ".dylibs")):
            raw_pkg = seg.rsplit(".", 1)[0]
            norm_pkg = normalize_pkg_name(raw_pkg)
            norm_pkg = MODULE_TO_KNOWN_PACKAGE.get(norm_pkg.lower(), norm_pkg)
            if norm_pkg:
                return norm_pkg, f"vendored-in-wheel:{norm_pkg}"
        if seg_lower in {".libs", "extra-dll", ".dylibs", "libs", "_libs", "dlls", "lib"} and idx > 0:
            cand_prev = dir_segs[idx - 1]
            cand_lower = cand_prev.lower()
            if cand_lower not in SYSTEM_GENERIC_SEGMENTS and not (len(cand_prev) == 2 and cand_prev[1] == ":"):
                norm_pkg = normalize_pkg_name(cand_prev)
                norm_pkg = MODULE_TO_KNOWN_PACKAGE.get(norm_pkg.lower(), norm_pkg)
                if norm_pkg:
                    return norm_pkg, f"vendored-in-wheel:{norm_pkg}"

    # 3. Standard layout markers: site-packages, dist-packages, _internal, src
    dir_segs_lower = [s.lower() for s in dir_segs]
    for marker in ("site-packages", "dist-packages", "_internal", "src"):
        if marker in dir_segs_lower:
            m_idx = dir_segs_lower.index(marker)
            if m_idx + 1 < len(dir_segs):
                cand_seg = dir_segs[m_idx + 1]
                cand_lower = cand_seg.lower()
                if cand_lower not in SYSTEM_GENERIC_SEGMENTS:
                    raw_cand = cand_seg.removesuffix(".dist-info")
                    if raw_cand.lower().endswith((".libs", ".dylibs")):
                        raw_cand = raw_cand.rsplit(".", 1)[0]
                    norm_pkg = normalize_pkg_name(raw_cand)
                    norm_pkg = MODULE_TO_KNOWN_PACKAGE.get(norm_pkg.lower(), norm_pkg)
                    if norm_pkg:
                        return norm_pkg, f"vendored-in-wheel:{norm_pkg}"

    # 4. Check if any directory segment directly names a known Python package or module
    for seg in dir_segs:
        s_norm = normalize_pkg_name(seg.removesuffix(".dist-info").removesuffix(".libs").removesuffix(".dylibs"))
        s_lower = s_norm.lower()
        if s_lower in KNOWN_PYTHON_PACKAGES:
            mapped_pkg = MODULE_TO_KNOWN_PACKAGE.get(s_lower, s_lower)
            return mapped_pkg, f"vendored-in-wheel:{mapped_pkg}"
        if s_lower in MODULE_TO_KNOWN_PACKAGE:
            mapped_pkg = MODULE_TO_KNOWN_PACKAGE[s_lower]
            return mapped_pkg, f"vendored-in-wheel:{mapped_pkg}"

    # 5. Known native library fallback (when libraries are flattened in dist root without subdirectories)
    cleaned_fname = _strip_wheel_hashes_and_arch(fname)
    lib_stem = cleaned_fname.lower()
    for ext in (".dll", ".so"):
        if ext in lib_stem:
            lib_stem = lib_stem.split(ext, 1)[0]
    lib_stem = lib_stem.split("-", 1)[0].rstrip("_")

    if lib_stem in KNOWN_LIBRARY_TO_PACKAGE:
        known_pkg = KNOWN_LIBRARY_TO_PACKAGE[lib_stem]
        return known_pkg, f"vendored-in-wheel:{known_pkg}"
    if not lib_stem.startswith("lib") and f"lib{lib_stem}" in KNOWN_LIBRARY_TO_PACKAGE:
        known_pkg = KNOWN_LIBRARY_TO_PACKAGE[f"lib{lib_stem}"]
        return known_pkg, f"vendored-in-wheel:{known_pkg}"

    # 6. Relative non-absolute path check (e.g. "my_custom_package/sub/libcustom.so")
    is_abs = Path(path_str.replace("\\", "/")).is_absolute() or clean_p.startswith("/") or (len(segments) > 0 and len(segments[0]) == 2 and segments[0][1] == ":")
    if not is_abs and len(segments) > 1:
        first_seg = segments[0]
        if first_seg.lower() not in SYSTEM_GENERIC_SEGMENTS and not (len(first_seg) == 2 and first_seg[1] == ":"):
            norm_pkg = normalize_pkg_name(first_seg.removesuffix(".dist-info").removesuffix(".libs").removesuffix(".dylibs"))
            if norm_pkg and norm_pkg.replace("-", "_").isidentifier():
                return norm_pkg, f"vendored-in-wheel:{norm_pkg}"

    # 7. Host system compiler runtimes
    if is_compiler_runtime or is_compiler_runtime_lib(fname):
        return None, "system-abi:windows" if is_win else "system-abi:linux"

    if bundler:
        return None, f"bundled-by-build-tool:{bundler}"
    return None, "standalone-binary"


def is_system_abi_lib(lib_name: str) -> bool:
    """Return True if a library name belongs to the base Linux/glibc or Windows OS/UCRT ABI."""
    base = Path(lib_name.replace("\\", "/")).name
    if base.startswith(SYSTEM_ABI_PREFIXES):
        return True
    return is_windows_system_dll(base)


def is_compiler_runtime_lib(lib_name: str) -> bool:
    """Return True if a library is a standard GCC/C++/Fortran or MSVC/MinGW runtime library."""
    base = Path(lib_name.replace("\\", "/")).name
    if base.startswith(COMPILER_RUNTIME_PREFIXES):
        return True
    return is_windows_compiler_runtime_dll(base)


def extract_printable_strings(data: bytes, limit: int = 2000) -> list[str]:
    """Extract ASCII printable strings from raw binary bytes."""
    results: list[str] = []
    for match in PRINTABLE_STR_RE.finditer(data):
        s = match.group(0).decode("ascii", errors="ignore").strip()
        if s:
            results.append(s)
            if len(results) >= limit:
                break
    return results


def _strip_wheel_hashes_and_arch(name: str) -> str:
    """Strip auditwheel/delvewheel hash suffixes and Windows arch tags from a shared library filename."""
    cleaned = re.sub(r"-r0-[0-9a-f]{6,32}", "", name, flags=re.IGNORECASE)
    cleaned = re.sub(r"(?:-[0-9a-f]{6,32})+(?=\.(?:so|dll)\b)", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"-(?:x64|x86|win64|win32|amd64|arm64)(?=\.dll\b)", "", cleaned, flags=re.IGNORECASE)
    return cleaned


def _match_known_native_profile(lib_key: str) -> NativeLibraryProfile | None:
    """Match a library key against KNOWN_NATIVE_LIBRARIES (longest prefix first, with or without 'lib')."""
    key_clean = lib_key.lower().rstrip("_")
    candidates = [key_clean]
    if not key_clean.startswith("lib"):
        candidates.append(f"lib{key_clean}")
    for cand in candidates:
        for prefix, profile in _SORTED_KNOWN_NATIVE_LIBS:
            if cand == prefix:
                return profile
            if cand.startswith(prefix) and len(cand) > len(prefix) and cand[len(prefix)] in "-_.0123456789":
                return profile
    return None


def _infer_library_identity(
    filename: str,
    soname: str | None,
    strings_list: list[str],
) -> tuple[str | None, str | None]:
    """Infer canonical library name and version from SONAME, filename, and embedded strings."""
    target_name = soname or filename
    base_name = Path(target_name.replace("\\", "/")).name

    # Strip PyInstaller/auditwheel/delvewheel hash suffixes and Windows arch suffixes
    cleaned_base = _strip_wheel_hashes_and_arch(base_name)

    detected_lib: str | None = None
    detected_ver: str | None = None

    # Special pattern for OpenBLAS auditwheel builds: libopenblas64_p-r0-0cf96a72.3.23.dev.so
    ob_m = re.match(
        r"^(libopenblas[a-z0-9_]*?)\.(\d+\.\d+(?:\.\d+)?)(?:\.[a-z0-9]+)?\.(?:so|dll)$",
        cleaned_base,
        re.IGNORECASE,
    )
    if ob_m:
        detected_lib = "libopenblas"
        ver_raw = ob_m.group(2)
        detected_ver = f"0.{ver_raw}" if ver_raw.count(".") == 1 and not ver_raw.startswith("0.") else ver_raw

    if not detected_lib:
        m = SONAME_VERSION_RE.match(cleaned_base)
        if m:
            prefix = m.group(1).rstrip("_")
            ver_inline = m.group(2)
            ver_suffix = m.group(3)
            detected_lib = prefix.lower()
            cand_ver = ver_inline or ver_suffix
            if (
                cand_ver
                and cand_ver not in {"0.0.0", "0.0", "0"}
                and (ver_inline or (ver_suffix and "." in ver_suffix))
            ):
                detected_ver = cand_ver

    if not detected_lib:
        # Handle libpython3.11.so.1.0 or Windows python312.dll / python3.dll
        py_m = re.match(r"^(?:lib)?python(\d+\.\d+).*\.(?:so|dll)", cleaned_base, re.IGNORECASE)
        if py_m:
            detected_lib = "libpython"
            detected_ver = py_m.group(1)
        else:
            py_win_m = re.match(r"^(?:lib)?python(\d)(\d{1,2})?\.dll$", cleaned_base, re.IGNORECASE)
            if py_win_m:
                detected_lib = "libpython"
                detected_ver = f"{py_win_m.group(1)}.{py_win_m.group(2)}" if py_win_m.group(2) else py_win_m.group(1)
            elif cleaned_base.lower().endswith(".dll"):
                # Handle Windows DLLs (e.g., libssl-3.dll, libgfortran-5.dll, zlib1.dll, sqlite3.dll)
                if re.match(r"^zlib\d+\.dll$", cleaned_base, re.IGNORECASE):
                    detected_lib = "zlib"
                    detected_ver = re.sub(r"[^0-9.]", "", cleaned_base)
                elif cleaned_base.lower() == "sqlite3.dll":
                    detected_lib = "sqlite3"
                else:
                    dll_m = DLL_VERSION_RE.match(cleaned_base)
                    if dll_m:
                        detected_lib = dll_m.group(1).lower().rstrip("_")
                        if dll_m.group(2):
                            cand_ver = dll_m.group(2).replace("_", ".")
                            if cand_ver not in {"0.0.0", "0.0", "0"}:
                                detected_ver = cand_ver
            elif cleaned_base.startswith("lib") and ".so" in cleaned_base:
                detected_lib = cleaned_base.split(".so", 1)[0].split("-", 1)[0].lower().rstrip("_")

    matched_profile = _match_known_native_profile(detected_lib) if detected_lib else None

    # Check embedded strings for precise version numbers
    joined_strings = "\n".join(strings_list)
    for canonical, pattern in VERSION_PATTERNS:
        vm = pattern.search(joined_strings)
        if vm:
            ver_found = vm.group(1)
            if matched_profile and canonical in matched_profile.canonical_name:
                detected_ver = ver_found
                break
            if detected_lib and canonical in detected_lib:
                detected_ver = ver_found
                break
            if detected_lib is None:
                detected_lib = f"lib{canonical}" if not canonical.startswith("lib") else canonical
                matched_profile = _match_known_native_profile(detected_lib)
                detected_ver = ver_found
                break

    if matched_profile:
        return matched_profile.canonical_name, detected_ver or "unknown"

    return detected_lib, detected_ver


def _empty_profile(name: str) -> NativeLibraryProfile:
    return NativeLibraryProfile(name, "NOASSERTION", "", "", "")


def _parse_elf_struct_fallback(data: bytes, path_str: str, sha256: str) -> ElfBinaryInfo:
    """Pure-Python struct parser fallback for ELF headers and program headers."""
    if len(data) < 52 or data[:4] != ELF_MAGIC:
        raise ValueError(f"Not a valid ELF binary: {path_str}")

    ei_class = data[4]
    ei_data = data[5]
    bits = 64 if ei_class == 2 else 32
    endian = "<" if ei_data == 1 else ">"
    endian_name = "little" if ei_data == 1 else "big"

    e_type, e_machine = struct.unpack_from(f"{endian}HH", data, 16)
    arch = MACHINE_MAP.get(e_machine, f"unknown({e_machine})")
    is_exec = e_type == 2  # ET_EXEC
    is_dyn = e_type == 3   # ET_DYN

    # Parse Program Headers to locate PT_DYNAMIC (2) and PT_INTERP (3)
    has_dynamic = False
    interpreter: str | None = None
    if bits == 64 and len(data) >= 64:
        e_phoff, _, _, _, e_phentsize, e_phnum, _, _ = struct.unpack_from(f"{endian}QQQIHHHH", data, 32)
        for i in range(min(e_phnum, 128)):
            off = e_phoff + i * e_phentsize
            if off + 56 > len(data):
                break
            p_type, _, p_offset, _, _, p_filesz, _, _ = struct.unpack_from(f"{endian}IIQQQQQQ", data, off)
            if p_type == 2:  # PT_DYNAMIC
                has_dynamic = True
            elif p_type == 3 and p_offset + p_filesz <= len(data):  # PT_INTERP
                raw_interp = data[p_offset : p_offset + p_filesz].split(b"\x00", 1)[0]
                interpreter = raw_interp.decode("utf-8", errors="replace")
    elif bits == 32 and len(data) >= 52:
        e_phoff, _, _, _, e_phentsize, e_phnum, _, _ = struct.unpack_from(f"{endian}IIIIHHHH", data, 28)
        for i in range(min(e_phnum, 128)):
            off = e_phoff + i * e_phentsize
            if off + 32 > len(data):
                break
            p_type, p_offset, _, _, p_filesz, _, _, _ = struct.unpack_from(f"{endian}IIIIIIII", data, off)
            if p_type == 2:
                has_dynamic = True
            elif p_type == 3 and p_offset + p_filesz <= len(data):
                raw_interp = data[p_offset : p_offset + p_filesz].split(b"\x00", 1)[0]
                interpreter = raw_interp.decode("utf-8", errors="replace")

    strings_sample = extract_printable_strings(data, limit=1500)
    leaf_name = Path(path_str.replace("\\", "/")).name
    needed_libs: list[str] = []
    soname: str | None = None
    for s in strings_sample:
        if SONAME_VERSION_RE.match(s) and s != leaf_name and s not in needed_libs:
            needed_libs.append(s)
    lib_name, lib_ver = _infer_library_identity(leaf_name, soname, strings_sample)

    origin_pkg = None
    prov = ""
    if path_str != "<memory>":
        origin_pkg, prov = infer_binary_provenance(path_str, leaf_name)

    matched_profile = _match_known_native_profile(lib_name) if lib_name else None
    lic_spdx = matched_profile.spdx_id if matched_profile else "NOASSERTION"
    cop_notice = matched_profile.copyright_notice if matched_profile else ""

    return ElfBinaryInfo(
        path=path_str,
        soname=soname,
        needed_libs=needed_libs,
        architecture=arch,
        bits=bits,
        endianness=endian_name,
        is_executable=is_exec or (is_dyn and interpreter is not None),
        is_shared_object=is_dyn and interpreter is None,
        is_statically_linked=not has_dynamic and interpreter is None,
        interpreter=interpreter,
        detected_library_name=lib_name,
        detected_version=lib_ver,
        ident_strings=strings_sample[:50],
        sha256=sha256,
        origin_package=origin_pkg,
        provenance=prov,
        license_spdx=lic_spdx,
        copyright=cop_notice,
    )


def parse_binary(path: Path) -> ElfBinaryInfo:
    """Parse either an ELF or Windows PE binary from disk."""
    raw_bytes = path.read_bytes()
    if raw_bytes[:4] == ELF_MAGIC:
        return parse_elf_bytes(raw_bytes, str(path))
    if is_pe_bytes(raw_bytes):
        return parse_pe_bytes(raw_bytes, str(path))
    raise ValueError(f"Not a valid ELF or PE binary: {path}")


def parse_elf_binary(path: Path) -> ElfBinaryInfo:
    """
    Parse an ELF binary (.so or executable) to extract DT_NEEDED, DT_SONAME,
    RPATH/RUNPATH, architecture, exported symbols, and library version metadata.
    Uses pyelftools with a pure-Python struct fallback for resilience.
    """
    raw_bytes = path.read_bytes()
    return parse_elf_bytes(raw_bytes, str(path))


def parse_elf_bytes(raw_bytes: bytes, path_str: str = "<memory>") -> ElfBinaryInfo:
    """Parse ELF metadata directly from in-memory bytes."""
    if len(raw_bytes) < 16 or raw_bytes[:4] != ELF_MAGIC:
        raise ValueError(f"Not an ELF file: {path_str}")

    sha256 = hashlib.sha256(raw_bytes).hexdigest()

    if not HAS_PYELFTOOLS:
        return _parse_elf_struct_fallback(raw_bytes, path_str, sha256)

    try:
        stream = io.BytesIO(raw_bytes)
        elffile = ELFFile(stream)

        arch_raw = elffile.header.get("e_machine", "unknown")
        arch = MACHINE_MAP.get(arch_raw, str(arch_raw))
        bits = elffile.elfclass
        endian_name = "little" if elffile.little_endian else "big"
        e_type = elffile.header.get("e_type", "")

        interpreter: str | None = None
        has_dynamic_segment = False
        for segment in elffile.iter_segments():
            seg_type = segment.header.get("p_type")
            if seg_type == "PT_INTERP":
                with contextlib.suppress(ELFError, KeyError, OSError, UnicodeDecodeError):
                    interpreter = segment.get_interp_name()
            elif seg_type == "PT_DYNAMIC":
                has_dynamic_segment = True

        soname: str | None = None
        needed_libs: list[str] = []
        rpath: str | None = None
        runpath: str | None = None
        priority_symbols: list[str] = []
        other_symbols: list[str] = []
        ident_strings: list[str] = []

        for section in elffile.iter_sections():
            if isinstance(section, DynamicSection):
                has_dynamic_segment = True
                for tag in section.iter_tags():
                    d_tag = tag.entry.d_tag
                    if d_tag == "DT_NEEDED":
                        val = getattr(tag, "needed", None)
                        if val and val not in needed_libs:
                            needed_libs.append(str(val))
                    elif d_tag == "DT_SONAME":
                        soname = str(getattr(tag, "soname", "")) or None
                    elif d_tag == "DT_RPATH":
                        rpath = str(getattr(tag, "rpath", "")) or None
                    elif d_tag == "DT_RUNPATH":
                        runpath = str(getattr(tag, "runpath", "")) or None

            elif isinstance(section, SymbolTableSection):
                for sym in section.iter_symbols():
                    sname = sym.name
                    if not sname:
                        continue
                    bind = sym.entry.get("st_info", {}).get("bind", "")
                    shndx = sym.entry.get("st_shndx", "SHN_UNDEF")
                    if bind in ("STB_GLOBAL", "STB_WEAK") and shndx != "SHN_UNDEF":
                        if sname.startswith(("PyInit_", "modulecode_")):
                            priority_symbols.append(sname)
                        elif sname.startswith(("Py_", "_Py")) or len(other_symbols) < 120:
                            other_symbols.append(sname)

            elif section.name in (".comment", ".rodata", ".dynstr"):
                with contextlib.suppress(ELFError, OSError):
                    sec_data = section.data()
                    for s in extract_printable_strings(sec_data, limit=400):
                        if len(ident_strings) < 600:
                            ident_strings.append(s)

        exported_symbols = priority_symbols + other_symbols
        if not ident_strings:
            ident_strings = extract_printable_strings(raw_bytes, limit=600)

        is_exec = e_type == "ET_EXEC" or (e_type == "ET_DYN" and interpreter is not None)
        is_shared = e_type == "ET_DYN" and interpreter is None
        is_static = not has_dynamic_segment and interpreter is None and len(needed_libs) == 0

        leaf_name = Path(path_str.replace("\\", "/")).name
        lib_name, lib_ver = _infer_library_identity(leaf_name, soname, ident_strings)

        origin_pkg = None
        prov = ""
        if path_str != "<memory>":
            origin_pkg, prov = infer_binary_provenance(path_str, leaf_name)

        matched_profile = _match_known_native_profile(lib_name) if lib_name else None
        lic_spdx = matched_profile.spdx_id if matched_profile else "NOASSERTION"
        cop_notice = matched_profile.copyright_notice if matched_profile else ""

        return ElfBinaryInfo(
            path=path_str,
            soname=soname,
            needed_libs=needed_libs,
            rpath=rpath,
            runpath=runpath,
            architecture=arch,
            bits=bits,
            endianness=endian_name,
            is_executable=is_exec,
            is_shared_object=is_shared,
            is_statically_linked=is_static,
            interpreter=interpreter,
            detected_library_name=lib_name,
            detected_version=lib_ver,
            exported_symbols_sample=exported_symbols[:150],
            ident_strings=ident_strings[:80],
            sha256=sha256,
            binary_format="ELF",
            origin_package=origin_pkg,
            provenance=prov,
            license_spdx=lic_spdx,
            copyright=cop_notice,
        )
    except (ELFError, struct.error, KeyError, IndexError, ValueError, OSError):
        return _parse_elf_struct_fallback(raw_bytes, path_str, sha256)


def _check_insecure_rpath(rpath_value: str | None) -> list[str]:
    """Identify insecure or non-portable RPATH/RUNPATH tokens (e.g., build host paths, /tmp, empty token)."""
    if not rpath_value:
        return []
    issues: list[str] = []
    tokens = rpath_value.split(":")
    for tok in tokens:
        stripped = tok.strip()
        if stripped == "" or stripped == ".":
            issues.append(f"Insecure current-directory RPATH token '{tok}' in '{rpath_value}'")
        elif stripped.startswith(("/tmp", "/var/tmp", "/home/", "/root/", "/build/", "/Users/")):
            issues.append(f"Build-host or world-writable RPATH token '{stripped}'")
        elif not stripped.startswith(("$ORIGIN", "${ORIGIN}", "@loader_path", "/lib", "/usr/lib")):
            issues.append(f"Non-portable RPATH token '{stripped}'")
    return issues


def _index_bundled_library_aliases(bundled_index: dict[str, str], fname: str, path_str: str) -> None:
    """Register exact, lowercase, and wheel-hash-stripped aliases for a bundled shared library."""
    bundled_index.setdefault(fname, path_str)
    bundled_index.setdefault(fname.lower(), path_str)
    cleaned = _strip_wheel_hashes_and_arch(fname)
    if cleaned != fname:
        bundled_index.setdefault(cleaned, path_str)
        bundled_index.setdefault(cleaned.lower(), path_str)
        if "_." in cleaned:
            no_us = cleaned.replace("_.", ".")
            bundled_index.setdefault(no_us, path_str)
            bundled_index.setdefault(no_us.lower(), path_str)
    so_match = re.match(r"^(lib[a-zA-Z0-9_+-]+?)(?:_)?\.so(?:\.(\d+))?", cleaned)
    if so_match:
        base_so = f"{so_match.group(1)}.so"
        bundled_index.setdefault(base_so, path_str)
        if so_match.group(2):
            ver_so = f"{so_match.group(1)}.so.{so_match.group(2)}"
            bundled_index.setdefault(ver_so, path_str)
    dll_match = re.match(r"^([a-zA-Z0-9_+]+?)(?:[-_.](\d+(?:[._]\d+)*))?\.dll$", cleaned, re.IGNORECASE)
    if dll_match:
        base_dll = f"{dll_match.group(1)}.dll"
        bundled_index.setdefault(base_dll, path_str)
        bundled_index.setdefault(base_dll.lower(), path_str)
        if base_dll.lower().startswith("lib"):
            no_lib_dll = f"{base_dll[3:]}"
            bundled_index.setdefault(no_lib_dll, path_str)
            bundled_index.setdefault(no_lib_dll.lower(), path_str)


def verify_binary_linkage(
    elf_binaries: list[ElfBinaryInfo],
    dist_root: Path | None = None,
) -> BinaryLinkageReport:
    """
    Verify binary linkage across all discovered ELF and Windows PE files in a distribution.
    Checks whether needed shared libraries (.so / .dll) are bundled inside the distribution,
    satisfied by the standard Linux or Windows system ABI, or missing external dependencies.
    Accurately tracks origin Python package and provenance for every library.
    """
    report = BinaryLinkageReport(elf_binaries=list(elf_binaries))

    bundled_index: dict[str, str] = {}
    bundled_binary_map: dict[str, ElfBinaryInfo] = {}

    for b in elf_binaries:
        fname = Path(b.path.replace("\\", "/")).name
        _index_bundled_library_aliases(bundled_index, fname, b.path)
        bundled_binary_map.setdefault(fname, b)
        bundled_binary_map.setdefault(fname.lower(), b)
        cleaned_f = _strip_wheel_hashes_and_arch(fname)
        bundled_binary_map.setdefault(cleaned_f, b)
        bundled_binary_map.setdefault(cleaned_f.lower(), b)
        if b.soname:
            _index_bundled_library_aliases(bundled_index, b.soname, b.path)
            bundled_binary_map.setdefault(b.soname, b)
            bundled_binary_map.setdefault(b.soname.lower(), b)

        # Track provenance of the binary itself
        b_origin = b.origin_package
        b_prov = b.provenance
        if not b_origin and not b_prov and b.path != "<memory>":
            b_origin, b_prov = infer_binary_provenance(b.path, fname)
            b.origin_package = b_origin
            b.provenance = b_prov
        if b_origin:
            report.binary_origins.setdefault(fname, b_origin)
            report.binary_origins.setdefault(b.path, b_origin)
            if b.soname:
                report.binary_origins.setdefault(b.soname, b_origin)
            report.package_libraries.setdefault(b_origin, [])
            if fname not in report.package_libraries[b_origin]:
                report.package_libraries[b_origin].append(fname)
            if b.soname and b.soname not in report.package_libraries[b_origin]:
                report.package_libraries[b_origin].append(b.soname)
        elif b_prov:
            report.binary_origins.setdefault(fname, b_prov)
            report.binary_origins.setdefault(b.path, b_prov)
            if b.soname:
                report.binary_origins.setdefault(b.soname, b_prov)

    if dist_root and dist_root.is_dir():
        for pat in ("*.so*", "*.dll", "*.pyd"):
            for sh_file in dist_root.rglob(pat):
                if sh_file.is_file():
                    _index_bundled_library_aliases(bundled_index, sh_file.name, str(sh_file))
                    sh_orig, sh_prov = infer_binary_provenance(str(sh_file), sh_file.name)
                    if sh_orig:
                        report.binary_origins.setdefault(sh_file.name, sh_orig)
                        report.binary_origins.setdefault(str(sh_file), sh_orig)
                        report.package_libraries.setdefault(sh_orig, [])
                        if sh_file.name not in report.package_libraries[sh_orig]:
                            report.package_libraries[sh_orig].append(sh_file.name)
                    elif sh_prov:
                        report.binary_origins.setdefault(sh_file.name, sh_prov)
                        report.binary_origins.setdefault(str(sh_file), sh_prov)

    seen_system_abi: set[str] = set()
    seen_system_abi_lower: set[str] = set()
    seen_unresolved: set[str] = set()
    seen_unresolved_lower: set[str] = set()
    seen_insecure_rpath: set[str] = set()

    for b in elf_binaries:
        # Check RPATH / RUNPATH hygiene (applicable to ELF binaries)
        for rpath_val in (b.rpath, b.runpath):
            for issue_msg in _check_insecure_rpath(rpath_val):
                if issue_msg not in seen_insecure_rpath:
                    seen_insecure_rpath.add(issue_msg)
                    report.insecure_rpaths.append(issue_msg)
                report.linkage_issues.append(
                    LinkageIssue(
                        binary_path=b.path,
                        needed_lib=rpath_val or "",
                        status=LinkageStatus.MISSING_EXTERNAL,
                        severity=Severity.MEDIUM,
                        message=issue_msg,
                        origin_package=b.origin_package,
                        provenance=b.provenance or "insecure-rpath",
                    )
                )

        if b.is_statically_linked:
            report.linkage_issues.append(
                LinkageIssue(
                    binary_path=b.path,
                    needed_lib="<static>",
                    status=LinkageStatus.STATIC,
                    severity=Severity.NONE,
                    message=f"Statically linked {b.binary_format} binary (no dynamic dependencies).",
                    origin_package=b.origin_package,
                    provenance=b.provenance or "static",
                )
            )
            continue

        for needed in b.needed_libs:
            needed_name = Path(needed.replace("\\", "/")).name
            # 1. Check if bundled inside the distribution (exact or case-insensitive for PE DLLs)
            resolved = bundled_index.get(needed_name) or bundled_index.get(needed_name.lower())
            if not resolved:
                cleaned_needed = _strip_wheel_hashes_and_arch(needed_name)
                resolved = bundled_index.get(cleaned_needed) or bundled_index.get(cleaned_needed.lower())
            if not resolved and needed_name.lower().endswith(".dll"):
                # Try without or with 'lib' prefix for Windows DLLs
                if needed_name.lower().startswith("lib"):
                    no_lib = needed_name[3:]
                    resolved = bundled_index.get(no_lib) or bundled_index.get(no_lib.lower())
                else:
                    with_lib = f"lib{needed_name}"
                    resolved = bundled_index.get(with_lib) or bundled_index.get(with_lib.lower())
                if not resolved:
                    # Match base DLL name without dotted or hyphenated version (e.g. mkl_rt.2.dll -> mkl_rt.dll)
                    dll_v_match = DLL_VERSION_RE.match(needed_name)
                    if dll_v_match and dll_v_match.group(2):
                        base_cand = f"{dll_v_match.group(1)}.dll"
                        resolved = bundled_index.get(base_cand) or bundled_index.get(base_cand.lower())
                        if not resolved and base_cand.lower().startswith("lib"):
                            no_lib_cand = base_cand[3:]
                            resolved = bundled_index.get(no_lib_cand) or bundled_index.get(no_lib_cand.lower())
            if not resolved:
                # Prefix match for versioned SONAMEs (e.g., libcrypto.so.3 vs libcrypto.so.3.0.2)
                stem_match = re.match(r"^(lib[a-zA-Z0-9_+-]+\.so(?:\.\d+)?)", needed_name)
                if stem_match:
                    resolved = bundled_index.get(stem_match.group(1))

            if resolved:
                report.resolved_dependencies[needed_name] = resolved
                matched_b = (
                    bundled_binary_map.get(needed_name)
                    or bundled_binary_map.get(needed_name.lower())
                    or (bundled_binary_map.get(Path(resolved.replace("\\", "/")).name))
                )
                iss_orig = matched_b.origin_package if matched_b else None
                iss_prov = matched_b.provenance if matched_b else ""
                if not iss_orig and not iss_prov:
                    iss_orig, iss_prov = infer_binary_provenance(resolved, needed_name)
                if not iss_prov:
                    iss_prov = f"vendored-in-wheel:{iss_orig}" if iss_orig else "bundled-by-build-tool"

                if iss_orig:
                    report.binary_origins.setdefault(needed_name, iss_orig)
                    report.package_libraries.setdefault(iss_orig, [])
                    if needed_name not in report.package_libraries[iss_orig]:
                        report.package_libraries[iss_orig].append(needed_name)
                else:
                    report.binary_origins.setdefault(needed_name, iss_prov)

                resolved_target_name = Path(resolved.replace("\\", "/")).name
                report.linkage_issues.append(
                    LinkageIssue(
                        binary_path=b.path,
                        needed_lib=needed_name,
                        status=LinkageStatus.BUNDLED,
                        severity=Severity.NONE,
                        message=f"Resolved within distribution at {resolved_target_name}",
                        resolved_path=resolved,
                        origin_package=iss_orig,
                        provenance=iss_prov,
                    )
                )
            elif is_system_abi_lib(needed_name):
                n_lower = needed_name.lower()
                is_win = n_lower.endswith((".dll", ".drv", ".ocx")) or is_windows_system_dll(needed_name)
                sys_prov = "system-abi:windows" if is_win else "system-abi:linux"
                report.binary_origins.setdefault(needed_name, sys_prov)
                if n_lower not in seen_system_abi_lower:
                    seen_system_abi_lower.add(n_lower)
                    seen_system_abi.add(needed_name)
                    report.system_abi_dependencies.append(needed_name)
                report.linkage_issues.append(
                    LinkageIssue(
                        binary_path=b.path,
                        needed_lib=needed_name,
                        status=LinkageStatus.SYSTEM_ABI,
                        severity=Severity.NONE,
                        message=f"Standard host OS / system ABI library ({needed_name})",
                        origin_package=None,
                        provenance=sys_prov,
                    )
                )
            elif is_compiler_runtime_lib(needed_name):
                n_lower = needed_name.lower()
                is_win = n_lower.endswith((".dll", ".drv", ".ocx")) or is_windows_compiler_runtime_dll(needed_name)
                comp_prov = "system-abi:windows" if is_win else "system-abi:linux"
                report.binary_origins.setdefault(needed_name, comp_prov)
                if n_lower not in seen_system_abi_lower:
                    seen_system_abi_lower.add(n_lower)
                    seen_system_abi.add(needed_name)
                    report.system_abi_dependencies.append(needed_name)
                report.linkage_issues.append(
                    LinkageIssue(
                        binary_path=b.path,
                        needed_lib=needed_name,
                        status=LinkageStatus.SYSTEM_ABI,
                        severity=Severity.LOW,
                        message=(
                            f"Compiler runtime library ({needed_name}) relies on target host; "
                            "ensure target OS / C++ / Fortran runtime ABI version is compatible."
                        ),
                        origin_package=None,
                        provenance=comp_prov,
                    )
                )
            else:
                n_lower = needed_name.lower()
                report.binary_origins.setdefault(needed_name, "missing-external")
                if n_lower not in seen_unresolved_lower:
                    seen_unresolved_lower.add(n_lower)
                    seen_unresolved.add(needed_name)
                    report.unresolved_dependencies.append(needed_name)
                binary_target_name = Path(b.path.replace("\\", "/")).name
                report.linkage_issues.append(
                    LinkageIssue(
                        binary_path=b.path,
                        needed_lib=needed_name,
                        status=LinkageStatus.MISSING_EXTERNAL,
                        severity=Severity.HIGH,
                        message=(
                            f"Unbundled external shared library '{needed_name}' required by "
                            f"'{binary_target_name}' is missing from distribution."
                        ),
                        origin_package=None,
                        provenance="missing-external",
                    )
                )

    return report


def elf_to_native_component(
    elf_info: ElfBinaryInfo,
    is_monolithic: bool = False,
    origin_package: str | None = None,
    provenance: str | None = None,
) -> Component | None:
    """
    Convert a non-Python native shared library ElfBinaryInfo (ELF .so or Windows PE .dll)
    into a Component with licence, copyright, hash, and provenance metadata.
    """
    fname = Path(elf_info.path.replace("\\", "/")).name
    fname_lower = fname.lower()
    # Skip Python C extension modules (.cpython-*.so, .abi3.so, .pyd) because they belong to a Python package
    if (
        ".cpython-" in fname_lower
        or ".abi3.so" in fname_lower
        or ".pypy" in fname_lower
        or fname_lower.endswith(".pyd")
        or bool(re.search(r"\.cp\d+-win", fname_lower))
        or fname.startswith("_")
        or any(s.startswith(("PyInit_", "_PyInit_")) for s in elf_info.exported_symbols_sample)
    ):
        return None
    # Skip OS system ABI and MSVC CRT redistributable libraries
    if is_system_abi_lib(fname) or is_windows_msvc_runtime_dll(fname):
        return None
    # Skip main executable unless it's a shared library
    if elf_info.is_executable and not (fname_lower.startswith("lib") or fname_lower.endswith(".dll")):
        return None
    if fname_lower.endswith(".exe"):
        return None

    target_label = elf_info.soname or fname
    cleaned_target = _strip_wheel_hashes_and_arch(Path(target_label.replace("\\", "/")).name)
    if cleaned_target.lower().endswith(".dll"):
        raw_base = cleaned_target[:-4]
    elif ".so" in cleaned_target:
        raw_base = cleaned_target.split(".so", 1)[0]
    else:
        raw_base = cleaned_target

    canonical_key = raw_base.lower().split("-", 1)[0].rstrip("_")
    if re.match(r"^(?:lib)?python\d+$", canonical_key):
        canonical_key = "libpython"
    elif re.match(r"^zlib\d+$", canonical_key):
        canonical_key = "zlib"

    profile = _match_known_native_profile(canonical_key)
    if profile is None and elf_info.detected_library_name:
        profile = _match_known_native_profile(elf_info.detected_library_name)

    lib_name = (
        profile.canonical_name
        if profile
        else (elf_info.detected_library_name or canonical_key or fname)
    )
    version = elf_info.detected_version or "unknown"

    if profile:
        lic_info = LicenseInfo(
            declared_raw=profile.spdx_id,
            spdx_id=profile.spdx_id,
            risk_category=classify_single_spdx(profile.spdx_id),
            copyright_notices=[profile.copyright_notice],
            license_texts={"EMBEDDED_NATIVE_LICENSE": profile.license_text},
        )
        homepage = profile.homepage
        source_url = getattr(profile, "source_url", "") or homepage
    else:
        lic_info = LicenseInfo(
            declared_raw="UNKNOWN",
            spdx_id="NOASSERTION",
            risk_category=classify_single_spdx("NOASSERTION"),
        )
        homepage = ""
        source_url = ""

    is_pe = elf_info.binary_format.upper() == "PE" or fname_lower.endswith(".dll")
    ecosystem = "Windows" if is_pe else "Linux"
    evidence_prefix = "pe-binary" if is_pe else "elf-binary"

    eff_origin = origin_package or elf_info.origin_package
    eff_prov = provenance or elf_info.provenance
    if not eff_origin and not eff_prov and elf_info.path != "<memory>":
        eff_origin, eff_prov = infer_binary_provenance(elf_info.path, fname)
    if eff_origin and not eff_prov:
        eff_prov = f"vendored-in-wheel:{eff_origin}"
    elif not eff_prov:
        eff_prov = "bundled-by-build-tool" if is_monolithic else "standalone-binary"

    target_soname = elf_info.soname or fname

    return Component(
        name=lib_name,
        version=version,
        component_type=ComponentType.NATIVE_LIBRARY,
        scope=ComponentScope.REQUIRED,
        ecosystem=ecosystem,
        description=f"Bundled native shared library ({fname}, {elf_info.architecture})",
        homepage=homepage,
        source_url=source_url,
        license_info=lic_info,
        hashes={"SHA256": elf_info.sha256} if elf_info.sha256 else {},
        dependencies=list(elf_info.needed_libs),
        bundled_files=[elf_info.path],
        is_bundled=True,
        is_statically_compiled=elf_info.is_statically_linked or is_monolithic,
        has_dynamic_relinking=not is_monolithic and not elf_info.is_statically_linked,
        discovery_evidence=[f"{evidence_prefix}:{fname}"],
        origin_package=eff_origin,
        provenance=eff_prov,
        architecture=elf_info.architecture,
        soname=target_soname,
    )


binary_to_native_component = elf_to_native_component
