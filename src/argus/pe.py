"""Windows Portable Executable (PE32 / PE32+) parser for .exe, .dll, and .pyd binaries."""

from __future__ import annotations

import hashlib
import re
import struct
from pathlib import Path

from argus.models import ElfBinaryInfo

DOS_MAGIC = b"MZ"
PE_SIGNATURE = b"PE\x00\x00"

IMAGE_FILE_DLL = 0x2000
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002

PE_MACHINE_MAP: dict[int, str] = {
    0x8664: "x86_64",
    0x014C: "x86",
    0xAA64: "aarch64",
    0x01C0: "arm",
    0x01C4: "arm",
}

# Standard Windows OS / Win32 / NT / UCRT system DLLs provided by the operating system
WINDOWS_SYSTEM_ABI_DLLS: set[str] = {
    "advapi32.dll",
    "authz.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "cabinet.dll",
    "cfgmgr32.dll",
    "combase.dll",
    "comctl32.dll",
    "comdlg32.dll",
    "credui.dll",
    "crypt32.dll",
    "cryptbase.dll",
    "cryptsp.dll",
    "d2d1.dll",
    "d3d11.dll",
    "d3d12.dll",
    "d3d9.dll",
    "dbghelp.dll",
    "dnsapi.dll",
    "dwmapi.dll",
    "dwrite.dll",
    "dxgi.dll",
    "gdi32.dll",
    "gdiplus.dll",
    "hid.dll",
    "imagehlp.dll",
    "imm32.dll",
    "iphlpapi.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "mpr.dll",
    "msi.dll",
    "msimg32.dll",
    "msvcrt.dll",
    "mswsock.dll",
    "ncrypt.dll",
    "netapi32.dll",
    "normaliz.dll",
    "ntdll.dll",
    "ole32.dll",
    "oleacc.dll",
    "oleaut32.dll",
    "opengl32.dll",
    "pdh.dll",
    "powrprof.dll",
    "profapi.dll",
    "propsys.dll",
    "psapi.dll",
    "rpcrt4.dll",
    "sechost.dll",
    "secur32.dll",
    "setupapi.dll",
    "shcore.dll",
    "shell32.dll",
    "shlwapi.dll",
    "sspicli.dll",
    "ucrtbase.dll",
    "ucrtbased.dll",
    "urlmon.dll",
    "user32.dll",
    "userenv.dll",
    "uxtheme.dll",
    "version.dll",
    "wer.dll",
    "winhttp.dll",
    "wininet.dll",
    "winmm.dll",
    "winspool.drv",
    "wintrust.dll",
    "wlanapi.dll",
    "wldap32.dll",
    "ws2_32.dll",
    "wsock32.dll",
    "wtsapi32.dll",
}

WINDOWS_SYSTEM_ABI_PREFIXES: tuple[str, ...] = (
    "api-ms-win-",
    "ext-ms-win-",
)

# Microsoft Visual C++ Redistributable runtime DLLs (treated as compiler/OS runtime ABI)
WINDOWS_MSVC_RUNTIME_PREFIXES: tuple[str, ...] = (
    "vcruntime",
    "msvcp",
    "msvcr",
    "concrt",
    "vcomp",
    "vccorlib",
    "mfc1",
)

# MinGW-w64 / GCC / Fortran compiler runtime DLLs on Windows
WINDOWS_COMPILER_RUNTIME_PREFIXES: tuple[str, ...] = (
    *WINDOWS_MSVC_RUNTIME_PREFIXES,
    "libgcc_s",
    "libstdc++",
    "libgomp",
    "libatomic",
    "libgfortran",
    "libquadmath",
    "libwinpthread",
)

ASCII_STR_RE = re.compile(rb"[\x20-\x7e]{4,200}")
UTF16LE_STR_RE = re.compile(rb"(?:[\x20-\x7e]\x00){4,200}")


def is_pe_bytes(data: bytes) -> bool:
    """Return True if raw bytes begin with a valid DOS MZ header and PE\\0\\0 signature."""
    if len(data) < 64 or data[:2] != DOS_MAGIC:
        return False
    try:
        (e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
    except struct.error:
        return False
    if e_lfanew < 0x40 or e_lfanew + 24 > len(data):
        return False
    return data[e_lfanew : e_lfanew + 4] == PE_SIGNATURE


def is_pe_file(path: Path) -> bool:
    """Return True if path is a regular file with a valid Windows PE (MZ/PE) header."""
    try:
        if not path.is_file() or path.is_symlink():
            return False
        with path.open("rb") as f:
            header = f.read(4096)
        if len(header) < 64 or header[:2] != DOS_MAGIC:
            return False
        (e_lfanew,) = struct.unpack_from("<I", header, 0x3C)
        if e_lfanew < 0x40:
            return False
        if e_lfanew + 4 <= len(header):
            return header[e_lfanew : e_lfanew + 4] == PE_SIGNATURE
        with path.open("rb") as f:
            f.seek(e_lfanew)
            sig = f.read(4)
        return sig == PE_SIGNATURE
    except OSError:
        return False


def is_windows_msvc_runtime_dll(lib_name: str) -> bool:
    """Return True if a DLL name is a Microsoft Visual C++ runtime library."""
    base = Path(lib_name.replace("\\", "/")).name.lower()
    if not base.endswith(".dll"):
        return False
    return base.startswith(WINDOWS_MSVC_RUNTIME_PREFIXES)


def is_windows_system_dll(lib_name: str) -> bool:
    """Return True if a DLL name belongs to the standard Windows OS / UCRT / MSVC system ABI."""
    base = Path(lib_name.replace("\\", "/")).name.lower()
    if base in WINDOWS_SYSTEM_ABI_DLLS:
        return True
    if base.startswith(WINDOWS_SYSTEM_ABI_PREFIXES):
        return True
    return is_windows_msvc_runtime_dll(base)


def is_windows_compiler_runtime_dll(lib_name: str) -> bool:
    """Return True if a DLL name is a standard Windows MSVC or MinGW-w64 compiler runtime DLL."""
    base = Path(lib_name.replace("\\", "/")).name.lower()
    if not base.endswith(".dll"):
        return False
    return base.startswith(WINDOWS_COMPILER_RUNTIME_PREFIXES)


def extract_utf16le_strings(data: bytes, limit: int = 800) -> list[str]:
    """Extract printable UTF-16LE strings from PE binary bytes (e.g. VS_VERSIONINFO and wide literals)."""
    results: list[str] = []
    for match in UTF16LE_STR_RE.finditer(data):
        s = match.group(0).decode("utf-16le", errors="ignore").strip()
        if s:
            results.append(s)
            if len(results) >= limit:
                break
    return results


def _extract_pe_version_resource(utf16_strings: list[str]) -> str | None:
    """Extract semantic version from PE VS_VERSIONINFO UTF-16LE key/value strings if present."""
    for idx, token in enumerate(utf16_strings[:-1]):
        if token in ("ProductVersion", "FileVersion"):
            candidate = utf16_strings[idx + 1].strip()
            m = re.match(r"^(\d+\.\d+(?:\.\d+)*(?:[a-zA-Z0-9._-]*)?)", candidate)
            if m:
                return m.group(1)
    return None


def _read_c_string(data: bytes, offset: int, max_len: int = 256) -> str:
    """Read a null-terminated ASCII string from `data` at `offset`."""
    if offset < 0 or offset >= len(data):
        return ""
    end = data.find(b"\x00", offset, offset + max_len)
    raw = data[offset : (end if end != -1 else offset + max_len)]
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return ""
    if all(0x20 <= ord(ch) <= 0x7E for ch in text):
        return text.strip()
    return ""


def parse_pe_binary(path: Path) -> ElfBinaryInfo:
    """Parse a Windows PE binary (.exe, .dll, or .pyd) from disk."""
    raw_bytes = path.read_bytes()
    return parse_pe_bytes(raw_bytes, str(path))


def parse_pe_bytes(raw_bytes: bytes, path_str: str = "<memory>") -> ElfBinaryInfo:
    """
    Parse a Windows PE32 or PE32+ binary from in-memory bytes.
    Extracts imported DLLs (Import Directory & Delay-Load Directory), exported symbols,
    internal DLL name, architecture, bitness, and embedded version strings.
    """
    if not is_pe_bytes(raw_bytes):
        raise ValueError(f"Not a valid PE binary: {path_str}")

    sha256 = hashlib.sha256(raw_bytes).hexdigest()
    (e_lfanew,) = struct.unpack_from("<I", raw_bytes, 0x3C)
    coff_off = e_lfanew + 4

    machine, num_sections, _timestamp, _sym_ptr, _num_syms, opt_hdr_size, characteristics = struct.unpack_from(
        "<HHIIIHH", raw_bytes, coff_off
    )
    arch = PE_MACHINE_MAP.get(machine, f"unknown(0x{machine:04x})")
    is_dll = bool(characteristics & IMAGE_FILE_DLL)
    is_exec = bool(characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) and not is_dll

    opt_off = coff_off + 20
    bits = 64
    data_dirs: list[tuple[int, int]] = []

    if opt_hdr_size >= 2 and opt_off + opt_hdr_size <= len(raw_bytes):
        (opt_magic,) = struct.unpack_from("<H", raw_bytes, opt_off)
        if opt_magic == 0x020B and opt_hdr_size >= 112:  # PE32+ (64-bit)
            bits = 64
            (num_rva_sizes,) = struct.unpack_from("<I", raw_bytes, opt_off + 108)
            dd_start = opt_off + 112
        elif opt_magic == 0x010B and opt_hdr_size >= 96:  # PE32 (32-bit)
            bits = 32
            (num_rva_sizes,) = struct.unpack_from("<I", raw_bytes, opt_off + 92)
            dd_start = opt_off + 96
        else:
            num_rva_sizes = 0
            dd_start = opt_off + opt_hdr_size

        max_dirs = min(num_rva_sizes, 16, (opt_off + opt_hdr_size - dd_start) // 8)
        for i in range(max(0, max_dirs)):
            rva, size = struct.unpack_from("<II", raw_bytes, dd_start + i * 8)
            data_dirs.append((rva, size))

    # Parse Section Headers (40 bytes each)
    sec_table_off = opt_off + opt_hdr_size
    sections: list[tuple[int, int, int, int]] = []
    for i in range(min(num_sections, 96)):
        sh_off = sec_table_off + i * 40
        if sh_off + 40 > len(raw_bytes):
            break
        vsize, vaddr, raw_size, raw_ptr = struct.unpack_from("<IIII", raw_bytes, sh_off + 8)
        sections.append((vaddr, vsize, raw_ptr, raw_size))

    def rva_to_offset(rva: int) -> int | None:
        if rva <= 0:
            return None
        for vaddr, vsize, raw_ptr, raw_size in sections:
            span = max(vsize, raw_size)
            if span > 0 and vaddr <= rva < vaddr + span:
                off = raw_ptr + (rva - vaddr)
                return off if 0 <= off < len(raw_bytes) else None
        if rva < len(raw_bytes) and not sections:
            return rva
        return None

    needed_libs: list[str] = []
    soname: str | None = None
    priority_exports: list[str] = []
    other_exports: list[str] = []

    # 1. Parse Import Directory Table (Data Directory index 1)
    if len(data_dirs) > 1 and data_dirs[1][0] > 0:
        imp_rva, _imp_size = data_dirs[1]
        imp_off = rva_to_offset(imp_rva)
        if imp_off is not None:
            pos = imp_off
            for _ in range(512):
                if pos + 20 > len(raw_bytes):
                    break
                orig_thunk, _ts, _fwd, name_rva, first_thunk = struct.unpack_from("<IIIII", raw_bytes, pos)
                if orig_thunk == 0 and name_rva == 0 and first_thunk == 0:
                    break
                name_off = rva_to_offset(name_rva)
                if name_off is not None:
                    dll_raw = _read_c_string(raw_bytes, name_off, max_len=256).strip()
                    if dll_raw:
                        dll_name = f"{dll_raw}.dll" if "." not in dll_raw else dll_raw
                        if (
                            dll_name.lower().endswith((".dll", ".pyd", ".drv", ".exe", ".ocx"))
                            and dll_name not in needed_libs
                        ):
                            needed_libs.append(dll_name)
                pos += 20

    # 2. Parse Delay-Load Import Directory Table (Data Directory index 13)
    if len(data_dirs) > 13 and data_dirs[13][0] > 0:
        delay_rva, _delay_size = data_dirs[13]
        delay_off = rva_to_offset(delay_rva)
        if delay_off is not None:
            pos = delay_off
            for _ in range(256):
                if pos + 32 > len(raw_bytes):
                    break
                _attrs, dll_name_rva, _hmod, _iat, _int, _biat, _uiat, _ts = struct.unpack_from(
                    "<IIIIIIII", raw_bytes, pos
                )
                if dll_name_rva == 0:
                    break
                name_off = rva_to_offset(dll_name_rva)
                if name_off is not None:
                    dll_raw = _read_c_string(raw_bytes, name_off, max_len=256).strip()
                    if dll_raw:
                        dll_name = f"{dll_raw}.dll" if "." not in dll_raw else dll_raw
                        if (
                            dll_name.lower().endswith((".dll", ".pyd", ".drv", ".exe", ".ocx"))
                            and dll_name not in needed_libs
                        ):
                            needed_libs.append(dll_name)
                pos += 32

    # 3. Parse Export Directory Table (Data Directory index 0)
    if len(data_dirs) > 0 and data_dirs[0][0] > 0:
        exp_rva, _exp_size = data_dirs[0]
        exp_off = rva_to_offset(exp_rva)
        if exp_off is not None and exp_off + 40 <= len(raw_bytes):
            (
                _flags,
                _ts,
                _maj,
                _min,
                exp_name_rva,
                _base,
                _num_funcs,
                num_names,
                _addr_funcs,
                addr_names_rva,
                _addr_ords,
            ) = struct.unpack_from("<IIHHIIIIIII", raw_bytes, exp_off)

            exp_name_off = rva_to_offset(exp_name_rva)
            if exp_name_off is not None:
                exp_mod_name = _read_c_string(raw_bytes, exp_name_off, max_len=256)
                if exp_mod_name:
                    soname = exp_mod_name

            names_table_off = rva_to_offset(addr_names_rva)
            if names_table_off is not None:
                for i in range(min(num_names, 4096)):
                    entry_off = names_table_off + i * 4
                    if entry_off + 4 > len(raw_bytes):
                        break
                    (sym_rva,) = struct.unpack_from("<I", raw_bytes, entry_off)
                    sym_off = rva_to_offset(sym_rva)
                    if sym_off is not None:
                        sname = _read_c_string(raw_bytes, sym_off, max_len=256)
                        if not sname:
                            continue
                        clean_sname = sname.lstrip("_") if sname.startswith(("_PyInit_", "_modulecode_")) else sname
                        if clean_sname.startswith(("PyInit_", "modulecode_")):
                            priority_exports.append(clean_sname)
                        elif len(other_exports) < 120:
                            other_exports.append(sname)

    exported_symbols = priority_exports + other_exports

    # Extract ASCII and UTF-16LE strings for library & version detection
    ascii_strings: list[str] = []
    for match in ASCII_STR_RE.finditer(raw_bytes):
        s = match.group(0).decode("ascii", errors="ignore").strip()
        if s:
            ascii_strings.append(s)
            if len(ascii_strings) >= 1200:
                break

    utf16_strings = extract_utf16le_strings(raw_bytes, limit=400)
    combined_strings = ascii_strings + utf16_strings

    from argus.elf import _infer_library_identity, _match_known_native_profile, infer_binary_provenance

    fname = Path(path_str.replace("\\", "/")).name
    lib_name, lib_ver = _infer_library_identity(fname, soname, combined_strings)
    if (not lib_ver or lib_ver == "unknown") and utf16_strings:
        res_ver = _extract_pe_version_resource(utf16_strings)
        if res_ver:
            lib_ver = res_ver

    origin_pkg = None
    prov = ""
    if path_str != "<memory>":
        origin_pkg, prov = infer_binary_provenance(path_str, fname)

    matched_profile = _match_known_native_profile(lib_name) if lib_name else None
    lic_spdx = matched_profile.spdx_id if matched_profile else "NOASSERTION"
    cop_notice = matched_profile.copyright_notice if matched_profile else ""

    return ElfBinaryInfo(
        path=path_str,
        soname=soname,
        needed_libs=needed_libs,
        rpath=None,
        runpath=None,
        architecture=arch,
        bits=bits,
        endianness="little",
        is_executable=is_exec,
        is_shared_object=is_dll,
        is_statically_linked=len(needed_libs) == 0,
        interpreter=None,
        detected_library_name=lib_name,
        detected_version=lib_ver,
        exported_symbols_sample=exported_symbols[:150],
        ident_strings=combined_strings[:80],
        sha256=sha256,
        binary_format="PE",
        origin_package=origin_pkg,
        provenance=prov,
        license_spdx=lic_spdx,
        copyright=cop_notice,
    )
