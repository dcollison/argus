"""Test helpers for generating valid synthetic 64-bit ELF binaries, PyInstaller CArchives, and uv workspaces."""

from __future__ import annotations

import struct
from pathlib import Path


def build_synthetic_elf64(
    *,
    is_executable: bool = False,
    soname: str | None = None,
    needed_libs: list[str] | None = None,
    rpath: str | None = None,
    runpath: str | None = None,
    exported_symbols: list[str] | None = None,
    rodata_strings: list[str] | None = None,
    interpreter: str | None = "/lib64/ld-linux-x86-64.so.2",
    static_only: bool = False,
    trailing_payload: bytes = b"",
) -> bytes:
    """
    Construct a valid 64-bit little-endian x86_64 ELF binary with real Section Headers
    (.shstrtab, .dynstr, .dynamic, .dynsym, .rodata) and Program Headers (PT_INTERP, PT_DYNAMIC)
    that parses cleanly with pyelftools as well as the pure-Python struct fallback.
    """
    needed_libs = needed_libs or []
    exported_symbols = exported_symbols or []
    rodata_strings = rodata_strings or []

    # 1. Build .dynstr string table
    dynstr = bytearray(b"\x00")

    def add_dynstr(s: str) -> int:
        off = len(dynstr)
        dynstr.extend(s.encode("utf-8") + b"\x00")
        return off

    soname_off = add_dynstr(soname) if soname else None
    needed_offs = [add_dynstr(lib) for lib in needed_libs]
    rpath_off = add_dynstr(rpath) if rpath is not None else None
    runpath_off = add_dynstr(runpath) if runpath is not None else None
    sym_offs = [add_dynstr(sym) for sym in exported_symbols]

    # 2. Build .dynamic section (array of Elf64_Dyn: d_tag (q), d_val (Q))
    dynamic_sec = bytearray()
    if not static_only:
        for noff in needed_offs:
            dynamic_sec.extend(struct.pack("<qQ", 1, noff))  # DT_NEEDED = 1
        if soname_off is not None:
            dynamic_sec.extend(struct.pack("<qQ", 14, soname_off))  # DT_SONAME = 14
        if rpath_off is not None:
            dynamic_sec.extend(struct.pack("<qQ", 15, rpath_off))  # DT_RPATH = 15
        if runpath_off is not None:
            dynamic_sec.extend(struct.pack("<qQ", 29, runpath_off))  # DT_RUNPATH = 29
        dynamic_sec.extend(struct.pack("<qQ", 5, 0))  # DT_STRTAB = 5
        dynamic_sec.extend(struct.pack("<qQ", 10, len(dynstr)))  # DT_STRSZ = 10
        dynamic_sec.extend(struct.pack("<qQ", 0, 0))  # DT_NULL = 0

    # 3. Build .dynsym section (array of Elf64_Sym: 24 bytes each: I B B H Q Q)
    dynsym_sec = bytearray(24)  # STN_UNDEF null symbol at index 0
    for soff in sym_offs:
        st_info = (1 << 4) | 2  # STB_GLOBAL (1), STT_FUNC (2)
        dynsym_sec.extend(struct.pack("<IBBHQQ", soff, st_info, 0, 1, 0x1000, 32))

    # 4. Build .rodata section
    rodata_sec = bytearray()
    for rs in rodata_strings:
        rodata_sec.extend(rs.encode("utf-8") + b"\x00")
    if not rodata_sec:
        rodata_sec.extend(b"rhada-test-rodata\x00")

    # 5. Build .interp section if executable and not static
    interp_bytes = b""
    if is_executable and not static_only and interpreter:
        interp_bytes = interpreter.encode("utf-8") + b"\x00"

    # 6. Build .shstrtab section
    shstrtab = bytearray(b"\x00")

    def add_shstr(s: str) -> int:
        off = len(shstrtab)
        shstrtab.extend(s.encode("ascii") + b"\x00")
        return off

    sh_dynstr_name = add_shstr(".dynstr")
    sh_dynamic_name = add_shstr(".dynamic")
    sh_dynsym_name = add_shstr(".dynsym")
    sh_rodata_name = add_shstr(".rodata")
    sh_interp_name = add_shstr(".interp")
    sh_shstrtab_name = add_shstr(".shstrtab")

    # Layout calculation:
    # 0x00 .. 0x40: ELF64 header (64 bytes)
    # 0x40 .. : Program headers (56 bytes each)
    num_phdrs = 0
    if interp_bytes:
        num_phdrs += 1
    if not static_only:
        num_phdrs += 1

    cursor = 64 + num_phdrs * 56

    def align8(val: int) -> int:
        return (val + 7) & ~7

    cursor = align8(cursor)
    dynstr_offset = cursor
    cursor = align8(cursor + len(dynstr))

    dynamic_offset = cursor
    cursor = align8(cursor + len(dynamic_sec))

    dynsym_offset = cursor
    cursor = align8(cursor + len(dynsym_sec))

    rodata_offset = cursor
    cursor = align8(cursor + len(rodata_sec))

    interp_offset = cursor
    if interp_bytes:
        cursor = align8(cursor + len(interp_bytes))

    shstrtab_offset = cursor
    cursor = align8(cursor + len(shstrtab))

    shdr_offset = cursor

    # Assemble Program Headers (Elf64_Phdr: <IIQQQQQQ = 56 bytes)
    phdr_bytes = bytearray()
    if interp_bytes:
        # PT_INTERP = 3, PF_R = 4
        phdr_bytes.extend(
            struct.pack(
                "<IIQQQQQQ",
                3,
                4,
                interp_offset,
                interp_offset,
                interp_offset,
                len(interp_bytes),
                len(interp_bytes),
                1,
            )
        )
    if not static_only:
        # PT_DYNAMIC = 2, PF_R | PF_W = 6
        phdr_bytes.extend(
            struct.pack(
                "<IIQQQQQQ",
                2,
                6,
                dynamic_offset,
                dynamic_offset,
                dynamic_offset,
                len(dynamic_sec),
                len(dynamic_sec),
                8,
            )
        )

    # Assemble Section Headers (Elf64_Shdr: <IIQQQQIIQQ = 64 bytes)
    # Index 0: SHT_NULL
    # Index 1: .dynstr (SHT_STRTAB = 3)
    # Index 2: .dynamic (SHT_DYNAMIC = 6, sh_link = 1 (.dynstr), sh_entsize = 16)
    # Index 3: .dynsym (SHT_DYNSYM = 11, sh_link = 1 (.dynstr), sh_info = 1, sh_entsize = 24)
    # Index 4: .rodata (SHT_PROGBITS = 1)
    # Index 5 (optional): .interp (SHT_PROGBITS = 1)
    # Last: .shstrtab (SHT_STRTAB = 3)
    shdrs: list[bytes] = []
    shdrs.append(b"\x00" * 64)  # 0: SHT_NULL
    shdrs.append(
        struct.pack("<IIQQQQIIQQ", sh_dynstr_name, 3, 2, dynstr_offset, dynstr_offset, len(dynstr), 0, 0, 1, 0)
    )
    if not static_only:
        shdrs.append(
            struct.pack(
                "<IIQQQQIIQQ", sh_dynamic_name, 6, 3, dynamic_offset, dynamic_offset, len(dynamic_sec), 1, 0, 8, 16
            )
        )
    shdrs.append(
        struct.pack("<IIQQQQIIQQ", sh_dynsym_name, 11, 2, dynsym_offset, dynsym_offset, len(dynsym_sec), 1, 1, 8, 24)
    )
    shdrs.append(
        struct.pack("<IIQQQQIIQQ", sh_rodata_name, 1, 2, rodata_offset, rodata_offset, len(rodata_sec), 0, 0, 4, 0)
    )
    if interp_bytes:
        shdrs.append(
            struct.pack("<IIQQQQIIQQ", sh_interp_name, 1, 2, interp_offset, interp_offset, len(interp_bytes), 0, 0, 1, 0)
        )
    shstrndx = len(shdrs)
    shdrs.append(
        struct.pack("<IIQQQQIIQQ", sh_shstrtab_name, 3, 0, shstrtab_offset, shstrtab_offset, len(shstrtab), 0, 0, 1, 0)
    )

    e_type = 2 if is_executable else 3  # ET_EXEC (2) or ET_DYN (3)
    e_machine = 62  # EM_X86_64
    e_ident = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        e_ident,
        e_type,
        e_machine,
        1,  # e_version
        0x400000 if is_executable else 0,
        64 if num_phdrs > 0 else 0,  # e_phoff
        shdr_offset,  # e_shoff
        0,  # e_flags
        64,  # e_ehsize
        56,  # e_phentsize
        num_phdrs,  # e_phnum
        64,  # e_shentsize
        len(shdrs),  # e_shnum
        shstrndx,  # e_shstrndx
    )

    out = bytearray(ehdr)
    out.extend(phdr_bytes)

    def pad_to(target_off: int) -> None:
        if len(out) < target_off:
            out.extend(b"\x00" * (target_off - len(out)))

    pad_to(dynstr_offset)
    out.extend(dynstr)
    pad_to(dynamic_offset)
    out.extend(dynamic_sec)
    pad_to(dynsym_offset)
    out.extend(dynsym_sec)
    pad_to(rodata_offset)
    out.extend(rodata_sec)
    if interp_bytes:
        pad_to(interp_offset)
        out.extend(interp_bytes)
    pad_to(shstrtab_offset)
    out.extend(shstrtab)
    pad_to(shdr_offset)
    for sh in shdrs:
        out.extend(sh)

    if trailing_payload:
        out.extend(trailing_payload)

    return bytes(out)


def build_synthetic_pe64(
    *,
    is_executable: bool = False,
    export_dll_name: str | None = None,
    needed_libs: list[str] | None = None,
    delay_load_libs: list[str] | None = None,
    exported_symbols: list[str] | None = None,
    rodata_strings: list[str] | None = None,
    utf16_strings: list[str] | None = None,
    machine: int = 0x8664,
    trailing_payload: bytes = b"",
) -> bytes:
    """
    Construct a valid 64-bit PE32+ (.exe, .dll, or .pyd) binary with DOS header,
    PE signature, COFF header, OptionalHeader64, .rdata section, Import Directory,
    Delay-Load Import Directory, Export Directory, and ASCII / UTF-16LE strings.
    """
    needed_libs = needed_libs or []
    delay_load_libs = delay_load_libs or []
    exported_symbols = exported_symbols or []
    rodata_strings = rodata_strings or []
    utf16_strings = utf16_strings or []

    sec_rva = 0x1000
    sec_raw_offset = 0x200
    sec_buf = bytearray(b"\x00" * 4)

    def add_cstr(s: str) -> int:
        rva = sec_rva + len(sec_buf)
        sec_buf.extend(s.encode("utf-8") + b"\x00")
        return rva

    def align4() -> None:
        rem = len(sec_buf) % 4
        if rem:
            sec_buf.extend(b"\x00" * (4 - rem))

    needed_rvas = [add_cstr(dll) for dll in needed_libs]
    delay_rvas = [add_cstr(dll) for dll in delay_load_libs]
    export_name_rva = add_cstr(export_dll_name) if export_dll_name else 0
    sym_rvas = [add_cstr(sym) for sym in exported_symbols]

    for rs in rodata_strings:
        add_cstr(rs)

    align4()
    for us in utf16_strings:
        sec_buf.extend(us.encode("utf-16le") + b"\x00\x00")
    align4()

    # 1. Import Directory Table (Data Directory 1)
    imp_rva = 0
    imp_size = 0
    if needed_rvas:
        imp_rva = sec_rva + len(sec_buf)
        for nrva in needed_rvas:
            sec_buf.extend(struct.pack("<IIIII", 0, 0, 0, nrva, 0))
        sec_buf.extend(b"\x00" * 20)
        imp_size = (len(needed_rvas) + 1) * 20

    # 2. Delay-Load Import Directory Table (Data Directory 13)
    delay_rva = 0
    delay_size = 0
    if delay_rvas:
        delay_rva = sec_rva + len(sec_buf)
        for drva in delay_rvas:
            sec_buf.extend(struct.pack("<IIIIIIII", 1, drva, 0, 0, 0, 0, 0, 0))
        sec_buf.extend(b"\x00" * 32)
        delay_size = (len(delay_rvas) + 1) * 32

    # 3. Export Directory Table (Data Directory 0)
    exp_rva = 0
    exp_size = 0
    if export_name_rva or sym_rvas:
        names_array_rva = sec_rva + len(sec_buf)
        for srva in sym_rvas:
            sec_buf.extend(struct.pack("<I", srva))
        exp_rva = sec_rva + len(sec_buf)
        sec_buf.extend(
            struct.pack(
                "<IIHHIIIIIII",
                0,  # Characteristics
                0,  # TimeDateStamp
                0,  # MajorVersion
                0,  # MinorVersion
                export_name_rva,  # Name RVA
                1,  # Base
                len(sym_rvas),  # NumberOfFunctions
                len(sym_rvas),  # NumberOfNames
                0,  # AddressOfFunctions
                names_array_rva,  # AddressOfNames
                0,  # AddressOfNameOrdinals
            )
        )
        exp_size = 40

    while len(sec_buf) % 16 != 0:
        sec_buf.append(0)

    # DOS Header (128 bytes with e_lfanew = 0x80 at offset 0x3C)
    dos_hdr = bytearray(0x80)
    dos_hdr[0:2] = b"MZ"
    struct.pack_into("<I", dos_hdr, 0x3C, 0x80)

    # COFF Header (20 bytes)
    # IMAGE_FILE_EXECUTABLE_IMAGE (0x0002) | IMAGE_FILE_LARGE_ADDRESS_AWARE (0x0020) | (0 if exe else IMAGE_FILE_DLL (0x2000))
    characteristics = 0x0002 | 0x0020 | (0x0000 if is_executable else 0x2000)
    coff_hdr = struct.pack(
        "<HHIIIHH",
        machine,
        1,  # NumberOfSections
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        240,  # SizeOfOptionalHeader (PE32+ = 112 + 16*8 = 240)
        characteristics,
    )

    # OptionalHeader64 (112 bytes fixed + 16 * 8 bytes data directories = 240 bytes)
    opt_fixed = bytearray(112)
    struct.pack_into("<H", opt_fixed, 0, 0x20B)  # PE32+ magic
    struct.pack_into("<I", opt_fixed, 16, sec_rva)  # AddressOfEntryPoint
    struct.pack_into("<Q", opt_fixed, 24, 0x140000000 if is_executable else 0x180000000)  # ImageBase
    struct.pack_into("<I", opt_fixed, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt_fixed, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", opt_fixed, 56, sec_rva + len(sec_buf))  # SizeOfImage
    struct.pack_into("<I", opt_fixed, 60, sec_raw_offset)  # SizeOfHeaders
    struct.pack_into("<H", opt_fixed, 68, 3)  # Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI
    struct.pack_into("<I", opt_fixed, 108, 16)  # NumberOfRvaAndSizes = 16

    data_dirs = [(0, 0)] * 16
    data_dirs[0] = (exp_rva, exp_size)
    data_dirs[1] = (imp_rva, imp_size)
    data_dirs[13] = (delay_rva, delay_size)
    opt_dirs = b"".join(struct.pack("<II", rva, sz) for rva, sz in data_dirs)

    # Section Header (.rdata, 40 bytes)
    sec_hdr = struct.pack(
        "<8sIIIIIIHHI",
        b".rdata\x00\x00",
        len(sec_buf),  # VirtualSize
        sec_rva,  # VirtualAddress
        len(sec_buf),  # SizeOfRawData
        sec_raw_offset,  # PointerToRawData
        0,
        0,
        0,
        0,
        0x40000040,  # IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
    )

    out = bytearray()
    out.extend(dos_hdr)
    out.extend(b"PE\x00\x00")
    out.extend(coff_hdr)
    out.extend(opt_fixed)
    out.extend(opt_dirs)
    out.extend(sec_hdr)
    if len(out) < sec_raw_offset:
        out.extend(b"\x00" * (sec_raw_offset - len(out)))
    out.extend(sec_buf)
    if trailing_payload:
        out.extend(trailing_payload)

    return bytes(out)


def build_pyinstaller_carchive_payload(entries: list[tuple[str, str]]) -> bytes:
    """
    Build a valid PyInstaller 2.1+ CArchive binary payload with TOC entries and 88-byte MEI cookie.
    Each item in `entries` is `(typecode, name)`, e.g. `('m', 'httpx')` or `('b', 'libssl.so.3')`.
    """
    toc_buf = bytearray()
    for typecode, name in entries:
        name_bytes = name.encode("utf-8") + b"\x00"
        # Pad entry length to 4-byte boundary
        raw_len = 18 + len(name_bytes)
        entry_len = (raw_len + 3) & ~3
        padded_name = name_bytes + b"\x00" * (entry_len - raw_len)
        toc_buf.extend(
            struct.pack(
                "!iIIIBc",
                entry_len,
                0,
                16,
                16,
                0,
                typecode.encode("ascii")[:1],
            )
            + padded_name
        )

    toc_len = len(toc_buf)
    pkg_len = toc_len + 88
    cookie = struct.pack(
        "!8sIIii64s",
        b"MEI\x0c\x0b\x0a\x0b\x0e",
        pkg_len,
        0,  # toc_offset from start of archive
        toc_len,
        311,  # pyvers
        b"libpython3.11.so.1.0".ljust(64, b"\x00"),
    )
    return bytes(toc_buf + cookie)


def create_dist_info(
    site_packages: Path,
    name: str,
    version: str,
    *,
    license_str: str = "",
    license_expression: str = "",
    classifiers: list[str] | None = None,
    requires_dist: list[str] | None = None,
    top_level: list[str] | None = None,
    license_files: dict[str, str] | None = None,
    notice_files: dict[str, str] | None = None,
    author: str = "Example Maintainer",
    homepage: str = "https://example.com",
) -> Path:
    """Create a realistic .dist-info directory inside site_packages."""
    norm = name.replace("-", "_")
    dist_dir = site_packages / f"{norm}-{version}.dist-info"
    dist_dir.mkdir(parents=True, exist_ok=True)

    meta_lines = [
        "Metadata-Version: 2.3",
        f"Name: {name}",
        f"Version: {version}",
        f"Summary: {name} package for testing",
        f"Home-page: {homepage}",
        f"Author: {author}",
    ]
    if license_str:
        formatted_lic = "\n       ".join(line if line.strip() else "." for line in license_str.splitlines())
        meta_lines.append(f"License: {formatted_lic}")
    if license_expression:
        meta_lines.append(f"License-Expression: {license_expression}")
    meta_lines.extend(f"Classifier: {clf}" for clf in classifiers or [])
    meta_lines.extend(f"Requires-Dist: {req}" for req in requires_dist or [])

    (dist_dir / "METADATA").write_text("\n".join(meta_lines) + "\n", encoding="utf-8")

    if top_level:
        (dist_dir / "top_level.txt").write_text("\n".join(top_level) + "\n", encoding="utf-8")

    if license_files:
        lic_sub = dist_dir / "licenses"
        lic_sub.mkdir(exist_ok=True)
        for fname, text in license_files.items():
            (lic_sub / fname).write_text(text, encoding="utf-8")

    if notice_files:
        for fname, text in notice_files.items():
            (dist_dir / fname).write_text(text, encoding="utf-8")

    return dist_dir
