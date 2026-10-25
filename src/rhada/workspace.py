"""Source workspace inspector for pyproject.toml, uv.lock, and virtualenv (.venv) metadata."""

from __future__ import annotations

import contextlib
import email
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from rhada.models import Component, ComponentScope, ComponentType, ElfBinaryInfo, LicenseInfo
from rhada.spdx import build_license_info


def normalize_pkg_name(name: str) -> str:
    """Normalise a Python package name per PEP 503."""
    if not name:
        return ""
    try:
        return str(canonicalize_name(name))
    except (ValueError, TypeError):
        return re.sub(r"[-_.]+", "-", name).lower().strip("-")


def parse_req_name(req_str: str) -> str:
    """Extract a normalised package name from a PEP 508 requirement string."""
    cleaned = req_str.strip()
    if not cleaned:
        return ""
    try:
        req = Requirement(cleaned)
        return normalize_pkg_name(req.name)
    except InvalidRequirement:
        match = re.match(r"^([A-Za-z0-9_.-]+)", cleaned)
        return normalize_pkg_name(match.group(1)) if match else ""


@dataclass(slots=True)
class WorkspaceMetadata:
    """Discovered metadata from a Python or uv project workspace."""

    project_name: str = "unknown-project"
    project_version: str = "0.0.0"
    project_description: str = ""
    project_license: str = "UNKNOWN"
    root_path: Path = field(default_factory=lambda: Path("."))
    direct_runtime_deps: set[str] = field(default_factory=set)
    direct_dev_deps: set[str] = field(default_factory=set)
    components: dict[str, Component] = field(default_factory=dict)
    module_to_package: dict[str, str] = field(default_factory=dict)
    native_components: list[Component] = field(default_factory=list)
    package_libraries: dict[str, list[str]] = field(default_factory=dict)
    elf_binaries: list[ElfBinaryInfo] = field(default_factory=list)


LICENSE_FILE_PATTERNS = (
    "LICENSE*",
    "LICENCE*",
    "COPYING*",
    "COPYRIGHT*",
    "LEGAL*",
)
NOTICE_FILE_PATTERNS = (
    "NOTICE*",
    "AUTHORS*",
)


def _find_site_packages_dirs(project_path: Path) -> list[Path]:
    """Locate site-packages directories inside .venv or virtualenvs in the project."""
    candidates: list[Path] = []
    seen_resolved: set[Path] = set()

    def _add_candidate(path: Path) -> None:
        if not path.is_dir():
            return
        try:
            resolved = path.resolve()
        except OSError:
            resolved = path
        if resolved not in seen_resolved:
            seen_resolved.add(resolved)
            candidates.append(path)

    venv_names = [".venv", "venv", ".env"]
    search_roots = [project_path]
    if project_path.parent != project_path:
        search_roots.append(project_path.parent)

    for root in search_roots:
        for vname in venv_names:
            venv_dir = root / vname
            if not venv_dir.is_dir():
                continue
            # Windows layout: .venv/Lib/site-packages
            _add_candidate(venv_dir / "Lib" / "site-packages")
            # POSIX layout: .venv/lib/python*/site-packages or .venv/lib/site-packages
            lib_dir = venv_dir / "lib"
            if lib_dir.is_dir():
                for py_dir in sorted(lib_dir.glob("python*")):
                    _add_candidate(py_dir / "site-packages")
                _add_candidate(lib_dir / "site-packages")
            # Direct site-packages inside venv
            _add_candidate(venv_dir / "site-packages")

    # Also support when project_path itself is or contains site-packages directly
    _add_candidate(project_path / "site-packages")

    return candidates


def _read_text_safe(path: Path, max_bytes: int = 2_000_000) -> str:
    """Safely read a text file with UTF-8 / Latin-1 fallback and universal newline normalisation."""
    try:
        raw = path.read_bytes()[:max_bytes]
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            try:
                text = raw.decode("utf-16")
                return text.replace("\r\n", "\n").replace("\r", "\n")
            except UnicodeDecodeError:
                return ""
        if b"\x00" in raw[:4096]:
            return ""
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode("latin-1", errors="replace")
        return text.replace("\r\n", "\n").replace("\r", "\n")
    except OSError:
        return ""


_BINARY_EXTENSIONS = frozenset({
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".bmp",
    ".tiff",
    ".webp",
    ".pdf",
    ".zip",
    ".gz",
    ".tgz",
    ".bz2",
    ".xz",
    ".7z",
    ".whl",
    ".pyc",
    ".pyo",
    ".pyd",
    ".so",
    ".dll",
    ".exe",
    ".bin",
    ".dat",
    ".wasm",
    ".o",
    ".a",
    ".dylib",
    ".class",
    ".jar",
})


def extract_extension_module_name(filename: str) -> str:
    """
    Extract canonical Python C-extension module identifier from a filename,
    handling PEP 3149 / PEP 489 tags (.cp312-win_amd64, .cpython-*, .abi3, .pyd, .so).
    """
    clean = filename.replace("\\", "/")
    leaf = clean.rsplit("/", 1)[-1]
    for tag_marker in (".cpython-", ".abi3.", ".pypy"):
        if tag_marker in leaf:
            return leaf.split(tag_marker, 1)[0]
    m = re.search(r"\.cp\d+[a-z0-9_]*[-.].*?\.(?:pyd|so)$", leaf, re.IGNORECASE)
    if m:
        return leaf[: m.start()]
    if leaf.lower().endswith(".pyd"):
        return leaf[:-4]
    if ".so" in leaf.lower():
        return leaf.split(".so", 1)[0]
    return leaf.split(".", 1)[0]


KNOWN_PACKAGE_TOP_MODULES: dict[str, list[str]] = {
    "attrs": ["attr", "attrs"],
    "beautifulsoup4": ["bs4"],
    "matplotlib": ["matplotlib", "mpl_toolkits", "pylab"],
    "numpy": ["numpy"],
    "opencv-python": ["cv2"],
    "opencv-python-headless": ["cv2"],
    "pandas": ["pandas"],
    "pillow": ["PIL"],
    "protobuf": ["google"],
    "psycopg2-binary": ["psycopg2"],
    "pycryptodome": ["Crypto"],
    "pycryptodomex": ["Cryptodome"],
    "pyjwt": ["jwt"],
    "pynacl": ["nacl"],
    "pyopenssl": ["OpenSSL"],
    "pyserial": ["serial"],
    "python-dateutil": ["dateutil"],
    "python-dotenv": ["dotenv"],
    "pyusb": ["usb"],
    "pyyaml": ["yaml", "_yaml"],
    "scikit-learn": ["sklearn"],
    "scipy": ["scipy"],
}

KNOWN_PACKAGE_SUBMODULES: dict[str, list[str]] = {
    "numpy": [
        "numpy.linalg",
        "numpy.fft",
        "numpy.random",
        "numpy.polynomial",
        "numpy.ma",
        "numpy.testing",
        "numpy.lib",
        "numpy._core",
        "numpy.core",
        "numpy.matrixlib",
        "numpy.ctypeslib",
        "numpy.distutils",
        "numpy.f2py",
        "numpy.typing",
        "numpy.array_api",
        "numpy.exceptions",
        "numpy.strings",
    ],
    "scipy": [
        "scipy.special",
        "scipy.linalg",
        "scipy.sparse",
        "scipy.optimize",
        "scipy.integrate",
        "scipy.interpolate",
        "scipy.signal",
        "scipy.ndimage",
        "scipy.spatial",
        "scipy.stats",
        "scipy.cluster",
        "scipy.constants",
        "scipy.fft",
        "scipy.fftpack",
        "scipy.io",
        "scipy.odr",
        "scipy.misc",
        "scipy.datasets",
    ],
}

KNOWN_PACKAGE_EXTENSIONS: dict[str, list[str]] = {
    "numpy": [
        "_multiarray_umath",
        "_multiarray_tests",
        "umath",
        "_pocketfft_internal",
        "lapack_lite",
        "_umath_linalg",
        "mtrand",
        "_generator",
        "_bounded_integers",
        "_common",
        "_mt19937",
        "_philox",
        "_pcg64",
        "_sfc64",
        "bit_generator",
        "_simd",
        "_dotblas",
        "_rational_tests",
        "_struct_ufunc_tests",
        "_operand_flag_tests",
    ],
    "scipy": [
        "cython_blas",
        "cython_lapack",
        "_fblas",
        "_flapack",
        "_flinalg",
        "_interpolative",
        "_calc_caches",
        "_ellip_harm_2",
        "_specfun",
        "cython_special",
        "_ufuncs",
        "_ufuncs_cxx",
        "_comb",
        "_sparsetools",
        "_csparsetools",
        "_traversal",
        "_min_spanning_tree",
        "_flow",
        "_reordering",
        "_iterative",
        "_superlu",
        "_arpack",
        "_voronoi",
        "_qhull",
        "_distance_wrap",
        "_ckdtree",
        "_hausdorff",
        "_sigtools",
        "_max_len_seq_inner",
        "_spectral",
        "_peak_finding_utils",
        "_sosfilt",
        "_upfirdn_apply",
        "_ni_label",
        "_nd_image",
        "_trlib",
        "_lsq",
        "_minpack",
        "_minpack2",
        "_zeros",
        "_slsqp",
        "_cobyla",
        "_lbfgsb",
        "_nnls",
        "_group_columns",
        "_bglu_dense",
        "_highs_wrapper",
        "_highs_constants",
        "_dop",
        "_odepack",
        "_quadpack",
        "_vode",
        "_stats",
        "_statlib",
        "_mvn",
        "_sobol",
        "_qmc_cy",
        "_fitpack",
        "_bspl",
        "_ppoly",
        "_hierarchy",
        "_vq",
        "_ccallback_c",
    ],
}


def split_dist_info_stem(stem: str) -> tuple[str, str]:
    """
    Split a .dist-info directory stem (e.g. 'my-cool-pkg-1.2.3' or 'urllib3-2.0.7')
    into (name, version) at the version boundary rather than the first hyphen.
    """
    m = re.match(r"^([A-Za-z0-9_.-]+?)-(\d+[A-Za-z0-9_.*+!-]*)$", stem)
    if m:
        return m.group(1), m.group(2)
    parts = stem.rsplit("-", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return stem, "unknown"


def _clean_metadata_field(value: str | None) -> str:
    """Strip whitespace and discard setuptools placeholder values ('UNKNOWN', 'NONE', 'NOASSERTION')."""
    cleaned = (value or "").strip()
    if cleaned.upper() in {"UNKNOWN", "NONE", "NOASSERTION"}:
        return ""
    return cleaned


_LICENSE_PREFIXES = (
    "LICENSE",
    "LICENCE",
    "COPYING",
    "COPYRIGHT",
    "LEGAL",
    "THIRD_PARTY",
    "THIRD-PARTY",
    "THIRDPARTY",
)
_NOTICE_PREFIXES = (
    "NOTICE",
    "AUTHORS",
    "ATTRIBUTION",
    "CREDITS",
)
_IGNORED_RECORD_TOP_DIRS = frozenset({
    "bin",
    "scripts",
    "include",
    "share",
    "etc",
    "lib",
})


def _inspect_dist_info(dist_info_dir: Path) -> tuple[Component | None, set[str], set[str]]:
    """
    Parse a single *.dist-info directory into (component, top_level_modules, all_modules_and_submodules).
    """
    metadata_file = dist_info_dir / "METADATA"
    pkg_info_file = dist_info_dir / "PKG-INFO"
    target_meta = metadata_file if metadata_file.is_file() else (pkg_info_file if pkg_info_file.is_file() else None)
    if target_meta is None:
        return None, set(), set()

    raw_meta = _read_text_safe(target_meta)
    msg = email.message_from_string(raw_meta)

    name = _clean_metadata_field(msg.get("Name"))
    version = _clean_metadata_field(msg.get("Version")) or "unknown"
    if not name or version == "unknown":
        # Fallback from directory name: foo_bar-1.2.3.dist-info or my-pkg-1.2.3.dist-info
        stem = dist_info_dir.name.removesuffix(".dist-info") if dist_info_dir.name.endswith(".dist-info") else dist_info_dir.stem
        parsed_name, parsed_ver = split_dist_info_stem(stem)
        if not name:
            name = parsed_name
        if version == "unknown" and parsed_ver != "unknown":
            version = parsed_ver

    summary = _clean_metadata_field(msg.get("Summary"))
    homepage = _clean_metadata_field(msg.get("Home-page"))
    if not homepage:
        for purl_header in msg.get_all("Project-URL") or []:
            if "," in purl_header:
                label, url = purl_header.split(",", 1)
                cand_url = _clean_metadata_field(url)
                if cand_url and any(k in label.lower() for k in ("home", "repository", "source", "url")):
                    homepage = cand_url
                    break

    author = _clean_metadata_field(msg.get("Author")) or _clean_metadata_field(msg.get("Maintainer"))
    author_email = _clean_metadata_field(msg.get("Author-email")) or _clean_metadata_field(msg.get("Maintainer-email"))
    declared_license = (msg.get("License") or "").strip()
    license_expression = (msg.get("License-Expression") or "").strip()
    classifiers = [c.strip() for c in (msg.get_all("Classifier") or []) if c.strip()]
    requires_dist = [r.strip() for r in (msg.get_all("Requires-Dist") or []) if r.strip()]

    deps: list[str] = []
    for req_str in requires_dist:
        # Ignore extra-only requirements unless unconditional
        if re.search(r"\bextra\s*==|['\"][^'\"]*['\"]\s*==\s*\bextra\b", req_str):
            continue
        dep_name = parse_req_name(req_str)
        if dep_name and dep_name not in deps:
            deps.append(dep_name)

    # Collect licence and notice files from .dist-info and .dist-info/licenses/
    license_texts: dict[str, str] = {}
    notice_texts: dict[str, str] = {}

    for child in sorted(dist_info_dir.iterdir()):
        if child.is_dir() and child.name.lower() in {"licenses", "license", "licences"}:
            for lf in sorted(child.rglob("*")):
                if (
                    lf.is_file()
                    and not lf.is_symlink()
                    and not lf.name.startswith(".")
                    and lf.suffix.lower() not in _BINARY_EXTENSIONS
                ):
                    rel_key = str(lf.relative_to(dist_info_dir)).replace("\\", "/")
                    content = _read_text_safe(lf).strip()
                    if content:
                        if any(k in lf.name.upper() for k in _NOTICE_PREFIXES):
                            notice_texts[rel_key] = content
                        else:
                            license_texts[rel_key] = content
        elif (
            child.is_file()
            and not child.is_symlink()
            and not child.name.startswith(".")
            and child.suffix.lower() not in _BINARY_EXTENSIONS
        ):
            upper_name = child.name.upper()
            if upper_name.startswith(_LICENSE_PREFIXES) and child.name not in license_texts:
                content = _read_text_safe(child).strip()
                if content:
                    license_texts[child.name] = content
            elif upper_name.startswith(_NOTICE_PREFIXES) and child.name not in notice_texts:
                content = _read_text_safe(child).strip()
                if content:
                    notice_texts[child.name] = content

    # Also check License-File headers in METADATA
    for lf_header in msg.get_all("License-File") or []:
        lf_rel = lf_header.strip().replace("\\", "/")
        if not lf_rel:
            continue
        candidates: list[Path] = []
        if "*" in lf_rel or "?" in lf_rel:
            candidates.extend(dist_info_dir.glob(lf_rel))
            candidates.extend((dist_info_dir / "licenses").glob(lf_rel))
        else:
            cand = dist_info_dir / lf_rel
            if not cand.is_file():
                cand = dist_info_dir / "licenses" / lf_rel
            if cand.is_file():
                candidates.append(cand)
        for candidate in candidates:
            if (
                candidate.is_file()
                and not candidate.is_symlink()
                and not candidate.name.startswith(".")
                and candidate.suffix.lower() not in _BINARY_EXTENSIONS
            ):
                rel_k = str(candidate.relative_to(dist_info_dir)).replace("\\", "/")
                if rel_k not in license_texts and rel_k not in notice_texts:
                    content = _read_text_safe(candidate).strip()
                    if content:
                        if any(k in candidate.name.upper() for k in _NOTICE_PREFIXES):
                            notice_texts[rel_k] = content
                        else:
                            license_texts[rel_k] = content

    # Discover top-level modules and submodules via top_level.txt and RECORD
    top_modules: set[str] = set()
    all_modules: set[str] = set()
    top_level_file = dist_info_dir / "top_level.txt"
    if top_level_file.is_file():
        for line in _read_text_safe(top_level_file).splitlines():
            mod = line.strip().split("/")[0].split("\\")[0]
            if mod and not mod.startswith("-") and mod.isidentifier():
                top_modules.add(mod)
                all_modules.add(mod)

    record_file = dist_info_dir / "RECORD"
    if record_file.is_file():
        for line in _read_text_safe(record_file, max_bytes=5_000_000).splitlines():
            path_part = line.split(",", 1)[0].strip().replace("\\", "/")
            if not path_part or path_part.startswith(("..", "/")):
                continue
            first_seg = path_part.split("/", 1)[0]
            if (
                first_seg.endswith((".dist-info", ".data", ".egg-info", ".libs", "__pycache__"))
                or first_seg.lower() in _IGNORED_RECORD_TOP_DIRS
            ):
                continue
            if first_seg.endswith(".py"):
                stem = first_seg.removesuffix(".py")
                if stem.isidentifier():
                    top_modules.add(stem)
                    all_modules.add(stem)
            elif ".cpython-" in first_seg or ".cp3" in first_seg or first_seg.endswith((".so", ".pyd")):
                mod_stem = extract_extension_module_name(first_seg)
                if mod_stem:
                    parts = mod_stem.split(".")
                    if all(p.isidentifier() for p in parts):
                        top_modules.add(parts[0])
                        all_modules.add(mod_stem)
            elif "/" in path_part and first_seg.isidentifier():
                top_modules.add(first_seg)
                all_modules.add(first_seg)
                parts = path_part.split("/")
                if len(parts) > 1:
                    for i in range(2, len(parts)):
                        sub_dotted = ".".join(parts[:i])
                        if all(p.isidentifier() for p in sub_dotted.split(".")):
                            all_modules.add(sub_dotted)
                    last_file = parts[-1]
                    if last_file.endswith(".py") and not last_file.startswith("__"):
                        sub_stem = last_file.removesuffix(".py")
                        if sub_stem.isidentifier():
                            full_sub = f"{'.'.join(parts[:-1])}.{sub_stem}"
                            if all(p.isidentifier() for p in full_sub.split(".")):
                                all_modules.add(full_sub)
                    elif (
                        last_file.endswith((".pyd", ".so"))
                        or ".cpython-" in last_file
                        or ".cp3" in last_file
                        or ".abi3." in last_file
                    ):
                        ext_stem = extract_extension_module_name(last_file)
                        if ext_stem:
                            full_ext = f"{'.'.join(parts[:-1])}.{ext_stem}"
                            if all(p.isidentifier() for p in full_ext.split(".")):
                                all_modules.add(full_ext)
                            leaf = ext_stem.split(".")[-1]
                            if leaf.isidentifier():
                                all_modules.add(leaf)
                            if ext_stem.isidentifier():
                                all_modules.add(ext_stem)

    norm_pkg = normalize_pkg_name(name)
    for known_mod in KNOWN_PACKAGE_TOP_MODULES.get(norm_pkg, []):
        top_modules.add(known_mod)
        all_modules.add(known_mod)
    for known_sub in KNOWN_PACKAGE_SUBMODULES.get(norm_pkg, []):
        all_modules.add(known_sub)
    for known_ext in KNOWN_PACKAGE_EXTENSIONS.get(norm_pkg, []):
        all_modules.add(known_ext)
    if not top_modules:
        top_modules.add(name.lower().replace("-", "_"))
        all_modules.add(name.lower().replace("-", "_"))

    lic_info = build_license_info(
        declared_raw=declared_license,
        license_expression=license_expression,
        classifiers=classifiers,
        license_texts=license_texts,
        notice_texts=notice_texts,
        author=author,
        author_email=author_email,
    )

    comp = Component(
        name=norm_pkg,
        version=version,
        component_type=ComponentType.PYTHON_PACKAGE,
        scope=ComponentScope.REQUIRED,
        ecosystem="PyPI",
        description=summary,
        homepage=homepage,
        author=author or author_email,
        license_info=lic_info,
        dependencies=deps,
        top_level_modules=sorted(top_modules),
        discovery_evidence=[f"virtualenv:{dist_info_dir.name}"],
    )
    return comp, top_modules, all_modules


def _discover_dist_native_libraries(
    dist_info_dir: Path,
    pkg_comp: Component,
) -> list[tuple[ElfBinaryInfo, Component]]:
    """
    Discover native shared libraries (.so / .dll) vendored by a Python package
    via its RECORD file or dedicated .libs / delvewheel vendor folders in site-packages.
    """
    results: list[tuple[ElfBinaryInfo, Component]] = []
    seen_files: set[str] = set()

    # 1. Parse RECORD file in .dist-info
    record_file = dist_info_dir / "RECORD"
    if record_file.is_file():
        for line in _read_text_safe(record_file, max_bytes=5_000_000).splitlines():
            parts = line.split(",")
            path_part = parts[0].strip().replace("\\", "/")
            hash_part = parts[1].strip() if len(parts) > 1 else ""
            if not path_part or path_part.startswith(("..", "/")):
                continue
            leaf = path_part.split("/")[-1]
            leaf_lower = leaf.lower()
            if (
                leaf_lower.endswith((".py", ".pyc", ".pyo", ".txt", ".h", ".json", ".dist-info"))
                or leaf_lower.startswith(".load-order-")
            ):
                continue

            is_so = ".so" in leaf_lower
            is_dll = leaf_lower.endswith(".dll")
            is_in_libs = ".libs/" in path_part or path_part.startswith((".libs/", "extra-dll/"))
            is_py_ext = (
                leaf_lower.endswith(".pyd")
                or ".cpython-" in leaf_lower
                or ".cp3" in leaf_lower
                or ".abi3." in leaf_lower
                or ".pypy" in leaf_lower
            )

            if (is_so or is_dll or is_in_libs) and not is_py_ext:
                if leaf in seen_files:
                    continue
                seen_files.add(leaf)

                full_path = dist_info_dir.parent / path_part
                sha256_val = ""
                if hash_part.startswith("sha256="):
                    sha256_val = hash_part.removeprefix("sha256=").strip()

                bin_info: ElfBinaryInfo | None = None
                comp: Component | None = None

                if full_path.is_file():
                    from rhada.elf import elf_to_native_component, is_binary_file, parse_binary

                    if is_binary_file(full_path):
                        with contextlib.suppress(OSError, ValueError, RuntimeError):
                            bin_info = parse_binary(full_path)
                            bin_info.origin_package = pkg_comp.name
                            bin_info.provenance = f"vendored-in-wheel:{pkg_comp.name}"
                            comp = elf_to_native_component(
                                bin_info,
                                origin_package=pkg_comp.name,
                                provenance=f"vendored-in-wheel:{pkg_comp.name}",
                            )
                            if comp:
                                comp.scope = pkg_comp.scope
                                comp.is_bundled = pkg_comp.is_bundled
                                results.append((bin_info, comp))
                else:
                    # File is listed in RECORD but not present on disk (e.g. metadata-only wheel or corrupted tree)
                    if leaf.startswith("_"):
                        continue
                    from rhada.elf import (
                        _infer_library_identity,
                        _match_known_native_profile,
                        _strip_wheel_hashes_and_arch,
                    )
                    from rhada.spdx import classify_single_spdx

                    cleaned_leaf = _strip_wheel_hashes_and_arch(leaf)
                    canonical_key = cleaned_leaf.lower()
                    for ext in (".dll", ".so"):
                        if ext in canonical_key:
                            canonical_key = canonical_key.split(ext, 1)[0]
                    canonical_key = canonical_key.split("-", 1)[0].rstrip("_")
                    profile = _match_known_native_profile(canonical_key)
                    det_name, det_ver = _infer_library_identity(leaf, None, [])
                    if profile:
                        lib_name = profile.canonical_name
                        spdx_id = profile.spdx_id
                        risk_cat = classify_single_spdx(spdx_id)
                        homepage = profile.homepage
                        cop_notices = [profile.copyright_notice]
                        lic_texts = {"EMBEDDED_NATIVE_LICENSE": profile.license_text}
                    else:
                        lib_name = det_name or canonical_key or leaf
                        spdx_id = "NOASSERTION"
                        risk_cat = classify_single_spdx("NOASSERTION")
                        homepage = ""
                        cop_notices = []
                        lic_texts = {}

                    version = det_ver or "unknown"
                    is_pe = leaf_lower.endswith(".dll")
                    ecosystem = "Windows" if is_pe else "Linux"
                    evidence_prefix = "pe-binary" if is_pe else "elf-binary"

                    lic_info = LicenseInfo(
                        declared_raw=spdx_id,
                        spdx_id=spdx_id,
                        risk_category=risk_cat,
                        copyright_notices=cop_notices,
                        license_texts=lic_texts,
                    )
                    bin_info = ElfBinaryInfo(
                        path=str(full_path),
                        soname=leaf,
                        architecture="x86_64",
                        bits=64,
                        endianness="little",
                        is_executable=False,
                        is_shared_object=True,
                        detected_library_name=lib_name,
                        detected_version=version,
                        sha256=sha256_val,
                        binary_format="PE" if is_pe else "ELF",
                        origin_package=pkg_comp.name,
                        provenance=f"vendored-in-wheel:{pkg_comp.name}",
                        license_spdx=spdx_id,
                        copyright=cop_notices[0] if cop_notices else "",
                    )
                    comp = Component(
                        name=lib_name,
                        version=version,
                        component_type=ComponentType.NATIVE_LIBRARY,
                        scope=pkg_comp.scope,
                        ecosystem=ecosystem,
                        description=f"Bundled native shared library ({leaf}, x86_64)",
                        homepage=homepage,
                        license_info=lic_info,
                        hashes={"SHA256": sha256_val} if sha256_val else {},
                        bundled_files=[str(full_path)],
                        is_bundled=pkg_comp.is_bundled,
                        is_statically_compiled=False,
                        has_dynamic_relinking=True,
                        discovery_evidence=[f"{evidence_prefix}:{leaf}"],
                        origin_package=pkg_comp.name,
                        provenance=f"vendored-in-wheel:{pkg_comp.name}",
                        architecture="x86_64",
                        soname=leaf,
                    )
                    results.append((bin_info, comp))

    # 2. Check dedicated vendor directories in site-packages (<pkg>.libs/, etc.)
    sp_dir = dist_info_dir.parent
    candidate_libs_dirs: list[Path] = [
        sp_dir / f"{pkg_comp.name}.libs",
        sp_dir / f"{pkg_comp.name.replace('-', '_')}.libs",
        sp_dir / f"{pkg_comp.name}.dylibs",
        sp_dir / f"{pkg_comp.name.replace('-', '_')}.dylibs",
        sp_dir / pkg_comp.name / ".libs",
        sp_dir / pkg_comp.name.replace("-", "_") / ".libs",
        sp_dir / pkg_comp.name / "extra-dll",
        sp_dir / pkg_comp.name.replace("-", "_") / "extra-dll",
        sp_dir / pkg_comp.name / "libs",
        sp_dir / pkg_comp.name.replace("-", "_") / "libs",
    ]
    for mod in pkg_comp.top_level_modules:
        candidate_libs_dirs.extend([
            sp_dir / f"{mod}.libs",
            sp_dir / f"{mod}.dylibs",
            sp_dir / mod / ".libs",
            sp_dir / mod / "extra-dll",
            sp_dir / mod / "libs",
        ])

    for libs_dir in candidate_libs_dirs:
        if libs_dir.is_dir():
            for bin_file in sorted(libs_dir.iterdir()):
                if not bin_file.is_file():
                    continue
                # Handle delvewheel .load-order-* manifest files
                if bin_file.name.startswith(".load-order-"):
                    load_order_text = _read_text_safe(bin_file)
                    for dll_line in load_order_text.splitlines():
                        dll_leaf = dll_line.strip()
                        if dll_leaf and dll_leaf not in seen_files:
                            seen_files.add(dll_leaf)
                            cand_dll_path = libs_dir / dll_leaf
                            if not cand_dll_path.is_file():
                                cand_dll_path = sp_dir / dll_leaf
                            from rhada.elf import (
                                _infer_library_identity,
                                _match_known_native_profile,
                                _strip_wheel_hashes_and_arch,
                                elf_to_native_component,
                                is_binary_file,
                                parse_binary,
                            )
                            if cand_dll_path.is_file() and is_binary_file(cand_dll_path):
                                with contextlib.suppress(OSError, ValueError, RuntimeError):
                                    b_info = parse_binary(cand_dll_path)
                                    b_info.origin_package = pkg_comp.name
                                    b_info.provenance = f"vendored-in-wheel:{pkg_comp.name}"
                                    c = elf_to_native_component(
                                        b_info,
                                        origin_package=pkg_comp.name,
                                        provenance=f"vendored-in-wheel:{pkg_comp.name}",
                                    )
                                    if c:
                                        c.scope = pkg_comp.scope
                                        c.is_bundled = pkg_comp.is_bundled
                                        results.append((b_info, c))
                            else:
                                cleaned_l = _strip_wheel_hashes_and_arch(dll_leaf)
                                c_key = cleaned_l.lower().split(".dll", 1)[0].split("-", 1)[0].rstrip("_")
                                prof = _match_known_native_profile(c_key)
                                det_n, det_v = _infer_library_identity(dll_leaf, None, [])
                                l_name = prof.canonical_name if prof else (det_n or c_key or dll_leaf)
                                spdx_i = prof.spdx_id if prof else "NOASSERTION"
                                cop_n = [prof.copyright_notice] if prof else []
                                lic_t = {"EMBEDDED_NATIVE_LICENSE": prof.license_text} if prof else {}
                                l_info = LicenseInfo(
                                    declared_raw=spdx_i,
                                    spdx_id=spdx_i,
                                    risk_category=classify_single_spdx(spdx_i),
                                    copyright_notices=cop_n,
                                    license_texts=lic_t,
                                )
                                b_stub = ElfBinaryInfo(
                                    path=str(cand_dll_path),
                                    soname=dll_leaf,
                                    architecture="x86_64",
                                    bits=64,
                                    endianness="little",
                                    is_executable=False,
                                    is_shared_object=True,
                                    detected_library_name=l_name,
                                    detected_version=det_v or "unknown",
                                    binary_format="PE",
                                    origin_package=pkg_comp.name,
                                    provenance=f"vendored-in-wheel:{pkg_comp.name}",
                                    license_spdx=spdx_i,
                                    copyright=cop_n[0] if cop_n else "",
                                )
                                c_stub = Component(
                                    name=l_name,
                                    version=det_v or "unknown",
                                    component_type=ComponentType.NATIVE_LIBRARY,
                                    scope=pkg_comp.scope,
                                    ecosystem="Windows",
                                    description=f"Bundled native shared library ({dll_leaf}, x86_64)",
                                    homepage=prof.homepage if prof else "",
                                    license_info=l_info,
                                    bundled_files=[str(cand_dll_path)],
                                    is_bundled=pkg_comp.is_bundled,
                                    is_statically_compiled=False,
                                    has_dynamic_relinking=True,
                                    discovery_evidence=[f"delvewheel:{dll_leaf}"],
                                    origin_package=pkg_comp.name,
                                    provenance=f"vendored-in-wheel:{pkg_comp.name}",
                                    architecture="x86_64",
                                    soname=dll_leaf,
                                )
                                results.append((b_stub, c_stub))
                    continue

                bname = bin_file.name
                bname_lower = bname.lower()
                if (bname_lower.endswith(".dll") or ".so" in bname_lower) and bname not in seen_files:
                    seen_files.add(bname)
                    from rhada.elf import elf_to_native_component, is_binary_file, parse_binary

                    if is_binary_file(bin_file):
                        with contextlib.suppress(OSError, ValueError, RuntimeError):
                            b_info = parse_binary(bin_file)
                            b_info.origin_package = pkg_comp.name
                            b_info.provenance = f"vendored-in-wheel:{pkg_comp.name}"
                            c = elf_to_native_component(
                                b_info,
                                origin_package=pkg_comp.name,
                                provenance=f"vendored-in-wheel:{pkg_comp.name}",
                            )
                            if c:
                                c.scope = pkg_comp.scope
                                c.is_bundled = pkg_comp.is_bundled
                                results.append((b_info, c))

    return results


def _parse_pyproject_toml(pyproject_path: Path) -> dict[str, Any]:
    """Read and parse pyproject.toml."""
    if not pyproject_path.is_file():
        return {}
    try:
        return tomllib.loads(_read_text_safe(pyproject_path))
    except (tomllib.TOMLDecodeError, OSError):
        return {}


def _parse_uv_lock(uv_lock_path: Path) -> dict[str, Any]:
    """Read and parse uv.lock."""
    if not uv_lock_path.is_file():
        return {}
    try:
        return tomllib.loads(_read_text_safe(uv_lock_path, max_bytes=10_000_000))
    except (tomllib.TOMLDecodeError, OSError):
        return {}


def inspect_workspace(project_path: Path, include_dev: bool = False) -> WorkspaceMetadata:
    """
    Inspect a Python project's uv workspace (pyproject.toml, uv.lock, and .venv)
    to build a complete map of runtime and development dependencies, licences, and modules.
    """
    project_path = project_path.resolve()
    ws = WorkspaceMetadata(root_path=project_path)

    pyproject_file = project_path / "pyproject.toml"
    uv_lock_file = project_path / "uv.lock"
    if not uv_lock_file.is_file() and (project_path.parent / "uv.lock").is_file():
        uv_lock_file = project_path.parent / "uv.lock"

    pyproject_data = _parse_pyproject_toml(pyproject_file)
    project_table = pyproject_data.get("project", {})
    has_explicit_project_metadata = isinstance(project_table, dict) and bool(project_table)
    if isinstance(project_table, dict):
        ws.project_name = normalize_pkg_name(project_table.get("name", project_path.name)) or project_path.name
        ws.project_version = str(project_table.get("version", "0.1.0"))
        ws.project_description = str(project_table.get("description", ""))
        lic_val = project_table.get("license")
        if isinstance(lic_val, str):
            ws.project_license = lic_val
        elif isinstance(lic_val, dict):
            ws.project_license = str(lic_val.get("text") or lic_val.get("file") or "UNKNOWN")

        for req_str in project_table.get("dependencies", []) or []:
            if isinstance(req_str, str):
                dep_name = parse_req_name(req_str)
                if dep_name:
                    ws.direct_runtime_deps.add(dep_name)

        opt_deps = project_table.get("optional-dependencies", {})
        if isinstance(opt_deps, dict):
            for group_name, group_reqs in opt_deps.items():
                if isinstance(group_reqs, list):
                    for req_str in group_reqs:
                        if isinstance(req_str, str):
                            dep_name = parse_req_name(req_str)
                            if dep_name and group_name.lower() in {"dev", "test", "testing", "lint", "build", "docs"}:
                                ws.direct_dev_deps.add(dep_name)

    # PEP 735 dependency-groups and tool.uv.dev-dependencies
    dep_groups = pyproject_data.get("dependency-groups", {})
    if isinstance(dep_groups, dict):
        for group_reqs in dep_groups.values():
            if isinstance(group_reqs, list):
                for item in group_reqs:
                    if isinstance(item, str):
                        dep_name = parse_req_name(item)
                        if dep_name:
                            ws.direct_dev_deps.add(dep_name)

    tool_uv = pyproject_data.get("tool", {}).get("uv", {})
    if isinstance(tool_uv, dict):
        for req_str in tool_uv.get("dev-dependencies", []) or []:
            if isinstance(req_str, str):
                dep_name = parse_req_name(req_str)
                if dep_name:
                    ws.direct_dev_deps.add(dep_name)

    # 1. Inspect virtualenv (.venv) for rich .dist-info metadata and licence texts
    venv_components: dict[str, Component] = {}
    dist_info_entries: list[tuple[Path, Component]] = []
    for sp_dir in _find_site_packages_dirs(project_path):
        for dist_info in sorted(sp_dir.glob("*.dist-info")):
            if not dist_info.is_dir():
                continue
            comp, _top_mods, all_mods = _inspect_dist_info(dist_info)
            if comp is None:
                continue
            venv_components[comp.name] = comp
            dist_info_entries.append((dist_info, comp))
            for mod in all_mods:
                ws.module_to_package[mod] = comp.name
            ws.module_to_package[comp.name.replace("-", "_")] = comp.name

    # 2. Parse uv.lock if present
    lock_data = _parse_uv_lock(uv_lock_file)
    lock_packages = lock_data.get("package", [])
    if isinstance(lock_packages, list) and lock_packages:
        lock_map: dict[str, dict[str, Any]] = {}
        root_pkg_names: set[str] = set()

        for pkg_entry in lock_packages:
            if not isinstance(pkg_entry, dict):
                continue
            pname = normalize_pkg_name(str(pkg_entry.get("name", "")))
            if not pname:
                continue
            if pname in lock_map:
                # Multiple [[package]] entries for the same name (e.g. platform-specific resolutions).
                # Prefer the entry matching the installed .venv version if available, and merge dependencies.
                existing_entry = lock_map[pname]
                venv_ver = venv_components[pname].version if pname in venv_components else None
                cand_ver = str(pkg_entry.get("version", "unknown"))
                merged_deps = list(existing_entry.get("dependencies", []) or [])
                for d in pkg_entry.get("dependencies", []) or []:
                    if d not in merged_deps:
                        merged_deps.append(d)
                chosen = dict(pkg_entry) if venv_ver and cand_ver == venv_ver else dict(existing_entry)
                chosen["dependencies"] = merged_deps
                lock_map[pname] = chosen
            else:
                lock_map[pname] = pkg_entry
            source = pkg_entry.get("source", {})
            if isinstance(source, dict) and (
                "virtual" in source
                or "editable" in source
                or "directory" in source
            ):
                root_pkg_names.add(pname)
            if pname == ws.project_name:
                root_pkg_names.add(pname)

        # Extract direct runtime and dev deps from root package entries in uv.lock
        for rname in root_pkg_names:
            rentry = lock_map.get(rname, {})
            for dep in rentry.get("dependencies", []) or []:
                if isinstance(dep, dict) and "name" in dep:
                    ws.direct_runtime_deps.add(normalize_pkg_name(str(dep["name"])))
            dev_deps_table = rentry.get("dev-dependencies", {})
            if isinstance(dev_deps_table, dict):
                for dlist in dev_deps_table.values():
                    if isinstance(dlist, list):
                        for dep in dlist:
                            if isinstance(dep, dict) and "name" in dep:
                                ws.direct_dev_deps.add(normalize_pkg_name(str(dep["name"])))

        # Traverse transitive runtime dependency graph from direct_runtime_deps
        reachable_runtime: set[str] = set()
        queue = list(ws.direct_runtime_deps)
        while queue:
            curr = queue.pop(0)
            if curr in reachable_runtime or curr in root_pkg_names:
                continue
            reachable_runtime.add(curr)
            entry = lock_map.get(curr, {})
            for dep in entry.get("dependencies", []) or []:
                if isinstance(dep, dict) and "name" in dep:
                    dname = normalize_pkg_name(str(dep["name"]))
                    if dname and dname not in reachable_runtime:
                        queue.append(dname)

        # Traverse transitive dev dependency graph from direct_dev_deps
        reachable_dev: set[str] = set()
        dev_queue = list(ws.direct_dev_deps)
        while dev_queue:
            curr = dev_queue.pop(0)
            if curr in reachable_dev or curr in root_pkg_names:
                continue
            reachable_dev.add(curr)
            entry = lock_map.get(curr, {})
            for dep in entry.get("dependencies", []) or []:
                if isinstance(dep, dict) and "name" in dep:
                    dname = normalize_pkg_name(str(dep["name"]))
                    if dname and dname not in reachable_dev:
                        dev_queue.append(dname)

        # Build merged Component entries for all non-root packages in uv.lock
        for pname, pkg_entry in sorted(lock_map.items()):
            if pname in root_pkg_names:
                continue
            pver = str(pkg_entry.get("version", "unknown"))
            dep_names: list[str] = []
            for dep in pkg_entry.get("dependencies", []) or []:
                if isinstance(dep, dict) and "name" in dep:
                    dname = normalize_pkg_name(str(dep["name"]))
                    if dname and dname not in dep_names:
                        dep_names.append(dname)

            hashes: dict[str, str] = {}
            sdist = pkg_entry.get("sdist", {})
            if isinstance(sdist, dict) and isinstance(sdist.get("hash"), str):
                h = sdist["hash"]
                if ":" in h:
                    alg, val = h.split(":", 1)
                    hashes[alg.upper()] = val
            wheels = pkg_entry.get("wheels", [])
            if not hashes and isinstance(wheels, list) and wheels:
                first_wheel = wheels[0]
                if isinstance(first_wheel, dict) and isinstance(first_wheel.get("hash"), str):
                    h = first_wheel["hash"]
                    if ":" in h:
                        alg, val = h.split(":", 1)
                        hashes[alg.upper()] = val

            is_runtime = pname in reachable_runtime or (
                not ws.direct_runtime_deps
                and not has_explicit_project_metadata
                and not root_pkg_names
                and pname not in reachable_dev
            )
            scope = ComponentScope.REQUIRED if is_runtime else ComponentScope.DEV_EXCLUDED

            if pname in venv_components:
                comp = venv_components[pname]
                if pver != "unknown" and comp.version != pver:
                    comp.version = pver
                    comp.refresh_purl()
                comp.scope = scope
                comp.is_bundled = is_runtime or include_dev
                if dep_names:
                    comp.dependencies = dep_names
                if hashes:
                    comp.hashes.update(hashes)
                if "uv.lock" not in comp.discovery_evidence:
                    comp.discovery_evidence.insert(0, "uv.lock")
            else:
                inferred_mods = sorted({pname.replace("-", "_"), *KNOWN_PACKAGE_TOP_MODULES.get(pname, [])})
                comp = Component(
                    name=pname,
                    version=pver,
                    component_type=ComponentType.PYTHON_PACKAGE,
                    scope=scope,
                    ecosystem="PyPI",
                    hashes=hashes,
                    dependencies=dep_names,
                    top_level_modules=inferred_mods,
                    is_bundled=is_runtime or include_dev,
                    discovery_evidence=["uv.lock"],
                )
                for imod in inferred_mods:
                    ws.module_to_package[imod] = pname
                for submod in KNOWN_PACKAGE_SUBMODULES.get(pname, []):
                    ws.module_to_package[submod] = pname
                for extmod in KNOWN_PACKAGE_EXTENSIONS.get(pname, []):
                    ws.module_to_package[extmod] = pname

            ws.components[pname] = comp

        # Include any additional packages found in .venv that were not in uv.lock
        for pname, comp in sorted(venv_components.items()):
            if pname in ws.components or pname in root_pkg_names:
                continue
            comp.scope = ComponentScope.OPTIONAL
            comp.is_bundled = include_dev
            ws.components[pname] = comp
    else:
        # No uv.lock present: rely on .venv + pyproject.toml
        reachable_runtime = set()
        if ws.direct_runtime_deps:
            queue = list(ws.direct_runtime_deps)
            while queue:
                curr = queue.pop(0)
                if curr in reachable_runtime or curr == ws.project_name:
                    continue
                reachable_runtime.add(curr)
                vcomp = venv_components.get(curr)
                if vcomp:
                    for dname in vcomp.dependencies:
                        if dname not in reachable_runtime:
                            queue.append(dname)

        reachable_dev = set()
        if ws.direct_dev_deps:
            dev_queue = list(ws.direct_dev_deps)
            while dev_queue:
                curr = dev_queue.pop(0)
                if curr in reachable_dev or curr == ws.project_name:
                    continue
                reachable_dev.add(curr)
                vcomp = venv_components.get(curr)
                if vcomp:
                    for dname in vcomp.dependencies:
                        if dname not in reachable_dev:
                            dev_queue.append(dname)

        for pname, comp in sorted(venv_components.items()):
            if pname == ws.project_name:
                continue
            if ws.direct_runtime_deps:
                is_runtime = pname in reachable_runtime
            elif has_explicit_project_metadata and ws.direct_dev_deps:
                is_runtime = False
            else:
                is_runtime = pname not in reachable_dev
            comp.scope = ComponentScope.REQUIRED if is_runtime else ComponentScope.DEV_EXCLUDED
            comp.is_bundled = is_runtime or include_dev
            ws.components[pname] = comp

        # If neither uv.lock nor .venv had entries for declared dependencies in pyproject.toml, add stubs
        for dep_name in sorted(ws.direct_runtime_deps):
            if dep_name not in ws.components and dep_name != ws.project_name:
                inferred_mods = sorted({dep_name.replace("-", "_"), *KNOWN_PACKAGE_TOP_MODULES.get(dep_name, [])})
                ws.components[dep_name] = Component(
                    name=dep_name,
                    version="unknown",
                    component_type=ComponentType.PYTHON_PACKAGE,
                    scope=ComponentScope.REQUIRED,
                    ecosystem="PyPI",
                    top_level_modules=inferred_mods,
                    is_bundled=True,
                    discovery_evidence=["pyproject.toml"],
                )
                for imod in inferred_mods:
                    ws.module_to_package[imod] = dep_name
                for submod in KNOWN_PACKAGE_SUBMODULES.get(dep_name, []):
                    ws.module_to_package[submod] = dep_name
                for extmod in KNOWN_PACKAGE_EXTENSIONS.get(dep_name, []):
                    ws.module_to_package[extmod] = dep_name

    # Discover vendored native shared libraries from installed distributions
    for dist_info, comp in dist_info_entries:
        if comp.name not in ws.components:
            continue
        final_comp = ws.components[comp.name]
        native_results = _discover_dist_native_libraries(dist_info, final_comp)
        for b_info, nat_comp in native_results:
            nat_comp.scope = final_comp.scope
            nat_comp.is_bundled = final_comp.is_bundled
            ws.native_components.append(nat_comp)
            pkg_libs = ws.package_libraries.setdefault(final_comp.name, [])
            if nat_comp.name not in pkg_libs:
                pkg_libs.append(nat_comp.name)
            b_leaf = Path(b_info.path.replace("\\", "/")).name
            if b_leaf and b_leaf not in pkg_libs:
                pkg_libs.append(b_leaf)
            if b_info.soname and b_info.soname not in pkg_libs:
                pkg_libs.append(b_info.soname)
            if final_comp.is_bundled or include_dev:
                ws.elf_binaries.append(b_info)
            if nat_comp.name not in ws.components:
                ws.components[nat_comp.name] = nat_comp

    return ws
