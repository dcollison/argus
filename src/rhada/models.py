"""Core data models for Rhada audit reports, components, ELF linkage, compliance, and vulnerabilities."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from pathlib import Path
from typing import Any

from packageurl import PackageURL


class ExitCode(IntEnum):
    """Standardised CLI exit codes for CI/CD gate integration."""

    OK = 0
    VULNERABILITY_FAILURE = 1
    LICENSE_FAILURE = 2
    COMBINED_POLICY_FAILURE = 3
    LINKAGE_FAILURE = 4
    USAGE_OR_IO_ERROR = 5


class AuditMode(StrEnum):
    """Operating mode of the Rhada audit."""

    SOURCE = "source"
    COMPILED_DIST = "compiled-dist"


class BundlerType(StrEnum):
    """Detected bundler technology for compiled distributions."""

    NONE = "none"
    NUITKA = "nuitka"
    PYINSTALLER = "pyinstaller"
    GENERIC_ELF = "generic-elf"
    GENERIC_PE = "generic-pe"


class DistributionLayout(StrEnum):
    """Layout of a compiled distribution."""

    SOURCE_WORKSPACE = "source-workspace"
    STANDALONE_DIR = "standalone-directory"
    MONOLITHIC_BINARY = "monolithic-binary"


class ComponentType(StrEnum):
    """Type of software component."""

    PYTHON_PACKAGE = "python-package"
    NATIVE_LIBRARY = "native-library"
    APPLICATION = "application"
    RUNTIME = "runtime"


class ComponentScope(StrEnum):
    """Dependency scope of a component."""

    REQUIRED = "required"
    OPTIONAL = "optional"
    DEV_EXCLUDED = "dev-or-build-excluded"


LEGAL_DISCLAIMER: str = (
    "Rhada is an automated technical audit tool and does not provide legal advice or guarantee "
    "legal compliance. Output reports, SBOMs, and licence classifications should be reviewed by qualified legal counsel."
)


class LicenseRiskCategory(StrEnum):
    """Legal risk category of a component's declared licence."""

    PERMISSIVE = "permissive"
    WEAK_COPYLEFT = "weak-copyleft"
    STRONG_COPYLEFT = "strong-copyleft"
    PROPRIETARY = "proprietary"
    PUBLIC_DOMAIN = "public-domain"
    UNKNOWN = "unknown"


class SbomFormat(StrEnum):
    """Supported Software Bill of Materials output standards."""

    CYCLONEDX = "cyclonedx"
    SPDX = "spdx"


class ConsoleFormat(StrEnum):
    """Supported console report output formats."""

    TABLE = "table"
    JSON = "json"


class Severity(StrEnum):
    """Standardised severity ranking for vulnerabilities and compliance findings."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = {
            Severity.NONE: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        return order[self]

    def meets_threshold(self, threshold: Severity) -> bool:
        if threshold == Severity.NONE:
            return False
        return self.rank >= threshold.rank


class LinkageStatus(StrEnum):
    """Resolution status of an ELF DT_NEEDED dependency."""

    BUNDLED = "bundled"
    SYSTEM_ABI = "system-abi"
    MISSING_EXTERNAL = "missing-external"
    STATIC = "static"


@dataclass(slots=True)
class LicenseInfo:
    """Licensing and attribution details for a component."""

    declared_raw: str = "UNKNOWN"
    spdx_id: str = "NOASSERTION"
    risk_category: LicenseRiskCategory = LicenseRiskCategory.UNKNOWN
    copyright_notices: list[str] = field(default_factory=list)
    license_texts: dict[str, str] = field(default_factory=dict)
    notice_texts: dict[str, str] = field(default_factory=dict)
    is_dual_licensed: bool = False
    license_choices: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "declared_raw": self.declared_raw,
            "spdx_id": self.spdx_id,
            "risk_category": self.risk_category.value,
            "copyright_notices": list(self.copyright_notices),
            "license_texts": dict(self.license_texts),
            "notice_texts": dict(self.notice_texts),
            "is_dual_licensed": self.is_dual_licensed,
            "license_choices": list(self.license_choices),
        }


@dataclass(slots=True)
class Vulnerability:
    """Security vulnerability discovered for a component."""

    id: str
    summary: str
    details: str = ""
    aliases: list[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    cvss_score: float | None = None
    cvss_vector: str | None = None
    fixed_versions: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    component_name: str = ""
    component_version: str = ""
    ecosystem: str = "PyPI"

    @property
    def primary_cve(self) -> str | None:
        if self.id.startswith("CVE-"):
            return self.id
        for alias in self.aliases:
            if alias.startswith("CVE-"):
                return alias
        return None

    @property
    def remediation(self) -> str:
        if self.fixed_versions:
            from packaging.version import InvalidVersion, Version

            def _ver_key(v_str: str) -> tuple[int, Any]:
                try:
                    return (0, Version(v_str))
                except InvalidVersion:
                    return (1, v_str)

            joined = ", ".join(sorted(set(self.fixed_versions), key=_ver_key))
            return f"Upgrade {self.component_name} to version >= {joined}"
        return f"No patched version published yet for {self.component_name}; review advisory {self.id} for mitigations."

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "primary_cve": self.primary_cve,
            "summary": self.summary,
            "details": self.details,
            "aliases": list(self.aliases),
            "severity": self.severity.value,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "fixed_versions": list(self.fixed_versions),
            "remediation": self.remediation,
            "references": list(self.references),
            "component_name": self.component_name,
            "component_version": self.component_version,
            "ecosystem": self.ecosystem,
        }


@dataclass(slots=True)
class Component:
    """Represents a discovered software component (Python package or native library)."""

    name: str
    version: str
    component_type: ComponentType = ComponentType.PYTHON_PACKAGE
    scope: ComponentScope = ComponentScope.REQUIRED
    purl: str = ""
    ecosystem: str = "PyPI"
    description: str = ""
    homepage: str = ""
    source_url: str = ""
    author: str = ""
    license_info: LicenseInfo = field(default_factory=LicenseInfo)
    hashes: dict[str, str] = field(default_factory=dict)
    dependencies: list[str] = field(default_factory=list)
    top_level_modules: list[str] = field(default_factory=list)
    bundled_files: list[str] = field(default_factory=list)
    is_bundled: bool = True
    is_statically_compiled: bool = False
    has_dynamic_relinking: bool = True
    discovery_evidence: list[str] = field(default_factory=list)
    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    origin_package: str | None = None
    provenance: str = ""
    architecture: str = ""
    soname: str | None = None

    def __post_init__(self) -> None:
        if not self.purl:
            self.refresh_purl()

    def refresh_purl(self) -> None:
        norm_name = self.name.strip().lower().replace("_", "-") or "unknown"
        pkg_type = "pypi" if self.component_type == ComponentType.PYTHON_PACKAGE else "generic"
        version = self.version if (self.version and self.version != "unknown") else None
        self.purl = PackageURL(type=pkg_type, name=norm_name, version=version).to_string()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "component_type": self.component_type.value,
            "scope": self.scope.value,
            "purl": self.purl,
            "ecosystem": self.ecosystem,
            "description": self.description,
            "homepage": self.homepage,
            "source_url": self.source_url,
            "author": self.author,
            "license_info": self.license_info.to_dict(),
            "hashes": dict(self.hashes),
            "dependencies": list(self.dependencies),
            "top_level_modules": list(self.top_level_modules),
            "bundled_files": list(self.bundled_files),
            "is_bundled": self.is_bundled,
            "is_statically_compiled": self.is_statically_compiled,
            "has_dynamic_relinking": self.has_dynamic_relinking,
            "discovery_evidence": list(self.discovery_evidence),
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "origin_package": self.origin_package,
            "provenance": self.provenance,
            "architecture": self.architecture,
            "soname": self.soname,
        }


@dataclass(slots=True)
class ElfBinaryInfo:
    """Parsed metadata from an ELF or Windows PE executable or shared library (.so, .dll, .pyd, .exe)."""

    path: str
    soname: str | None = None
    needed_libs: list[str] = field(default_factory=list)
    rpath: str | None = None
    runpath: str | None = None
    architecture: str = "x86_64"
    bits: int = 64
    endianness: str = "little"
    is_executable: bool = False
    is_shared_object: bool = True
    is_statically_linked: bool = False
    interpreter: str | None = None
    detected_library_name: str | None = None
    detected_version: str | None = None
    exported_symbols_sample: list[str] = field(default_factory=list)
    ident_strings: list[str] = field(default_factory=list)
    sha256: str = ""
    binary_format: str = "ELF"
    origin_package: str | None = None
    provenance: str = ""
    license_spdx: str = "NOASSERTION"
    copyright: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


BinaryInfo = ElfBinaryInfo


@dataclass(slots=True)
class LinkageIssue:
    """A binary linkage finding or resolution status entry."""

    binary_path: str
    needed_lib: str
    status: LinkageStatus
    severity: Severity
    message: str
    resolved_path: str | None = None
    origin_package: str | None = None
    provenance: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "binary_path": self.binary_path,
            "needed_lib": self.needed_lib,
            "status": self.status.value,
            "severity": self.severity.value,
            "message": self.message,
            "resolved_path": self.resolved_path,
            "origin_package": self.origin_package,
            "provenance": self.provenance,
        }


@dataclass(slots=True)
class BinaryLinkageReport:
    """Aggregated binary linkage verification report for a compiled distribution."""

    elf_binaries: list[ElfBinaryInfo] = field(default_factory=list)
    linkage_issues: list[LinkageIssue] = field(default_factory=list)
    resolved_dependencies: dict[str, str] = field(default_factory=dict)
    system_abi_dependencies: list[str] = field(default_factory=list)
    unresolved_dependencies: list[str] = field(default_factory=list)
    insecure_rpaths: list[str] = field(default_factory=list)
    binary_origins: dict[str, str] = field(default_factory=dict)
    package_libraries: dict[str, list[str]] = field(default_factory=dict)

    @property
    def binaries(self) -> list[ElfBinaryInfo]:
        return self.elf_binaries

    @property
    def issues(self) -> list[LinkageIssue]:
        return self.linkage_issues

    @property
    def is_self_contained(self) -> bool:
        return len(self.unresolved_dependencies) == 0 and len(self.insecure_rpaths) == 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "elf_binaries": [b.to_dict() for b in self.elf_binaries],
            "linkage_issues": [i.to_dict() for i in self.linkage_issues],
            "resolved_dependencies": dict(self.resolved_dependencies),
            "system_abi_dependencies": list(self.system_abi_dependencies),
            "unresolved_dependencies": list(self.unresolved_dependencies),
            "insecure_rpaths": list(self.insecure_rpaths),
            "binary_origins": dict(self.binary_origins),
            "package_libraries": {k: list(v) for k, v in self.package_libraries.items()},
            "is_self_contained": self.is_self_contained,
        }


@dataclass(slots=True)
class ComplianceFinding:
    """A legal or licence compliance warning or violation."""

    rule_id: str
    component_name: str
    component_version: str
    license_spdx: str
    risk_category: LicenseRiskCategory
    severity: Severity
    title: str
    description: str
    remediation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "component_name": self.component_name,
            "component_version": self.component_version,
            "license_spdx": self.license_spdx,
            "risk_category": self.risk_category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
        }


@dataclass(slots=True)
class AuditConfig:
    """Configuration for a Rhada audit run."""

    project_path: Path = field(default_factory=lambda: Path("."))
    dist_path: Path | None = None
    compilation_report_path: Path | None = None
    include_dev: bool = False
    offline: bool = False
    osv_timeout: float = 15.0
    fail_on_severity: Severity = Severity.HIGH
    fail_on_license: Severity = Severity.HIGH
    fail_on_linkage: bool = False
    allow_unknown_license: bool = False
    allowed_licenses: set[str] = field(default_factory=set)
    denied_licenses: set[str] = field(default_factory=set)
    company_licenses: set[str] = field(default_factory=set)
    sbom_output: Path | None = None
    sbom_format: str = "cyclonedx"
    notices_output: Path | None = None
    report_output: Path | None = None


@dataclass(slots=True)
class AuditReport:
    """Complete result of a Rhada audit."""

    target_name: str
    target_version: str
    mode: AuditMode
    bundler_type: BundlerType = BundlerType.NONE
    layout: DistributionLayout = DistributionLayout.SOURCE_WORKSPACE
    timestamp: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    project_path: str = ""
    dist_path: str | None = None
    components: list[Component] = field(default_factory=list)
    excluded_components: list[Component] = field(default_factory=list)
    compliance_findings: list[ComplianceFinding] = field(default_factory=list)
    linkage_report: BinaryLinkageReport | None = None
    exit_code: ExitCode = ExitCode.OK
    warnings: list[str] = field(default_factory=list)
    disclaimer: str = LEGAL_DISCLAIMER

    @property
    def bundled_python_components(self) -> list[Component]:
        return [
            c
            for c in self.components
            if c.component_type == ComponentType.PYTHON_PACKAGE and c.is_bundled
        ]

    @property
    def native_components(self) -> list[Component]:
        return [
            c
            for c in self.components
            if c.component_type == ComponentType.NATIVE_LIBRARY and c.is_bundled
        ]

    @property
    def all_vulnerabilities(self) -> list[Vulnerability]:
        vulns: list[Vulnerability] = []
        for comp in self.components:
            if comp.is_bundled:
                vulns.extend(comp.vulnerabilities)
        return vulns

    def vulnerability_counts_by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)}
        for v in self.all_vulnerabilities:
            if v.severity.value in counts:
                counts[v.severity.value] += 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_name": self.target_name,
            "target_version": self.target_version,
            "mode": self.mode.value,
            "bundler_type": self.bundler_type.value,
            "layout": self.layout.value,
            "timestamp": self.timestamp,
            "project_path": self.project_path,
            "dist_path": self.dist_path,
            "summary": {
                "total_active_components": len(self.components),
                "python_packages": len(self.bundled_python_components),
                "native_libraries": len(self.native_components),
                "excluded_dev_build_components": len(self.excluded_components),
                "total_vulnerabilities": len(self.all_vulnerabilities),
                "vulnerabilities_by_severity": self.vulnerability_counts_by_severity(),
                "compliance_findings_count": len(self.compliance_findings),
                "exit_code": int(self.exit_code),
                "passed": self.exit_code == ExitCode.OK,
            },
            "components": [c.to_dict() for c in self.components],
            "excluded_components": [c.to_dict() for c in self.excluded_components],
            "compliance_findings": [f.to_dict() for f in self.compliance_findings],
            "linkage_report": self.linkage_report.to_dict() if self.linkage_report else None,
            "warnings": list(self.warnings),
            "disclaimer": self.disclaimer,
        }
