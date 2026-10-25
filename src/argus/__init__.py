"""Argus: Legal compliance, SBOM generation, and security auditor for Python and compiled distributions."""

__version__ = "0.1.0"

from argus.auditor import compute_exit_code, run_audit
from argus.elf import is_pe_file, parse_pe_binary
from argus.models import (
    AuditConfig,
    AuditMode,
    AuditReport,
    BinaryInfo,
    BinaryLinkageReport,
    BundlerType,
    ComplianceFinding,
    Component,
    ComponentScope,
    ComponentType,
    ConsoleFormat,
    DistributionLayout,
    ElfBinaryInfo,
    ExitCode,
    LicenseInfo,
    LicenseRiskCategory,
    LinkageIssue,
    LinkageStatus,
    SbomFormat,
    Severity,
    Vulnerability,
)

__all__ = [
    "AuditConfig",
    "AuditMode",
    "AuditReport",
    "BinaryInfo",
    "BinaryLinkageReport",
    "BundlerType",
    "ComplianceFinding",
    "Component",
    "ComponentScope",
    "ComponentType",
    "ConsoleFormat",
    "DistributionLayout",
    "ElfBinaryInfo",
    "ExitCode",
    "LicenseInfo",
    "LicenseRiskCategory",
    "LinkageIssue",
    "LinkageStatus",
    "SbomFormat",
    "Severity",
    "Vulnerability",
    "__version__",
    "compute_exit_code",
    "is_pe_file",
    "parse_pe_binary",
    "run_audit",
]
