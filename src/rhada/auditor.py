"""Core orchestrator for Rhada source-workspace and compiled-distribution audits."""

from __future__ import annotations

import httpx

from rhada.compliance import evaluate_compliance, write_third_party_notices
from rhada.dist import (
    build_distribution_file_inventory,
    correlate_workspace_and_dist,
    inspect_compiled_distribution,
)
from rhada.models import (
    AuditConfig,
    AuditMode,
    AuditReport,
    BundlerType,
    DistributionLayout,
    ExitCode,
)
from rhada.osv import OsvClient
from rhada.reporter import write_json_report
from rhada.sbom import write_sbom
from rhada.workspace import inspect_workspace


def compute_exit_code(report: AuditReport, config: AuditConfig) -> ExitCode:
    """
    Determine the standardised CLI exit code based on policy thresholds:
    - 0: OK
    - 1: VULNERABILITY_FAILURE
    - 2: LICENSE_FAILURE
    - 3: COMBINED_POLICY_FAILURE (both vulnerability and licence failures)
    - 4: LINKAGE_FAILURE (when fail_on_linkage is enabled and linkage is not self-contained)
    """
    has_vuln_failure = any(v.severity.meets_threshold(config.fail_on_severity) for v in report.all_vulnerabilities)
    has_license_failure = any(f.severity.meets_threshold(config.fail_on_license) for f in report.compliance_findings)

    if has_vuln_failure and has_license_failure:
        return ExitCode.COMBINED_POLICY_FAILURE
    if has_vuln_failure:
        return ExitCode.VULNERABILITY_FAILURE
    if has_license_failure:
        return ExitCode.LICENSE_FAILURE

    if config.fail_on_linkage and report.linkage_report is not None and not report.linkage_report.is_self_contained:
        return ExitCode.LINKAGE_FAILURE

    return ExitCode.OK


def run_audit(
    config: AuditConfig,
    http_client: httpx.Client | None = None,
) -> AuditReport:
    """
    Execute a full Rhada compliance, SBOM, binary linkage, and security audit.
    - When `config.dist_path` is None: runs in Source-Only mode against `config.project_path`.
    - When `config.dist_path` is provided: inspects the compiled Nuitka/PyInstaller distribution,
      correlates bundled modules with workspace metadata, verifies ELF linkage, and audits
      both Python and native components.
    """
    project_path = config.project_path.resolve()
    ws = inspect_workspace(project_path, include_dev=config.include_dev)

    if config.dist_path is None:
        # Source-Only Mode
        active = [c for c in ws.components.values() if c.is_bundled]
        excluded = [c for c in ws.components.values() if not c.is_bundled]
        linkage_rep = None
        if ws.elf_binaries:
            from rhada.elf import verify_binary_linkage

            linkage_rep = verify_binary_linkage(ws.elf_binaries, dist_root=None)
        report = AuditReport(
            target_name=ws.project_name,
            target_version=ws.project_version,
            mode=AuditMode.SOURCE,
            bundler_type=BundlerType.NONE,
            layout=DistributionLayout.SOURCE_WORKSPACE,
            project_path=str(project_path),
            dist_path=None,
            components=active,
            excluded_components=excluded,
            linkage_report=linkage_rep,
        )
    else:
        # Compiled Distribution Audit Mode
        dist_path = config.dist_path.resolve()
        dist_res = inspect_compiled_distribution(
            dist_path,
            compilation_report_path=config.compilation_report_path,
        )
        active, excluded = correlate_workspace_and_dist(
            ws,
            dist_res,
            include_dev=config.include_dev,
        )
        target_name = ws.project_name if ws.project_name != "unknown-project" else dist_path.stem
        report = AuditReport(
            target_name=target_name,
            target_version=ws.project_version,
            mode=AuditMode.COMPILED_DIST,
            bundler_type=dist_res.bundler_type,
            layout=dist_res.layout,
            project_path=str(project_path),
            dist_path=str(dist_path),
            components=active,
            excluded_components=excluded,
            linkage_report=dist_res.linkage_report,
            warnings=list(dist_res.warnings),
        )

        # Build distribution file accounting inventory
        all_native = report.native_components or (dist_res.native_components if dist_res else [])
        report.file_inventory = build_distribution_file_inventory(
            dist_path=dist_path,
            target_name=target_name,
            target_version=ws.project_version,
            components=report.components,
            native_components=all_native,
            ws=ws,
            dist_res=dist_res,
        )
        if report.file_inventory.unaccounted_files:
            unacc_count = len(report.file_inventory.unaccounted_files)
            sample = ", ".join(f.path for f in report.file_inventory.unaccounted_files[:3])
            report.warnings.append(
                f"{unacc_count} unaccounted file(s) found in distribution directory (e.g. {sample}). "
                "Run with --verbose to view complete distribution file inventory."
            )

    # Evaluate legal & licensing compliance
    report.compliance_findings = evaluate_compliance(
        report.components,
        mode=report.mode,
        layout=report.layout,
        config=config,
    )

    # Check security vulnerabilities via OSV.dev unless offline
    if not config.offline:
        osv_client = OsvClient(timeout=config.osv_timeout, http_client=http_client)
        osv_warnings = osv_client.audit_components(report.components)
        report.warnings.extend(osv_warnings)

    # Compute exit code
    report.exit_code = compute_exit_code(report, config)

    # Generate requested output artefacts
    if config.sbom_output is not None:
        write_sbom(report, config.sbom_output, fmt=config.sbom_format)

    if config.notices_output is not None:
        write_third_party_notices(report, config.notices_output)

    if config.report_output is not None:
        write_json_report(report, config.report_output)

    return report
