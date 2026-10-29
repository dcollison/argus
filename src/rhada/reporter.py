"""Human-readable Rich console and structured JSON/Markdown report formatters."""

from __future__ import annotations

import json
from io import StringIO
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rhada.models import (
    AuditReport,
    DistributionFileCategory,
    ExitCode,
    LicenseRiskCategory,
    Severity,
)

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.NONE: "green",
}

RISK_COLORS: dict[LicenseRiskCategory, str] = {
    LicenseRiskCategory.STRONG_COPYLEFT: "bold red",
    LicenseRiskCategory.PROPRIETARY: "red",
    LicenseRiskCategory.WEAK_COPYLEFT: "yellow",
    LicenseRiskCategory.UNKNOWN: "magenta",
    LicenseRiskCategory.PERMISSIVE: "green",
    LicenseRiskCategory.PUBLIC_DOMAIN: "bright_green",
}

FILE_CATEGORY_COLORS: dict[DistributionFileCategory, str] = {
    DistributionFileCategory.APPLICATION_BINARY: "bold cyan",
    DistributionFileCategory.PYTHON_RUNTIME: "green",
    DistributionFileCategory.COMPILER_ABI: "magenta",
    DistributionFileCategory.NATIVE_LIBRARY: "bright_blue",
    DistributionFileCategory.PYTHON_PACKAGE: "blue",
    DistributionFileCategory.DATA_OR_METADATA: "dim",
    DistributionFileCategory.UNACCOUNTED: "bold red",
}


def _format_size(size_bytes: int) -> str:
    """Format byte count into human-readable size string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def render_console_report(
    report: AuditReport,
    console: Console | None = None,
    verbose: bool = False,
) -> None:
    """Render a comprehensive human-readable compliance & security report to a Rich Console."""
    out = console or Console(safe_box=True)

    status_color = "green" if report.exit_code == ExitCode.OK else "bold red"
    status_label = (
        "PASSED"
        if report.exit_code == ExitCode.OK
        else f"FAILED ({report.exit_code.name}, exit={int(report.exit_code)})"
    )

    tgt_ver = (
        "[dim]unknown[/dim]"
        if report.target_version in ("unknown", "0.0.0", "")
        else report.target_version
    )
    header = Text()
    header.append("Target: ", style="bold")
    header.append(f"{report.target_name}@{tgt_ver}\n")
    header.append("Mode:   ", style="bold")
    header.append(f"{report.mode.value} (layout={report.layout.value}, bundler={report.bundler_type.value})\n")
    header.append("Status: ", style="bold")
    header.append(status_label, style=status_color)

    out.print(Panel(header, title="[bold]Rhada Compliance & Security Audit[/bold]", expand=False, safe_box=True))

    # 1. Component Inventory Table
    # 1. Component Inventory Table
    comp_table = Table(title="Bundled / Active Runtime Components", show_lines=False, safe_box=True)
    comp_table.add_column("Component", style="bold", overflow="fold")
    comp_table.add_column("Version", overflow="fold")
    comp_table.add_column("Type", overflow="fold")
    comp_table.add_column("Provenance", overflow="fold")
    comp_table.add_column("Licence (SPDX)", overflow="fold")
    comp_table.add_column("Risk Category", overflow="fold")
    comp_table.add_column("Relinkable", justify="center", overflow="fold")
    comp_table.add_column("Vulns", justify="right")

    bundled = sorted(
        (c for c in report.components if c.is_bundled),
        key=lambda c: (c.component_type.value, c.name.lower()),
    )
    for comp in bundled:
        risk_cat = comp.license_info.risk_category
        risk_style = RISK_COLORS.get(risk_cat, "white")
        vcount = len(comp.vulnerabilities)
        v_style = "bold red" if vcount > 0 else "green"
        relink_str = "Yes" if comp.has_dynamic_relinking else "No (Static/Onefile)"
        prov_str = ""
        if comp.origin_package:
            prov_str = f"vendored ({comp.origin_package})"
        elif comp.is_internal:
            prov_str = "internal package"
            risk_style = "cyan"
        elif comp.provenance:
            prov_str = comp.provenance
        elif comp.component_type.value == "python-package":
            prov_str = "PyPI package"

        ver_str = "[dim]unknown[/dim]" if comp.version in ("unknown", "", "0.0.0") else comp.version
        comp_table.add_row(
            comp.name,
            ver_str,
            comp.component_type.value,
            prov_str,
            comp.license_info.spdx_id,
            f"[{risk_style}]{risk_cat.value}[/{risk_style}]",
            relink_str,
            f"[{v_style}]{vcount}[/{v_style}]",
        )
    out.print(comp_table)

    # 2. Excluded Build / Dev Tools Summary (when in compiled distribution mode or when dev tools excluded)
    if report.excluded_components:
        excl_names = ", ".join(
            sorted(
                f"{c.name}@"
                + ("[dim]unknown[/dim]" if c.version in ("unknown", "", "0.0.0") else c.version)
                for c in report.excluded_components
            )
        )
        out.print(
            Panel(
                f"[dim]{excl_names}[/dim]",
                title=f"Excluded Build / Dev Dependencies ({len(report.excluded_components)} omitted from bundle)",
                expand=False,
                safe_box=True,
            )
        )

    # 3. Binary Linkage Report
    if report.linkage_report is not None:
        lr = report.linkage_report
        link_table = Table(title="ELF / PE Binary Linkage & Native Dependencies", safe_box=True)
        link_table.add_column("Metric", style="bold")
        link_table.add_column("Value")
        link_table.add_row("Inspected Native Binaries", str(len(lr.elf_binaries)))
        if lr.package_libraries:
            for pkg_name, libs in sorted(lr.package_libraries.items()):
                link_table.add_row(f"Vendored by {pkg_name}", ", ".join(sorted(libs)))
        link_table.add_row(
            "Bundled Shared Libraries Resolved",
            ", ".join(sorted(lr.resolved_dependencies.keys())) or "None",
        )
        link_table.add_row(
            "System ABI Libraries (glibc/Win32/OS)",
            ", ".join(sorted(lr.system_abi_dependencies)) or "None",
        )
        unres_str = (
            f"[bold red]{', '.join(lr.unresolved_dependencies)}[/bold red]"
            if lr.unresolved_dependencies
            else "[green]0 unresolved[/green]"
        )
        link_table.add_row("Unresolved External Libraries", unres_str)
        rpath_str = (
            f"[bold yellow]{'; '.join(lr.insecure_rpaths)}[/bold yellow]"
            if lr.insecure_rpaths
            else "[green]Clean ($ORIGIN / standard)[/green]"
        )
        link_table.add_row("RPATH / RUNPATH Hygiene", rpath_str)

        if report.file_inventory is not None:
            fi = report.file_inventory
            cov_pct = fi.coverage_percent
            cov_style = "green" if cov_pct == 100.0 else "bold yellow"
            counts = fi.counts_by_category()
            parts = [
                f"{counts[cat_val]} {cat_val.replace('-', ' ')}"
                for cat_val in (
                    DistributionFileCategory.APPLICATION_BINARY.value,
                    DistributionFileCategory.PYTHON_RUNTIME.value,
                    DistributionFileCategory.COMPILER_ABI.value,
                    DistributionFileCategory.NATIVE_LIBRARY.value,
                    DistributionFileCategory.PYTHON_PACKAGE.value,
                    DistributionFileCategory.DATA_OR_METADATA.value,
                )
                if cat_val in counts
            ]
            counts_str = ", ".join(parts) or "0 classified"
            link_table.add_row(
                "Distribution File Coverage",
                f"[{cov_style}]{cov_pct:.1f}%[/{cov_style}] ({fi.classified_count}/{fi.total_files} files classified: {counts_str})",
            )
            if fi.unaccounted_files:
                unacc_names = ", ".join(f.path for f in fi.unaccounted_files[:5])
                link_table.add_row(
                    "Unaccounted Distribution Files",
                    f"[bold red]{len(fi.unaccounted_files)} unclassified ({unacc_names})[/bold red]",
                )

        out.print(link_table)
    elif report.file_inventory is not None:
        fi = report.file_inventory
        cov_pct = fi.coverage_percent
        cov_style = "green" if cov_pct == 100.0 else "bold yellow"
        file_summary_table = Table(title="Distribution File Accounting & Coverage", safe_box=True)
        file_summary_table.add_column("Metric", style="bold")
        file_summary_table.add_column("Value")
        file_summary_table.add_row("Total Distribution Files", str(fi.total_files))
        file_summary_table.add_row("Total Size", _format_size(fi.total_bytes))
        counts = fi.counts_by_category()
        counts_str = ", ".join(f"{count} {cat.replace('-', ' ')}" for cat, count in sorted(counts.items()))
        file_summary_table.add_row(
            "Coverage",
            f"[{cov_style}]{cov_pct:.1f}%[/{cov_style}] ({fi.classified_count}/{fi.total_files} files: {counts_str})",
        )
        if fi.unaccounted_files:
            unacc_names = ", ".join(f.path for f in fi.unaccounted_files[:5])
            file_summary_table.add_row(
                "Unaccounted Files",
                f"[bold red]{len(fi.unaccounted_files)} unclassified ({unacc_names})[/bold red]",
            )
        out.print(file_summary_table)

    # 4. Detailed Distribution File Inventory Table (when verbose mode is active)
    if verbose and report.file_inventory is not None:
        fi = report.file_inventory
        file_table = Table(
            title=f"Distribution File Accounting & Inventory ({fi.total_files} files, {fi.coverage_percent:.1f}% classified, {_format_size(fi.total_bytes)})",
            show_lines=False,
            safe_box=True,
        )
        file_table.add_column("File Path", style="bold", overflow="fold")
        file_table.add_column("Category", overflow="fold")
        file_table.add_column("Attributed Component", overflow="fold")
        file_table.add_column("Size", justify="right")
        file_table.add_column("SHA-256", style="dim", overflow="fold")
        file_table.add_column("Classification Details", overflow="fold")

        for f_entry in fi.files:
            cat_style = FILE_CATEGORY_COLORS.get(f_entry.category, "white")
            if f_entry.component_version in ("unknown", "0.0.0"):
                comp_str = f"{f_entry.component_name}@[dim]unknown[/dim]"
            elif f_entry.component_version:
                comp_str = f"{f_entry.component_name}@{f_entry.component_version}"
            else:
                comp_str = f_entry.component_name or "—"
            sha_str = f_entry.sha256[:12] + "…" if f_entry.sha256 else "—"
            file_table.add_row(
                f_entry.path,
                f"[{cat_style}]{f_entry.category.value}[/{cat_style}]",
                comp_str,
                _format_size(f_entry.size_bytes),
                sha_str,
                f_entry.description,
            )
        out.print(file_table)

    # 4. Legal & Licensing Compliance Findings
    if report.compliance_findings:
        lic_table = Table(title="Legal & Licence Compliance Findings", show_lines=True, safe_box=True)
        lic_table.add_column("Rule ID", style="bold", overflow="fold")
        lic_table.add_column("Severity", overflow="fold")
        lic_table.add_column("Component", overflow="fold")
        lic_table.add_column("Licence", overflow="fold")
        lic_table.add_column("Finding & Remediation", overflow="fold")

        for f in sorted(report.compliance_findings, key=lambda x: -x.severity.rank):
            s_style = SEVERITY_COLORS.get(f.severity, "white")
            lic_table.add_row(
                f.rule_id,
                f"[{s_style}]{f.severity.value.upper()}[/{s_style}]",
                f"{f.component_name}@{f.component_version}",
                f.license_spdx,
                f"[bold]{f.title}[/bold]\n{f.description}\n[dim]Remediation: {f.remediation}[/dim]",
            )
        out.print(lic_table)
    else:
        out.print("[green]No legal or licence compliance violations detected.[/green]")

    # 5. Security Vulnerabilities Summary
    all_vulns = report.all_vulnerabilities
    if all_vulns:
        counts = report.vulnerability_counts_by_severity()
        summary_str = (
            f"CRITICAL: {counts['critical']} | HIGH: {counts['high']} | "
            f"MEDIUM: {counts['medium']} | LOW: {counts['low']}"
        )
        vuln_table = Table(title=f"Security Vulnerabilities ({summary_str})", show_lines=True, safe_box=True)
        vuln_table.add_column("Advisory / CVE", style="bold", overflow="fold")
        vuln_table.add_column("Severity", overflow="fold")
        vuln_table.add_column("CVSS", justify="right")
        vuln_table.add_column("Component", overflow="fold")
        vuln_table.add_column("Summary & Actionable Remediation", overflow="fold")

        ignored_count = sum(1 for v in all_vulns if v.is_ignored)
        if ignored_count:
            summary_str += f" | [yellow]{ignored_count} ignored by policy[/yellow]"

        for v in sorted(all_vulns, key=lambda x: (x.is_ignored, -x.severity.rank, x.id)):
            s_style = SEVERITY_COLORS.get(v.severity, "white")
            cve_str = f"{v.id}\n({v.primary_cve})" if v.primary_cve and v.primary_cve != v.id else v.id
            score_str = f"{v.cvss_score:.1f}" if v.cvss_score is not None else "N/A"
            if v.is_ignored:
                reason_note = f"\n[yellow]Ignored: {v.ignore_reason}[/yellow]" if v.ignore_reason else "\n[yellow]Ignored by policy[/yellow]"
                sev_cell = f"[dim strike]{v.severity.value.upper()}[/dim strike]{reason_note}"
            else:
                sev_cell = f"[{s_style}]{v.severity.value.upper()}[/{s_style}]"
            vuln_table.add_row(
                cve_str,
                sev_cell,
                score_str,
                f"{v.component_name}@{v.component_version}",
                f"{v.summary}\n[bold cyan]Remediation:[/bold cyan] {v.remediation}",
            )
        out.print(vuln_table)
    else:
        out.print("[green]No known security vulnerabilities detected.[/green]")

    if report.warnings:
        for w in report.warnings:
            out.print(f"[yellow]Warning:[/yellow] {w}")

    out.print(
        Text(
            "Notice: Rhada is an automated analysis tool, not a provider of legal advice. "
            "Compliance findings and SBOMs do not guarantee legal compliance. Consult qualified legal counsel.",
            style="dim italic",
        )
    )


def format_report_text(report: AuditReport, verbose: bool = False) -> str:
    """Render the human-readable report to a plain-text string (without ANSI codes)."""
    buf = StringIO()
    console = Console(file=buf, force_terminal=False, color_system=None, width=120, safe_box=True)
    render_console_report(report, console=console, verbose=verbose)
    return buf.getvalue()


def write_json_report(report: AuditReport, output_path: Path) -> Path:
    """Write the complete machine-readable AuditReport JSON to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(report.to_dict(), indent=2) + "\n", encoding="utf-8")
    return output_path
