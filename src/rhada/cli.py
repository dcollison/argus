"""Command-line interface for Rhada compliance, SBOM, binary linkage, and security auditing."""

from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from typer.core import TyperGroup

from rhada import __version__
from rhada.auditor import run_audit
from rhada.compliance import (
    generate_third_party_notices,
    generate_third_party_notices_markdown,
    write_third_party_notices,
)
from rhada.diff import compare_sboms, render_diff_console
from rhada.elf import is_binary_file, parse_binary, verify_binary_linkage
from rhada.models import AuditConfig, ConsoleFormat, ExitCode, SbomFormat, Severity
from rhada.reporter import render_console_report
from rhada.sbom import serialize_sbom, write_sbom


def _configure_streams() -> None:
    """Ensure standard output and standard error streams use UTF-8 encoding on Windows."""
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            with contextlib.suppress(AttributeError, OSError, ValueError):
                stream.reconfigure(encoding="utf-8", errors="replace")


_configure_streams()


def _safe_echo_text(text: str, *, err: bool = False, nl: bool = True) -> None:
    """Echo text to stdout/stderr with UTF-8 fallback to prevent Windows charmap/cp1252 encode errors."""
    target_stream = sys.stderr if err else sys.stdout
    try:
        typer.echo(text, err=err, nl=nl)
    except UnicodeEncodeError:
        raw_bytes = (text + ("\n" if nl else "")).encode("utf-8", errors="replace")
        if hasattr(target_stream, "buffer"):
            target_stream.buffer.write(raw_bytes)
            target_stream.buffer.flush()
        else:
            encoding = getattr(target_stream, "encoding", "utf-8") or "utf-8"
            fallback_text = raw_bytes.decode(encoding, errors="replace")
            typer.echo(fallback_text, err=err, nl=False)


class DefaultToAuditGroup(TyperGroup):
    """Typer group that defaults to the 'audit' command when invoked with flags directly."""

    def parse_args(self, ctx: typer.Context, args: list[str]) -> list[str]:
        if args and args[0] not in self.commands and args[0] not in ("--help", "-h", "--version"):
            args = ["audit", *args]
        elif not args:
            args = ["audit"]
        return super().parse_args(ctx, args)


app = typer.Typer(
    cls=DefaultToAuditGroup,
    name="rhada",
    help=(
        "Rhada: Legal compliance, SBOM generation, binary linkage, and security auditor.\n\n"
        "Disclaimer: Rhada is an automated analysis tool, not a provider of legal advice. "
        "Outputs do not guarantee legal compliance."
    ),
    context_settings={"help_option_names": ["-h", "--help"]},
    add_completion=False,
    no_args_is_help=False,
)

# Alias retained for compatibility with test runners and external callers
cli = app


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"rhada, version {__version__}")
        raise typer.Exit()


def _split_csv_values(values: list[str] | None) -> set[str]:
    result: set[str] = set()
    if not values:
        return result
    for item in values:
        for part in item.split(","):
            cleaned = part.strip()
            if cleaned:
                result.add(cleaned)
    return result


@app.callback()
def main_callback(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_callback,
            is_eager=True,
            help="Show the version and exit.",
        ),
    ] = False,
) -> None:
    """Rhada: Legal compliance, SBOM generation, binary linkage, and security auditor."""


@app.command("audit")
def audit_cmd(
    project_path: Annotated[
        Path,
        typer.Option(
            "--project",
            "-p",
            help="Path to the Python or uv project workspace root.",
        ),
    ] = Path("."),
    dist_path: Annotated[
        Path | None,
        typer.Option(
            "--dist",
            "-d",
            help="Path to a compiled Nuitka or PyInstaller distribution (directory or monolithic binary).",
        ),
    ] = None,
    compilation_report: Annotated[
        Path | None,
        typer.Option(
            "--compilation-report",
            help="Optional path to a Nuitka compilation-report.xml file.",
        ),
    ] = None,
    include_dev: Annotated[
        bool,
        typer.Option(
            "--include-dev",
            help="Include development and build dependencies in source audit mode.",
        ),
    ] = False,
    offline: Annotated[
        bool,
        typer.Option(
            "--offline",
            help="Skip online OSV.dev vulnerability lookups.",
        ),
    ] = False,
    sbom_output: Annotated[
        Path | None,
        typer.Option(
            "--sbom",
            help="Write a machine-readable SBOM JSON file to the specified path.",
        ),
    ] = None,
    sbom_format: Annotated[
        SbomFormat,
        typer.Option(
            "--sbom-format",
            case_sensitive=False,
            help="SBOM standard format.",
        ),
    ] = SbomFormat.CYCLONEDX,
    notices_output: Annotated[
        Path | None,
        typer.Option(
            "--notices",
            help="Write a THIRD_PARTY_NOTICES attribution file to the specified path.",
        ),
    ] = None,
    report_output: Annotated[
        Path | None,
        typer.Option(
            "--report-json",
            "--output",
            "-o",
            help="Write the full machine-readable JSON audit report to disk.",
        ),
    ] = None,
    console_format: Annotated[
        ConsoleFormat,
        typer.Option(
            "--format",
            case_sensitive=False,
            help="Standard output format.",
        ),
    ] = ConsoleFormat.TABLE,
    fail_on_severity: Annotated[
        Severity,
        typer.Option(
            "--fail-on-severity",
            case_sensitive=False,
            help="Minimum vulnerability severity that triggers a non-zero exit code.",
        ),
    ] = Severity.HIGH,
    fail_on_license: Annotated[
        Severity,
        typer.Option(
            "--fail-on-license",
            "--fail-on-licence",
            case_sensitive=False,
            help="Minimum licence compliance finding severity that triggers a non-zero exit code.",
        ),
    ] = Severity.HIGH,
    fail_on_linkage: Annotated[
        bool,
        typer.Option(
            "--fail-on-linkage",
            help="Fail with exit code 4 if unresolved ELF/PE binary dependencies or insecure RPATHs exist.",
        ),
    ] = False,
    allow_unknown_license: Annotated[
        bool,
        typer.Option(
            "--allow-unknown-license",
            "--allow-unknown-licence",
            help="Downgrade unknown or unasserted licence findings to LOW severity.",
        ),
    ] = False,
    allowed_licenses: Annotated[
        list[str] | None,
        typer.Option(
            "--allow-licence",
            "--allow-license",
            "--allow-licences",
            "--allow-licenses",
            help="Approved SPDX licence IDs or internal company licences (repeatable or comma-separated).",
        ),
    ] = None,
    extra_allowed_licenses: Annotated[
        list[str] | None,
        typer.Option(
            "--allow-extra-licence",
            "--allow-extra-license",
            "--allow-extra-licences",
            "--allow-extra-licenses",
            help="Additional approved licence IDs or custom company licences (repeatable or comma-separated) that supplement default rules without enforcing an exclusive allowlist.",
        ),
    ] = None,
    denied_licenses: Annotated[
        list[str] | None,
        typer.Option(
            "--deny-licence",
            "--deny-license",
            "--deny-licences",
            "--deny-licenses",
            help="Forbidden SPDX licence IDs (repeatable or comma-separated).",
        ),
    ] = None,
    internal_packages: Annotated[
        list[str] | None,
        typer.Option(
            "--internal-package",
            "--internal-packages",
            "--allow-package",
            "--allow-packages",
            help="Internal package names or wildcards (e.g. 'mycorp-*') to treat as application code.",
        ),
    ] = None,
    ignore_packages: Annotated[
        list[str] | None,
        typer.Option(
            "--ignore-package",
            "--ignore-packages",
            help="Packages or wildcards to completely ignore from compliance audit and vulnerability checks.",
        ),
    ] = None,
    ignore_vulnerabilities: Annotated[
        list[str] | None,
        typer.Option(
            "--ignore-vulnerability",
            "--ignore-vulnerabilities",
            help="Vulnerability or CVE IDs (repeatable or comma-separated) to ignore from failure evaluation.",
        ),
    ] = None,
    license_files: Annotated[
        list[str] | None,
        typer.Option(
            "--license-file",
            help="Override licence text file for a component in 'component=path' format (repeatable).",
        ),
    ] = None,
    notices_format: Annotated[
        str,
        typer.Option(
            "--notices-format",
            help="Format for THIRD_PARTY_NOTICES: 'text' or 'markdown' (auto-detected from .md extension).",
        ),
    ] = "text",
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            "--full",
            help="Show detailed distribution file accounting and component mapping breakdown.",
        ),
    ] = False,
) -> None:
    """Run a legal compliance, SBOM, binary linkage, and security audit."""
    if not project_path.exists():
        typer.echo(f"Error: Project path does not exist: {project_path}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE_OR_IO_ERROR))
    if dist_path is not None and not dist_path.exists():
        typer.echo(f"Error: Distribution path does not exist: {dist_path}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE_OR_IO_ERROR))

    lic_files_map: dict[str, str] = {}
    if license_files:
        for item in license_files:
            if "=" in item:
                k, v = item.split("=", 1)
                lic_files_map[k.strip().lower()] = v.strip()

    config = AuditConfig(
        project_path=project_path,
        dist_path=dist_path,
        compilation_report_path=compilation_report,
        include_dev=include_dev,
        offline=offline,
        verbose=verbose,
        fail_on_severity=fail_on_severity,
        fail_on_license=fail_on_license,
        fail_on_linkage=fail_on_linkage,
        allow_unknown_license=allow_unknown_license,
        allowed_licenses=_split_csv_values(allowed_licenses),
        extra_allowed_licenses=_split_csv_values(extra_allowed_licenses),
        denied_licenses=_split_csv_values(denied_licenses),
        internal_packages=_split_csv_values(internal_packages),
        ignore_packages=_split_csv_values(ignore_packages),
        ignore_vulnerabilities=_split_csv_values(ignore_vulnerabilities),
        license_files=lic_files_map,
        notices_format=notices_format,
        sbom_output=sbom_output,
        sbom_format=sbom_format.value,
        notices_output=notices_output,
        report_output=report_output,
    )

    try:
        report = run_audit(config)
    except (OSError, ValueError, RuntimeError) as exc:
        typer.echo(f"Error executing audit: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE_OR_IO_ERROR)) from exc

    if console_format == ConsoleFormat.JSON:
        _safe_echo_text(json.dumps(report.to_dict(), indent=2))
    else:
        render_console_report(report, console=Console(safe_box=True), verbose=verbose)

    raise typer.Exit(code=int(report.exit_code))


@app.command("sbom")
def sbom_cmd(
    project_path: Annotated[
        Path,
        typer.Option("--project", "-p", help="Path to the Python or uv project workspace root."),
    ] = Path("."),
    dist_path: Annotated[
        Path | None,
        typer.Option("--dist", "-d", help="Path to a compiled distribution directory or binary."),
    ] = None,
    sbom_format: Annotated[
        SbomFormat,
        typer.Option("--format", "-f", case_sensitive=False, help="SBOM standard format."),
    ] = SbomFormat.CYCLONEDX,
    output_path: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Output file path (writes to stdout if omitted)."),
    ] = None,
    offline: Annotated[
        bool,
        typer.Option("--offline", help="Skip OSV vulnerability enrichment."),
    ] = False,
) -> None:
    """Generate a CycloneDX 1.5 or SPDX 2.3 SBOM for a source workspace or compiled distribution."""
    if not project_path.exists() or (dist_path is not None and not dist_path.exists()):
        typer.echo("Error: Specified project or dist path does not exist.", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE_OR_IO_ERROR))

    config = AuditConfig(
        project_path=project_path,
        dist_path=dist_path,
        offline=offline,
        sbom_format=sbom_format.value,
    )
    try:
        report = run_audit(config)
        if output_path is not None:
            write_sbom(report, output_path, fmt=sbom_format.value)
            typer.echo(f"SBOM ({sbom_format.value}) written to {output_path}")
        else:
            _safe_echo_text(serialize_sbom(report, fmt=sbom_format.value), nl=False)
    except (OSError, ValueError, RuntimeError) as exc:
        typer.echo(f"Error generating SBOM: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE_OR_IO_ERROR)) from exc


@app.command("notices")
def notices_cmd(
    project_path: Annotated[
        Path,
        typer.Option("--project", "-p", help="Path to the Python or uv project workspace root."),
    ] = Path("."),
    dist_path: Annotated[
        Path | None,
        typer.Option("--dist", "-d", help="Path to a compiled distribution directory or binary."),
    ] = None,
    output_path: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write THIRD_PARTY_NOTICES to a file instead of stdout."),
    ] = None,
    notices_format: Annotated[
        str,
        typer.Option("--format", "-f", help="Output format: 'text' or 'markdown' (auto-detected if output path ends with .md)."),
    ] = "text",
) -> None:
    """Generate a THIRD_PARTY_NOTICES attribution file (plain text or markdown)."""
    if not project_path.exists() or (dist_path is not None and not dist_path.exists()):
        typer.echo("Error: Specified project or dist path does not exist.", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE_OR_IO_ERROR))

    config = AuditConfig(
        project_path=project_path,
        dist_path=dist_path,
        offline=True,
        notices_format=notices_format,
    )
    try:
        report = run_audit(config)
        is_md = notices_format in ("markdown", "md") or (output_path is not None and output_path.suffix.lower() in (".md", ".markdown"))
        if output_path is not None:
            write_third_party_notices(report, output_path, fmt=notices_format)
            typer.echo(f"THIRD_PARTY_NOTICES ({'markdown' if is_md else 'text'}) written to {output_path}")
        else:
            txt = generate_third_party_notices_markdown(report) if is_md else generate_third_party_notices(report)
            _safe_echo_text(txt, nl=False)
    except (OSError, ValueError, RuntimeError) as exc:
        typer.echo(f"Error generating THIRD_PARTY_NOTICES: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE_OR_IO_ERROR)) from exc


@app.command("diff")
def diff_cmd(
    base: Annotated[
        Path,
        typer.Argument(help="Path to baseline report JSON or SBOM file (CycloneDX, SPDX, or Rhada JSON)."),
    ],
    target: Annotated[
        Path,
        typer.Argument(help="Path to target report JSON or SBOM file to compare against baseline."),
    ],
    console_format: Annotated[
        ConsoleFormat,
        typer.Option("--format", "-f", case_sensitive=False, help="Console output format (table or json)."),
    ] = ConsoleFormat.TABLE,
    fail_on_downgrade: Annotated[
        bool,
        typer.Option("--fail-on-downgrade", help="Exit with non-zero code if any dependency version was downgraded."),
    ] = False,
    fail_on_new_vuln: Annotated[
        bool,
        typer.Option("--fail-on-new-vuln", help="Exit with non-zero code if any new security vulnerability was introduced."),
    ] = False,
    fail_on_changes: Annotated[
        bool,
        typer.Option("--fail-on-changes", help="Exit with non-zero code if any dependency, version, or licence changed."),
    ] = False,
) -> None:
    """Compare two SBOMs or Rhada reports to detect dependency, licence, and vulnerability deltas."""
    if not base.exists():
        typer.echo(f"Error: Baseline file does not exist: {base}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE_OR_IO_ERROR))
    if not target.exists():
        typer.echo(f"Error: Target file does not exist: {target}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE_OR_IO_ERROR))

    try:
        diff_res = compare_sboms(base, target)
    except (OSError, ValueError, RuntimeError) as exc:
        typer.echo(f"Error comparing SBOMs: {exc}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE_OR_IO_ERROR)) from exc

    if console_format == ConsoleFormat.JSON:
        _safe_echo_text(json.dumps(diff_res.to_dict(), indent=2))
    else:
        render_diff_console(diff_res, console=Console(safe_box=True))

    if fail_on_downgrade and diff_res.has_downgrades:
        raise typer.Exit(code=1)
    if fail_on_new_vuln and diff_res.new_vulnerabilities:
        raise typer.Exit(code=1)
    if fail_on_changes and diff_res.has_changes:
        raise typer.Exit(code=1)

    raise typer.Exit(code=0)


@app.command("inspect-elf")
@app.command("inspect-binary")
def inspect_elf_cmd(
    target: Annotated[
        Path,
        typer.Argument(help="Target ELF/PE binary (.so, .dll, .pyd, .exe) or distribution directory to inspect."),
    ],
) -> None:
    """Inspect ELF and Windows PE binaries and verify dynamic linkage in a file or directory."""
    if not target.exists():
        typer.echo(f"Error: Target path does not exist: {target}", err=True)
        raise typer.Exit(code=int(ExitCode.USAGE_OR_IO_ERROR))

    binaries = []
    if target.is_file():
        if not is_binary_file(target):
            typer.echo(f"Error: {target} is not a valid ELF or PE binary.", err=True)
            raise typer.Exit(code=int(ExitCode.USAGE_OR_IO_ERROR))
        binaries.append(parse_binary(target))
        linkage = verify_binary_linkage(binaries, dist_root=None)
    else:
        binaries.extend(parse_binary(p) for p in sorted(target.rglob("*")) if is_binary_file(p))
        linkage = verify_binary_linkage(binaries, dist_root=target)

    _safe_echo_text(json.dumps(linkage.to_dict(), indent=2))


def main() -> None:
    """Entrypoint for the rhada CLI."""
    _configure_streams()
    app()


if __name__ == "__main__":
    main()
