"""SBOM and Audit Report comparison / diffing engine for Rhada."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table


@dataclass(slots=True)
class NormalizedComponent:
    """Standardised component representation extracted from any supported SBOM/report format."""

    name: str
    version: str
    license_spdx: str = "UNKNOWN"
    vulnerabilities: set[str] = field(default_factory=set)


@dataclass(slots=True)
class ComponentDelta:
    """Represents a component addition, removal, upgrade, downgrade, or license shift."""

    name: str
    old_version: str | None = None
    new_version: str | None = None
    old_license: str | None = None
    new_license: str | None = None
    change_type: str = "unchanged"  # "added", "removed", "upgraded", "downgraded", "license_changed"


@dataclass(slots=True)
class SbomDiffResult:
    """Complete summary of changes between two SBOMs or audit reports."""

    base_path: str
    target_path: str
    added_components: list[ComponentDelta] = field(default_factory=list)
    removed_components: list[ComponentDelta] = field(default_factory=list)
    modified_components: list[ComponentDelta] = field(default_factory=list)
    new_vulnerabilities: list[str] = field(default_factory=list)
    resolved_vulnerabilities: list[str] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(
            self.added_components
            or self.removed_components
            or self.modified_components
            or self.new_vulnerabilities
            or self.resolved_vulnerabilities
        )

    @property
    def has_downgrades(self) -> bool:
        return any(c.change_type == "downgraded" for c in self.modified_components)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_path": self.base_path,
            "target_path": self.target_path,
            "has_changes": self.has_changes,
            "added_count": len(self.added_components),
            "removed_count": len(self.removed_components),
            "modified_count": len(self.modified_components),
            "new_vulnerabilities_count": len(self.new_vulnerabilities),
            "resolved_vulnerabilities_count": len(self.resolved_vulnerabilities),
            "added": [
                {"name": c.name, "version": c.new_version, "license": c.new_license}
                for c in self.added_components
            ],
            "removed": [
                {"name": c.name, "version": c.old_version, "license": c.old_license}
                for c in self.removed_components
            ],
            "modified": [
                {
                    "name": c.name,
                    "old_version": c.old_version,
                    "new_version": c.new_version,
                    "old_license": c.old_license,
                    "new_license": c.new_license,
                    "change_type": c.change_type,
                }
                for c in self.modified_components
            ],
            "new_vulnerabilities": list(self.new_vulnerabilities),
            "resolved_vulnerabilities": list(self.resolved_vulnerabilities),
        }


def _extract_components_from_file(path: Path) -> dict[str, NormalizedComponent]:
    """Parse a Rhada JSON report, CycloneDX JSON, or SPDX JSON file."""
    try:
        content = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Unable to read or parse JSON file {path}: {exc}") from exc

    results: dict[str, NormalizedComponent] = {}

    # 1. Rhada Audit Report JSON
    if "components" in content and isinstance(content["components"], list):
        # Could be Rhada report or CycloneDX
        if content.get("bomFormat") == "CycloneDX":
            # CycloneDX JSON
            for item in content.get("components", []):
                name = item.get("name", "")
                if not name:
                    continue
                version = item.get("version", "unknown")
                spdx = "NOASSERTION"
                lic_list = item.get("licenses", [])
                if lic_list and isinstance(lic_list, list):
                    first = lic_list[0]
                    if "license" in first and isinstance(first["license"], dict):
                        spdx = first["license"].get("id") or first["license"].get("name") or "NOASSERTION"
                    elif "expression" in first:
                        spdx = first["expression"]
                results[name.lower()] = NormalizedComponent(
                    name=name,
                    version=version,
                    license_spdx=spdx,
                )
        else:
            # Rhada Audit Report format
            for item in content.get("components", []):
                name = item.get("name", "")
                if not name:
                    continue
                version = item.get("version", "unknown")
                lic_info = item.get("license_info") or {}
                spdx = lic_info.get("spdx_id") or "UNKNOWN"
                vulns = {v.get("id") for v in item.get("vulnerabilities", []) if v.get("id")}
                results[name.lower()] = NormalizedComponent(
                    name=name,
                    version=version,
                    license_spdx=spdx,
                    vulnerabilities=vulns,
                )

    # 2. SPDX JSON format
    elif "spdxVersion" in content and "packages" in content:
        for pkg in content.get("packages", []):
            name = pkg.get("name", "")
            if not name:
                continue
            version = pkg.get("versionInfo", "unknown")
            spdx = pkg.get("licenseConcluded") or pkg.get("licenseDeclared") or "NOASSERTION"
            results[name.lower()] = NormalizedComponent(
                name=name,
                version=version,
                license_spdx=spdx,
            )

    return results


def compare_sboms(base_path: Path, target_path: Path) -> SbomDiffResult:
    """Compute component, version, license, and vulnerability differences between two SBOMs or audit reports."""
    base_comps = _extract_components_from_file(base_path)
    target_comps = _extract_components_from_file(target_path)

    base_names = set(base_comps.keys())
    target_names = set(target_comps.keys())

    added: list[ComponentDelta] = []
    removed: list[ComponentDelta] = []
    modified: list[ComponentDelta] = []

    # Added components
    for name in sorted(target_names - base_names):
        comp = target_comps[name]
        added.append(
            ComponentDelta(
                name=comp.name,
                new_version=comp.version,
                new_license=comp.license_spdx,
                change_type="added",
            )
        )

    # Removed components
    for name in sorted(base_names - target_names):
        comp = base_comps[name]
        removed.append(
            ComponentDelta(
                name=comp.name,
                old_version=comp.version,
                old_license=comp.license_spdx,
                change_type="removed",
            )
        )

    # Version / license comparison helper
    from packaging.version import InvalidVersion, Version

    def _compare_versions(v1: str, v2: str) -> str:
        try:
            parsed1 = Version(v1)
            parsed2 = Version(v2)
            if parsed2 > parsed1:
                return "upgraded"
            if parsed2 < parsed1:
                return "downgraded"
        except InvalidVersion:
            if v1 != v2:
                return "modified"
        return "unchanged"

    # Common components
    for name in sorted(base_names & target_names):
        b = base_comps[name]
        t = target_comps[name]
        v_diff = _compare_versions(b.version, t.version)
        lic_diff = b.license_spdx != t.license_spdx

        if v_diff != "unchanged" or lic_diff:
            ctype = v_diff if v_diff != "unchanged" else "license_changed"
            modified.append(
                ComponentDelta(
                    name=t.name,
                    old_version=b.version,
                    new_version=t.version,
                    old_license=b.license_spdx,
                    new_license=t.license_spdx,
                    change_type=ctype,
                )
            )

    # Vulnerability differences
    base_vulns: set[str] = set()
    for c in base_comps.values():
        base_vulns.update(c.vulnerabilities)

    target_vulns: set[str] = set()
    for c in target_comps.values():
        target_vulns.update(c.vulnerabilities)

    new_vulns = sorted(target_vulns - base_vulns)
    resolved_vulns = sorted(base_vulns - target_vulns)

    return SbomDiffResult(
        base_path=str(base_path),
        target_path=str(target_path),
        added_components=added,
        removed_components=removed,
        modified_components=modified,
        new_vulnerabilities=new_vulns,
        resolved_vulnerabilities=resolved_vulns,
    )


def render_diff_console(result: SbomDiffResult, console: Console | None = None) -> None:
    """Print a Rich formatted diff table to the console."""
    out = console or Console()

    out.print(
        f"[bold]Rhada SBOM / Report Diff[/bold]: "
        f"[cyan]{result.base_path}[/cyan] -> [green]{result.target_path}[/green]\n"
    )

    if not result.has_changes:
        out.print("[green]No differences detected between baseline and target.[/green]")
        return

    # 1. Component Changes Table
    table = Table(title="Component Differences", show_lines=True, safe_box=True)
    table.add_column("Change", style="bold", overflow="fold")
    table.add_column("Component", style="cyan", overflow="fold")
    table.add_column("Version Delta", overflow="fold")
    table.add_column("Licence Delta", overflow="fold")

    for c in result.added_components:
        table.add_row("[green]+ ADDED[/green]", c.name, f"[green]{c.new_version}[/green]", c.new_license or "-")

    for c in result.removed_components:
        table.add_row("[red]- REMOVED[/red]", c.name, f"[red]{c.old_version}[/red]", c.old_license or "-")

    for c in result.modified_components:
        color = "yellow"
        if c.change_type == "upgraded":
            color = "green"
            tag = "[green]^ UPGRADE[/green]"
        elif c.change_type == "downgraded":
            color = "red"
            tag = "[red]v DOWNGRADE[/red]"
        else:
            tag = "[yellow]~ MODIFIED[/yellow]"

        v_delta = f"{c.old_version} -> [{color}]{c.new_version}[/{color}]" if c.old_version != c.new_version else f"{c.old_version} (unchanged)"
        lic_delta = (
            f"[dim strike]{c.old_license}[/dim strike] -> [bold]{c.new_license}[/bold]"
            if c.old_license != c.new_license
            else (c.new_license or "-")
        )
        table.add_row(tag, c.name, v_delta, lic_delta)

    out.print(table)

    # 2. Vulnerability Deltas
    if result.new_vulnerabilities or result.resolved_vulnerabilities:
        v_table = Table(title="Vulnerability Deltas", show_lines=True, safe_box=True)
        v_table.add_column("Type", style="bold")
        v_table.add_column("Advisory ID", style="bold")

        for v in result.new_vulnerabilities:
            v_table.add_row("[red]+ NEW VULNERABILITY[/red]", f"[red]{v}[/red]")
        for v in result.resolved_vulnerabilities:
            v_table.add_row("[green]- RESOLVED[/green]", f"[green]{v}[/green]")
        out.print(v_table)

    # 3. Summary metrics
    summary = (
        f"[bold]Summary:[/bold] "
        f"[green]{len(result.added_components)} added[/green], "
        f"[red]{len(result.removed_components)} removed[/red], "
        f"[yellow]{len(result.modified_components)} modified[/yellow]"
    )
    if result.new_vulnerabilities:
        summary += f" | [red bold]{len(result.new_vulnerabilities)} new CVEs/advisories introduced[/red bold]"
    if result.resolved_vulnerabilities:
        summary += f" | [green bold]{len(result.resolved_vulnerabilities)} CVEs resolved[/green bold]"
    out.print(f"\n{summary}\n")
