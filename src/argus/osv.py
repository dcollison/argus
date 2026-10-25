"""Vulnerability auditing via pip-audit and OSV.dev, CVSS v3 scoring, and remediation analysis."""

from __future__ import annotations

from typing import Any

import httpx
from cvss import CVSS3
from cvss.exceptions import CVSS3Error
from packaging.version import InvalidVersion, Version
from pip_audit._service.interface import (
    ResolvedDependency,
    ServiceError,
    VulnerabilityResult,
)
from pip_audit._service.osv import OsvService

from argus.models import Component, ComponentType, Severity, Vulnerability

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL_TEMPLATE = "https://api.osv.dev/v1/vulns/{vuln_id}"


def compute_cvss_v3_score(vector: str) -> float | None:
    """
    Calculate the FIRST.org CVSS v3.0 / v3.1 base score (0.0 - 10.0) from a CVSS vector string
    using the reference `cvss` library.
    Example: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' -> 9.8
    """
    if not vector:
        return None
    cleaned = vector.strip()
    try:
        val = float(cleaned)
        if 0.0 <= val <= 10.0:
            return round(val, 1)
    except ValueError:
        pass

    if not cleaned.upper().startswith("CVSS:3"):
        return None

    try:
        parsed = CVSS3(cleaned)
        return float(parsed.base_score)
    except (CVSS3Error, ValueError, TypeError):
        return None


def score_to_severity(score: float | None) -> Severity:
    """Convert a numeric CVSS score (0.0 - 10.0) to a Severity enum."""
    if score is None:
        return Severity.MEDIUM
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0.0:
        return Severity.LOW
    return Severity.NONE


def _normalize_severity_label(label: str) -> Severity | None:
    """Map OSV / GHSA severity strings to Severity enum."""
    upper = label.strip().upper()
    mapping = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MODERATE": Severity.MEDIUM,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "NONE": Severity.NONE,
    }
    return mapping.get(upper)


def vulnerability_from_pip_audit(
    result: VulnerabilityResult,
    component_name: str,
    component_version: str,
    ecosystem: str = "PyPI",
) -> Vulnerability:
    """Convert a `pip-audit` `VulnerabilityResult` into an Argus `Vulnerability` model."""
    vuln_id = str(result.id)
    aliases = sorted(str(a) for a in result.aliases if str(a) != vuln_id)
    description = (result.description or "").strip()
    summary = description.splitlines()[0].strip() if description else ""
    if len(summary) > 140:
        summary = summary[:140] + "..."
    if not summary:
        summary = f"Security vulnerability {vuln_id} affecting {component_name}"

    fixed_versions = [str(v) for v in sorted(result.fix_versions)]
    return Vulnerability(
        id=vuln_id,
        summary=summary,
        details=description,
        aliases=aliases,
        severity=Severity.MEDIUM,
        fixed_versions=fixed_versions,
        component_name=component_name,
        component_version=component_version,
        ecosystem=ecosystem,
    )


def parse_osv_vulnerability(
    raw_vuln: dict[str, Any],
    component_name: str,
    component_version: str,
    ecosystem: str = "PyPI",
) -> Vulnerability:
    """Parse a full OSV vulnerability JSON object into a structured Vulnerability instance."""
    vuln_id = str(raw_vuln.get("id", "UNKNOWN-ADVISORY"))
    summary = str(raw_vuln.get("summary") or "").strip()
    details = str(raw_vuln.get("details") or "").strip()
    if not summary and details:
        first_line = details.splitlines()[0].strip()
        summary = first_line[:140] + ("..." if len(first_line) > 140 else "")
    if not summary:
        summary = f"Security vulnerability {vuln_id} affecting {component_name}"

    aliases = [str(a) for a in (raw_vuln.get("aliases") or []) if isinstance(a, str)]

    cvss_vector: str | None = None
    cvss_score: float | None = None
    severity_entries = raw_vuln.get("severity") or []
    if isinstance(severity_entries, list):
        for sev_item in severity_entries:
            if isinstance(sev_item, dict):
                s_score_str = str(sev_item.get("score") or "").strip()
                if s_score_str:
                    cvss_vector = s_score_str
                    computed = compute_cvss_v3_score(s_score_str)
                    if computed is not None:
                        cvss_score = computed
                        break

    explicit_sev: Severity | None = None
    db_spec = raw_vuln.get("database_specific") or {}
    if isinstance(db_spec, dict):
        if "severity" in db_spec and isinstance(db_spec["severity"], str):
            explicit_sev = _normalize_severity_label(db_spec["severity"])
        if cvss_score is None and isinstance(db_spec.get("cvss_score"), (int, float)):
            cvss_score = float(db_spec["cvss_score"])

    fixed_versions: list[str] = []
    affected_list = raw_vuln.get("affected") or []
    if isinstance(affected_list, list):
        for aff in affected_list:
            if not isinstance(aff, dict):
                continue
            pkg_obj = aff.get("package") or {}
            pkg_name = str(pkg_obj.get("name") or "").lower().replace("_", "-")
            if pkg_name and pkg_name != component_name.lower().replace("_", "-"):
                continue

            if explicit_sev is None:
                eco_spec = aff.get("ecosystem_specific") or {}
                if isinstance(eco_spec, dict) and isinstance(eco_spec.get("severity"), str):
                    explicit_sev = _normalize_severity_label(eco_spec["severity"])
                aff_db_spec = aff.get("database_specific") or {}
                if isinstance(aff_db_spec, dict) and isinstance(aff_db_spec.get("severity"), str):
                    explicit_sev = _normalize_severity_label(aff_db_spec["severity"])

            for rng in aff.get("ranges") or []:
                if not isinstance(rng, dict):
                    continue
                for ev in rng.get("events") or []:
                    if isinstance(ev, dict) and "fixed" in ev:
                        fver = str(ev["fixed"]).strip()
                        if fver and fver not in fixed_versions:
                            fixed_versions.append(fver)

    if cvss_score is not None:
        final_severity = score_to_severity(cvss_score)
    elif explicit_sev is not None:
        final_severity = explicit_sev
    else:
        final_severity = Severity.MEDIUM

    references: list[str] = []
    for ref in raw_vuln.get("references") or []:
        if isinstance(ref, dict) and isinstance(ref.get("url"), str):
            url = ref["url"].strip()
            if url and url not in references:
                references.append(url)

    return Vulnerability(
        id=vuln_id,
        summary=summary,
        details=details,
        aliases=aliases,
        severity=final_severity,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        fixed_versions=fixed_versions,
        references=references[:10],
        component_name=component_name,
        component_version=component_version,
        ecosystem=ecosystem,
    )


def _build_resolved_dependency(comp: Component) -> ResolvedDependency | None:
    """Create a `pip-audit` `ResolvedDependency` for a Python package component."""
    if comp.component_type != ComponentType.PYTHON_PACKAGE:
        return None
    if not comp.version or comp.version == "unknown":
        return None
    try:
        return ResolvedDependency(comp.name, Version(comp.version))
    except InvalidVersion:
        return None


class OsvClient:
    """Vulnerability client integrating `pip-audit` (`OsvService`) and OSV.dev batch/advisory APIs."""

    def __init__(
        self,
        timeout: float = 15.0,
        http_client: httpx.Client | None = None,
        pip_audit_service: OsvService | None = None,
    ) -> None:
        self.timeout = timeout
        self._external_client = http_client
        self._pip_audit_service = pip_audit_service

    def audit_with_pip_audit(self, components: list[Component]) -> list[str]:
        """
        Audit bundled Python packages directly using `pip-audit`'s `OsvService` and `ResolvedDependency`.
        Populates `component.vulnerabilities` in-place and returns any warning messages.
        """
        warnings: list[str] = []
        service = self._pip_audit_service or OsvService(timeout=int(self.timeout))
        vuln_cache: dict[str, dict[str, Any]] = {}

        for comp in components:
            if not comp.is_bundled or comp.component_type != ComponentType.PYTHON_PACKAGE:
                continue
            dep = _build_resolved_dependency(comp)
            if dep is None:
                continue
            try:
                _, vuln_results = service.query(dep)
            except (ServiceError, ConnectionError, OSError, ValueError) as exc:
                warnings.append(f"pip-audit OSV query failed for {comp.name}@{comp.version}: {exc}")
                continue

            seen_ids = {v.id for v in comp.vulnerabilities}
            for res in vuln_results:
                vid = str(res.id)
                if vid in seen_ids:
                    continue
                vuln_obj = vulnerability_from_pip_audit(
                    res,
                    component_name=comp.name,
                    component_version=comp.version,
                    ecosystem=comp.ecosystem,
                )
                if self._external_client is not None:
                    full_data = vuln_cache.get(vid)
                    if full_data is None:
                        try:
                            v_resp = self._external_client.get(OSV_VULN_URL_TEMPLATE.format(vuln_id=vid))
                            v_resp.raise_for_status()
                            full_data = v_resp.json()
                            vuln_cache[vid] = full_data
                        except (httpx.HTTPError, ValueError, KeyError, TypeError):
                            full_data = None
                    if isinstance(full_data, dict):
                        hydrated = parse_osv_vulnerability(
                            full_data,
                            component_name=comp.name,
                            component_version=comp.version,
                            ecosystem=comp.ecosystem,
                        )
                        vuln_obj.severity = hydrated.severity
                        vuln_obj.cvss_score = hydrated.cvss_score
                        vuln_obj.cvss_vector = hydrated.cvss_vector
                        if hydrated.references:
                            vuln_obj.references = hydrated.references
                comp.vulnerabilities.append(vuln_obj)
                seen_ids.add(vid)
            comp.vulnerabilities.sort(key=lambda v: (-v.severity.rank, v.id))

        return warnings

    def audit_components(self, components: list[Component]) -> list[str]:
        """
        Query OSV.dev for all bundled components that have a known version.
        Uses `pip-audit` `ResolvedDependency` canonicalisation for Python packages, and
        queries `self._pip_audit_service` when explicitly configured.
        Populates `component.vulnerabilities` in-place and returns any warning messages.
        """
        warnings: list[str] = []
        if self._pip_audit_service is not None:
            warnings.extend(self.audit_with_pip_audit(components))
            if self._external_client is None:
                return warnings

        queryable: list[tuple[Component, dict[str, Any]]] = []

        for comp in components:
            if not comp.is_bundled:
                continue
            if not comp.version or comp.version == "unknown":
                continue

            if comp.component_type == ComponentType.PYTHON_PACKAGE and self._pip_audit_service is None:
                resolved_dep = _build_resolved_dependency(comp)
                pkg_name = resolved_dep.canonical_name if resolved_dep is not None else comp.name
                pkg_ver = str(resolved_dep.version) if resolved_dep is not None else comp.version
                query_obj = {
                    "package": {"name": pkg_name, "ecosystem": "PyPI"},
                    "version": pkg_ver,
                }
                queryable.append((comp, query_obj))
            elif comp.component_type == ComponentType.NATIVE_LIBRARY:
                query_obj = {
                    "package": {"name": comp.name, "ecosystem": "OSS-Fuzz"},
                    "version": comp.version,
                }
                queryable.append((comp, query_obj))

        if not queryable:
            return warnings

        client = self._external_client or httpx.Client(timeout=self.timeout)
        close_client = self._external_client is None
        vuln_cache: dict[str, dict[str, Any]] = {}

        try:
            batch_size = 500
            for start in range(0, len(queryable), batch_size):
                chunk = queryable[start : start + batch_size]
                payload = {"queries": [q for _, q in chunk]}
                resp = client.post(OSV_BATCH_URL, json=payload)
                resp.raise_for_status()
                data = resp.json()
                results = data.get("results") or []

                for (comp, q_obj), res_entry in zip(chunk, results, strict=False):
                    if not isinstance(res_entry, dict):
                        continue
                    raw_vulns = res_entry.get("vulns") or []
                    if not isinstance(raw_vulns, list):
                        continue

                    eco = str(q_obj.get("package", {}).get("ecosystem", comp.ecosystem))
                    seen_ids: set[str] = {v.id for v in comp.vulnerabilities}

                    for stub in raw_vulns:
                        if not isinstance(stub, dict):
                            continue
                        vid = str(stub.get("id") or "")
                        if not vid or vid in seen_ids:
                            continue

                        has_details = any(
                            k in stub for k in ("summary", "details", "severity", "affected", "database_specific")
                        )
                        full_vuln_data = stub
                        if not has_details:
                            if vid in vuln_cache:
                                full_vuln_data = vuln_cache[vid]
                            else:
                                try:
                                    v_resp = client.get(OSV_VULN_URL_TEMPLATE.format(vuln_id=vid))
                                    v_resp.raise_for_status()
                                    full_vuln_data = v_resp.json()
                                    vuln_cache[vid] = full_vuln_data
                                except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
                                    warnings.append(f"Failed to hydrate OSV advisory {vid}: {exc}")
                                    full_vuln_data = stub

                        parsed = parse_osv_vulnerability(
                            full_vuln_data,
                            component_name=comp.name,
                            component_version=comp.version,
                            ecosystem=eco,
                        )
                        comp.vulnerabilities.append(parsed)
                        seen_ids.add(vid)

                    comp.vulnerabilities.sort(key=lambda v: (-v.severity.rank, v.id))

        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            warnings.append(f"OSV.dev vulnerability query failed: {exc}")
        finally:
            if close_client:
                client.close()

        return warnings
