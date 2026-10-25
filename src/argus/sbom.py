"""Standards-compliant SBOM generator supporting CycloneDX 1.5 JSON and SPDX 2.3 JSON."""

from __future__ import annotations

import contextlib
import json
import re
import uuid
import warnings
from decimal import Decimal
from pathlib import Path
from typing import Any

from cyclonedx.model import (
    AttachedText,
    ExternalReference,
    ExternalReferenceType,
    HashAlgorithm,
    HashType,
    Property,
    XsUri,
)
from cyclonedx.model.bom import Bom
from cyclonedx.model.component import (
    Component as CdxComponent,
)
from cyclonedx.model.component import (
    ComponentScope as CdxScope,
)
from cyclonedx.model.component import (
    ComponentType as CdxComponentType,
)
from cyclonedx.model.license import DisjunctiveLicense, License, LicenseExpression
from cyclonedx.model.tool import Tool
from cyclonedx.model.vulnerability import (
    BomTarget,
    VulnerabilityAdvisory,
    VulnerabilityRating,
    VulnerabilityScoreSource,
    VulnerabilitySeverity,
    VulnerabilitySource,
)
from cyclonedx.model.vulnerability import (
    Vulnerability as CdxVulnerability,
)
from cyclonedx.output.json import JsonV1Dot5
from cyclonedx.spdx import fixup_id, is_expression
from packageurl import PackageURL

from argus import __version__
from argus.models import AuditReport, Component, Severity

HASH_ALG_CYCLONEDX: dict[str, HashAlgorithm] = {
    "SHA256": HashAlgorithm.SHA_256,
    "SHA-256": HashAlgorithm.SHA_256,
    "SHA512": HashAlgorithm.SHA_512,
    "SHA-512": HashAlgorithm.SHA_512,
    "SHA384": HashAlgorithm.SHA_384,
    "SHA-384": HashAlgorithm.SHA_384,
    "SHA1": HashAlgorithm.SHA_1,
    "SHA-1": HashAlgorithm.SHA_1,
    "MD5": HashAlgorithm.MD5,
    "BLAKE2B": HashAlgorithm.BLAKE2B_256,
}

SEVERITY_TO_CYCLONEDX: dict[Severity, VulnerabilitySeverity] = {
    Severity.CRITICAL: VulnerabilitySeverity.CRITICAL,
    Severity.HIGH: VulnerabilitySeverity.HIGH,
    Severity.MEDIUM: VulnerabilitySeverity.MEDIUM,
    Severity.LOW: VulnerabilitySeverity.LOW,
    Severity.NONE: VulnerabilitySeverity.NONE,
}

HASH_ALG_SPDX: dict[str, str] = {
    "SHA256": "SHA256",
    "SHA-256": "SHA256",
    "SHA512": "SHA512",
    "SHA-512": "SHA512",
    "SHA384": "SHA384",
    "SHA-384": "SHA384",
    "SHA1": "SHA1",
    "SHA-1": "SHA1",
    "MD5": "MD5",
}


def _is_valid_http_url(url: str) -> bool:
    """Return True if `url` is a well-formed HTTP/HTTPS URL with a valid network location."""
    from urllib.parse import urlsplit

    cleaned = (url or "").strip()
    if not cleaned or any(ch.isspace() for ch in cleaned):
        return False
    try:
        parts = urlsplit(cleaned)
    except ValueError:
        return False
    return parts.scheme in ("http", "https") and bool(parts.netloc)


def _sanitize_spdx_id(raw: str) -> str:
    """Sanitise an identifier to conform to SPDX-2.3 SPDXRef-[A-Za-z0-9.-]+ rules."""
    cleaned = re.sub(r"[^A-Za-z0-9.-]+", "-", raw).strip("-")
    return f"SPDXRef-{cleaned or 'Component'}"


def _build_cyclonedx_licenses(comp: Component) -> list[License]:
    """Construct CycloneDX License objects (`DisjunctiveLicense` or `LicenseExpression`)."""
    lic = comp.license_info
    spdx = lic.spdx_id or "NOASSERTION"
    if spdx == "NOASSERTION":
        if lic.declared_raw and lic.declared_raw != "UNKNOWN":
            return [DisjunctiveLicense(name=lic.declared_raw)]
        return []

    attached_text = None
    if lic.license_texts:
        first_text = next(iter(lic.license_texts.values()))
        attached_text = AttachedText(content=first_text[:32_000], content_type="text/plain")

    if (" OR " in spdx or " AND " in spdx or " WITH " in spdx) and is_expression(spdx):
        return [LicenseExpression(value=spdx)]

    canonical_id = None if spdx.startswith("LicenseRef-") else fixup_id(spdx)
    if canonical_id:
        return [DisjunctiveLicense(id=canonical_id, text=attached_text)]
    return [DisjunctiveLicense(name=spdx, text=attached_text)]


def generate_cyclonedx_sbom(report: AuditReport) -> dict[str, Any]:
    """Generate a CycloneDX 1.5 JSON Software Bill of Materials using `cyclonedx-python-lib`."""
    root_ref = PackageURL(type="generic", name=report.target_name.lower(), version=report.target_version).to_string()
    bundled = [c for c in report.components if c.is_bundled]
    bundled_sorted = sorted(bundled, key=lambda c: (c.name.lower(), c.version, c.component_type.value))

    bom = Bom()
    bom.metadata.tools.tools.add(
        Tool(vendor="Argus DevSecOps", name="argus", version=__version__)
    )
    root_component = CdxComponent(
        name=report.target_name,
        version=report.target_version,
        type=CdxComponentType.APPLICATION,
        bom_ref=root_ref,
        properties=[
            Property(name="argus:mode", value=report.mode.value),
            Property(name="argus:bundler", value=report.bundler_type.value),
            Property(name="argus:layout", value=report.layout.value),
        ],
    )
    bom.metadata.component = root_component

    comp_cdx_pairs: list[tuple[Component, CdxComponent]] = []
    name_to_cdx_comp: dict[str, CdxComponent] = {}

    for comp in bundled_sorted:
        bom_ref = comp.purl or PackageURL(type="generic", name=comp.name.lower(), version=comp.version).to_string()
        purl_obj = None
        with contextlib.suppress(ValueError):
            purl_obj = PackageURL.from_string(bom_ref)

        cdx_hashes: list[HashType] = []
        for alg, digest in sorted(comp.hashes.items()):
            mapped_alg = HASH_ALG_CYCLONEDX.get(alg.upper())
            if mapped_alg and digest:
                with contextlib.suppress(ValueError):
                    cdx_hashes.append(HashType(alg=mapped_alg, content=digest))

        copyright_str = (
            "; ".join(comp.license_info.copyright_notices)
            if comp.license_info.copyright_notices
            else None
        )

        ext_refs: list[ExternalReference] = []
        if _is_valid_http_url(comp.homepage):
            with contextlib.suppress(ValueError):
                ext_refs.append(
                    ExternalReference(type=ExternalReferenceType.WEBSITE, url=XsUri(comp.homepage.strip()))
                )

        props = [
            Property(name="argus:component_type", value=comp.component_type.value),
            Property(name="argus:license_risk", value=comp.license_info.risk_category.value),
            Property(name="argus:statically_compiled", value=str(comp.is_statically_compiled).lower()),
            Property(name="argus:dynamic_relinking", value=str(comp.has_dynamic_relinking).lower()),
        ]
        if comp.origin_package:
            props.append(Property(name="argus:origin_package", value=comp.origin_package))
        if comp.provenance:
            props.append(Property(name="argus:provenance", value=comp.provenance))
        if comp.architecture:
            props.append(Property(name="argus:architecture", value=comp.architecture))
        if comp.soname:
            props.append(Property(name="argus:soname", value=comp.soname))

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            cdx_comp = CdxComponent(
                name=comp.name,
                version=comp.version,
                type=CdxComponentType.LIBRARY,
                scope=CdxScope.REQUIRED,
                bom_ref=bom_ref,
                purl=purl_obj,
                description=comp.description or None,
                author=comp.author or None,
                copyright=copyright_str,
                licenses=_build_cyclonedx_licenses(comp),
                hashes=cdx_hashes,
                external_references=ext_refs,
                properties=props,
            )
        bom.components.add(cdx_comp)
        comp_cdx_pairs.append((comp, cdx_comp))
        name_to_cdx_comp.setdefault(comp.name, cdx_comp)
        name_to_cdx_comp.setdefault(comp.name.lower(), cdx_comp)
        if comp.soname:
            name_to_cdx_comp.setdefault(comp.soname, cdx_comp)
            name_to_cdx_comp.setdefault(comp.soname.lower(), cdx_comp)
        for bf in comp.bundled_files:
            bf_leaf = Path(bf.replace("\\", "/")).name
            name_to_cdx_comp.setdefault(bf_leaf, cdx_comp)
            name_to_cdx_comp.setdefault(bf_leaf.lower(), cdx_comp)

    # Register dependency graph with cyclonedx-python-lib
    bom.register_dependency(root_component, [cdx_comp for _, cdx_comp in comp_cdx_pairs])
    for comp, src_cdx in comp_cdx_pairs:
        dep_cdx_list: list[CdxComponent] = []
        for d in comp.dependencies:
            target_cdx = name_to_cdx_comp.get(d) or name_to_cdx_comp.get(d.lower())
            if not target_cdx:
                from argus.elf import _strip_wheel_hashes_and_arch

                cleaned_d = _strip_wheel_hashes_and_arch(d)
                target_cdx = name_to_cdx_comp.get(cleaned_d) or name_to_cdx_comp.get(cleaned_d.lower())
            if target_cdx and target_cdx != src_cdx and target_cdx not in dep_cdx_list:
                dep_cdx_list.append(target_cdx)
        for nat_c, nat_cdx in comp_cdx_pairs:
            if nat_c.origin_package == comp.name and nat_cdx not in dep_cdx_list:
                dep_cdx_list.append(nat_cdx)
        bom.register_dependency(src_cdx, dep_cdx_list)

    # Register vulnerabilities
    for comp, cdx_comp in comp_cdx_pairs:
        for v in comp.vulnerabilities:
            score_dec = Decimal(f"{v.cvss_score:.1f}") if v.cvss_score is not None else None
            method = VulnerabilityScoreSource.CVSS_V3 if v.cvss_score is not None or v.cvss_vector else None
            rating = VulnerabilityRating(
                severity=SEVERITY_TO_CYCLONEDX.get(v.severity, VulnerabilitySeverity.MEDIUM),
                score=score_dec,
                method=method,
                vector=v.cvss_vector,
            )
            advisories = []
            for ref_url in v.references:
                if _is_valid_http_url(ref_url):
                    with contextlib.suppress(ValueError):
                        advisories.append(VulnerabilityAdvisory(url=XsUri(ref_url.strip())))

            bom.vulnerabilities.add(
                CdxVulnerability(
                    id=v.id,
                    source=VulnerabilitySource(
                        name="OSV",
                        url=XsUri(f"https://osv.dev/vulnerability/{v.id}"),
                    ),
                    ratings=[rating],
                    description=v.summary,
                    recommendation=v.remediation,
                    affects=[BomTarget(ref=cdx_comp.bom_ref.value or comp.purl)],
                    advisories=advisories,
                )
            )

    raw_json = JsonV1Dot5(bom).output_as_string()
    return json.loads(raw_json)


def generate_spdx_sbom(report: AuditReport) -> dict[str, Any]:
    """Generate an SPDX 2.3 JSON Software Bill of Materials."""
    doc_uuid = uuid.uuid4()
    root_spdx_id = "SPDXRef-RootApplication"
    bundled = [c for c in report.components if c.is_bundled]
    bundled_sorted = sorted(bundled, key=lambda c: (c.name.lower(), c.version, c.component_type.value))

    packages: list[dict[str, Any]] = [
        {
            "SPDXID": root_spdx_id,
            "name": report.target_name,
            "versionInfo": report.target_version,
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "APPLICATION",
        }
    ]

    relationships: list[dict[str, Any]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_spdx_id,
        }
    ]

    comp_spdx_pairs: list[tuple[Component, str]] = []
    name_to_spdx_id: dict[str, str] = {}
    used_spdx_ids: set[str] = {root_spdx_id, "SPDXRef-DOCUMENT"}

    for comp in bundled_sorted:
        base_id = _sanitize_spdx_id(f"Package-{comp.component_type.value}-{comp.name}-{comp.version}")
        spdx_id = base_id
        counter = 2
        while spdx_id in used_spdx_ids:
            spdx_id = f"{base_id}-{counter}"
            counter += 1
        used_spdx_ids.add(spdx_id)
        comp_spdx_pairs.append((comp, spdx_id))
        name_to_spdx_id.setdefault(comp.name, spdx_id)
        name_to_spdx_id.setdefault(comp.name.lower(), spdx_id)
        if comp.soname:
            name_to_spdx_id.setdefault(comp.soname, spdx_id)
            name_to_spdx_id.setdefault(comp.soname.lower(), spdx_id)
        for bf in comp.bundled_files:
            bf_leaf = Path(bf.replace("\\", "/")).name
            name_to_spdx_id.setdefault(bf_leaf, spdx_id)
            name_to_spdx_id.setdefault(bf_leaf.lower(), spdx_id)

        lic_spdx = comp.license_info.spdx_id or "NOASSERTION"
        copyright_text = (
            "\n".join(comp.license_info.copyright_notices)
            if comp.license_info.copyright_notices
            else "NOASSERTION"
        )

        checksums = []
        for alg, digest in sorted(comp.hashes.items()):
            spdx_alg = HASH_ALG_SPDX.get(alg.upper())
            if spdx_alg and digest:
                checksums.append({"algorithm": spdx_alg, "checksumValue": digest})

        download_loc = comp.homepage.strip() if _is_valid_http_url(comp.homepage) else "NOASSERTION"
        pkg_entry: dict[str, Any] = {
            "SPDXID": spdx_id,
            "name": comp.name,
            "versionInfo": comp.version,
            "downloadLocation": download_loc,
            "filesAnalyzed": False,
            "licenseConcluded": lic_spdx,
            "licenseDeclared": lic_spdx,
            "copyrightText": copyright_text,
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": comp.purl,
                }
            ],
        }
        if comp.description:
            pkg_entry["summary"] = comp.description
        if comp.author:
            pkg_entry["originator"] = f"Person: {comp.author}"
        if checksums:
            pkg_entry["checksums"] = checksums

        source_info_parts = []
        if comp.origin_package:
            source_info_parts.append(f"origin_package: {comp.origin_package}")
        if comp.provenance:
            source_info_parts.append(f"provenance: {comp.provenance}")
        if comp.architecture:
            source_info_parts.append(f"architecture: {comp.architecture}")
        if comp.soname:
            source_info_parts.append(f"soname: {comp.soname}")

        if source_info_parts:
            pkg_entry["sourceInfo"] = "; ".join(source_info_parts)
            if comp.origin_package:
                pkg_entry["comment"] = f"Vendored by {comp.origin_package} ({comp.provenance})"
            elif comp.provenance:
                pkg_entry["comment"] = comp.provenance
        elif comp.provenance:
            pkg_entry["comment"] = comp.provenance
            pkg_entry["sourceInfo"] = f"provenance: {comp.provenance}"

        packages.append(pkg_entry)
        relationships.append(
            {
                "spdxElementId": root_spdx_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": spdx_id,
            }
        )

    for comp, src_id in comp_spdx_pairs:
        for dep_name in comp.dependencies:
            target_id = name_to_spdx_id.get(dep_name) or name_to_spdx_id.get(dep_name.lower())
            if not target_id:
                from argus.elf import _strip_wheel_hashes_and_arch

                cleaned_dep = _strip_wheel_hashes_and_arch(dep_name)
                target_id = name_to_spdx_id.get(cleaned_dep) or name_to_spdx_id.get(cleaned_dep.lower())
            if target_id and target_id != src_id:
                rel = {
                    "spdxElementId": src_id,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": target_id,
                }
                if rel not in relationships:
                    relationships.append(rel)
        for nat_c, nat_id in comp_spdx_pairs:
            if nat_c.origin_package == comp.name:
                rel = {
                    "spdxElementId": src_id,
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": nat_id,
                }
                if rel not in relationships:
                    relationships.append(rel)

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"{report.target_name}-{report.target_version}-sbom",
        "documentNamespace": f"https://spdx.org/spdxdocs/{report.target_name}-{report.target_version}-{doc_uuid}",
        "creationInfo": {
            "created": report.timestamp,
            "creators": [f"Tool: argus-{__version__}"],
            "licenseListVersion": "3.25",
        },
        "documentDescribes": [root_spdx_id],
        "packages": packages,
        "relationships": relationships,
    }


def serialize_sbom(report: AuditReport, fmt: str = "cyclonedx") -> str:
    """Serialise an AuditReport to a formatted CycloneDX 1.5 or SPDX 2.3 JSON string."""
    fmt_clean = fmt.strip().lower()
    if fmt_clean in ("cyclonedx", "cdx", "cyclonedx-json"):
        data = generate_cyclonedx_sbom(report)
    elif fmt_clean in ("spdx", "spdx-json", "spdx-2.3"):
        data = generate_spdx_sbom(report)
    else:
        raise ValueError(f"Unsupported SBOM format '{fmt}'. Choose 'cyclonedx' or 'spdx'.")
    return json.dumps(data, indent=2) + "\n"


def write_sbom(report: AuditReport, output_path: Path, fmt: str = "cyclonedx") -> Path:
    """Write a CycloneDX or SPDX SBOM file to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    content = serialize_sbom(report, fmt=fmt)
    output_path.write_text(content, encoding="utf-8")
    return output_path
