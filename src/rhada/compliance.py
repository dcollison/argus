"""Legal and licensing compliance engine and turnkey THIRD_PARTY_NOTICES generator."""

from __future__ import annotations

from pathlib import Path

from rhada.models import (
    AuditConfig,
    AuditMode,
    AuditReport,
    ComplianceFinding,
    Component,
    DistributionLayout,
    LicenseRiskCategory,
    Severity,
)
from rhada.spdx import evaluate_spdx_allowlist, evaluate_spdx_denylist, normalize_single_license
from rhada.workspace import matches_package_pattern

# Canonical fallback licence summaries when a wheel omits a verbatim LICENSE file
CANONICAL_LICENSE_FALLBACKS: dict[str, str] = {
    "MIT": (
        "MIT License\n\n"
        "Permission is hereby granted, free of charge, to any person obtaining a copy of this software and "
        'associated documentation files (the "Software"), to deal in the Software without restriction, '
        "including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, "
        "and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, "
        "subject to the following conditions:\n\n"
        "The above copyright notice and this permission notice shall be included in all copies or substantial "
        "portions of the Software.\n\n"
        'THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.'
    ),
    "Apache-2.0": (
        "Apache License, Version 2.0\n\n"
        'Licensed under the Apache License, Version 2.0 (the "License"); you may not use this component '
        "except in compliance with the License. You may obtain a copy of the License at:\n"
        "    http://www.apache.org/licenses/LICENSE-2.0\n\n"
        "Unless required by applicable law or agreed to in writing, software distributed under the License "
        'is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.'
    ),
    "BSD-3-Clause": (
        "BSD 3-Clause License\n\n"
        "Redistribution and use in source and binary forms, with or without modification, are permitted "
        "provided that the following conditions are met:\n"
        "1. Redistributions of source code must retain the above copyright notice, this list of conditions "
        "and the following disclaimer.\n"
        "2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions "
        "and the following disclaimer in the documentation and/or other materials provided with the distribution.\n"
        "3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse "
        "or promote products derived from this software without specific prior written permission."
    ),
    "BSD-2-Clause": (
        "BSD 2-Clause Simplified License\n\n"
        "Redistribution and use in source and binary forms, with or without modification, are permitted "
        "provided that the following conditions are met:\n"
        "1. Redistributions of source code must retain the above copyright notice, this list of conditions "
        "and the following disclaimer.\n"
        "2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions "
        "and the following disclaimer in the documentation and/or other materials provided with the distribution."
    ),
    "ISC": (
        "ISC License\n\n"
        "Permission to use, copy, modify, and/or distribute this software for any purpose with or without fee "
        "is hereby granted, provided that the above copyright notice and this permission notice appear in all copies."
    ),
    "PSF-2.0": (
        "Python Software Foundation License Version 2\n\n"
        "This software is licensed under the Python Software Foundation License Version 2. "
        "Full text available at https://docs.python.org/3/license.html"
    ),
    "MPL-2.0": (
        "Mozilla Public License Version 2.0\n\n"
        "This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. "
        "If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/."
    ),
    "LicenseRef-Intel-Simplified-Software-License": (
        "Intel Simplified Software License\n\n"
        "Use and redistribution of the Intel Math Kernel Library (MKL) binaries are permitted "
        "provided that the Intel copyright notice and license conditions are preserved."
    ),
}


def evaluate_compliance(
    components: list[Component],
    mode: AuditMode,
    layout: DistributionLayout,
    config: AuditConfig,
) -> list[ComplianceFinding]:
    """
    Evaluate all active/bundled components for legal and licence compliance risks.
    Detects strong copyleft contamination, LGPL static/monolithic relinking violations,
    proprietary dependencies, unknown licences, and explicit policy allow/deny rules.
    """
    findings: list[ComplianceFinding] = []
    denied_upper = {d.strip().upper() for d in config.denied_licenses if d.strip()}
    allowed_upper: set[str] = set()
    for a in config.allowed_licenses:
        clean = a.strip()
        if not clean:
            continue
        allowed_upper.add(clean.upper())
        norm = normalize_single_license(clean)
        if norm != "NOASSERTION":
            allowed_upper.add(norm.upper())

    for comp in components:
        if not comp.is_bundled or comp.is_internal:
            continue
        if config.internal_packages and matches_package_pattern(comp.name, config.internal_packages):
            continue
        if config.ignore_packages and matches_package_pattern(comp.name, config.ignore_packages):
            continue

        lic = comp.license_info
        spdx_id = lic.spdx_id or "NOASSERTION"
        choices = lic.license_choices or [spdx_id]
        choices_upper = {c.upper() for c in choices}

        # 1. Explicit Denied Licence Policy Check
        is_denied = denied_upper and (
            evaluate_spdx_denylist(spdx_id, denied_upper)
            or (not lic.is_dual_licensed and bool(choices_upper & denied_upper))
        )
        if is_denied:
            findings.append(
                ComplianceFinding(
                    rule_id="LIC-POLICY-DENIED",
                    component_name=comp.name,
                    component_version=comp.version,
                    license_spdx=spdx_id,
                    risk_category=lic.risk_category,
                    severity=Severity.CRITICAL,
                    title=f"Explicitly denied licence ({spdx_id})",
                    description=(
                        f"Component '{comp.name}@{comp.version}' is licensed under '{spdx_id}', "
                        "which is explicitly forbidden by the active deny-list policy."
                    ),
                    remediation=f"Remove '{comp.name}' or replace it with a dependency under an approved licence.",
                )
            )
            continue

        # Check if licence is permitted by explicit allow-list
        is_permitted = not allowed_upper or (
            evaluate_spdx_allowlist(spdx_id, allowed_upper)
            or (lic.is_dual_licensed and bool(choices_upper & allowed_upper))
            or (lic.declared_raw and lic.declared_raw.strip().upper() in allowed_upper)
            or (
                lic.risk_category == LicenseRiskCategory.PROPRIETARY
                and bool(allowed_upper & {"PROPRIETARY", "LICENSEREF-PROPRIETARY"})
            )
            or (
                (spdx_id.upper().endswith("-INTERNAL") or spdx_id.upper() == "LICENSEREF-INTERNAL")
                and bool(allowed_upper & {"INTERNAL", "LICENSEREF-INTERNAL"})
            )
        )
        is_explicitly_allowed = bool(allowed_upper) and is_permitted

        # 2. Explicit Allowed Licence Policy Check
        if allowed_upper and not is_permitted:
            findings.append(
                ComplianceFinding(
                    rule_id="LIC-POLICY-NOT-ALLOWED",
                    component_name=comp.name,
                    component_version=comp.version,
                    license_spdx=spdx_id,
                    risk_category=lic.risk_category,
                    severity=Severity.HIGH,
                    title=f"Licence '{spdx_id}' not in policy allow-list",
                    description=(
                        f"Component '{comp.name}@{comp.version}' declares licence '{spdx_id}', "
                        f"which is not among the approved licences ({', '.join(sorted(config.allowed_licenses))})."
                    ),
                    remediation=f"Request legal exception for '{spdx_id}' or replace '{comp.name}'.",
                )
            )

        # 3. Strong Copyleft (GPL / AGPL / SSPL)
        if lic.risk_category == LicenseRiskCategory.STRONG_COPYLEFT:
            is_network_copyleft = any(k in spdx_id.upper() for k in ("AGPL", "SSPL"))
            if is_network_copyleft:
                findings.append(
                    ComplianceFinding(
                        rule_id="LIC-COP-NETWORK",
                        component_name=comp.name,
                        component_version=comp.version,
                        license_spdx=spdx_id,
                        risk_category=lic.risk_category,
                        severity=Severity.CRITICAL,
                        title=f"Network Copyleft contamination ({spdx_id})",
                        description=(
                            f"Component '{comp.name}@{comp.version}' is governed by '{spdx_id}'. "
                            "Network copyleft mandates disclosure of the complete corresponding source code "
                            "of the combined application both upon distribution and when users interact with "
                            "it over a network."
                        ),
                        remediation=(
                            f"Eliminate '{comp.name}' from commercial builds or obtain a commercial "
                            "exception licence from the copyright holder."
                        ),
                    )
                )
            else:
                sev = Severity.CRITICAL if mode == AuditMode.COMPILED_DIST else Severity.HIGH
                findings.append(
                    ComplianceFinding(
                        rule_id="LIC-COP-STRONG",
                        component_name=comp.name,
                        component_version=comp.version,
                        license_spdx=spdx_id,
                        risk_category=lic.risk_category,
                        severity=sev,
                        title=f"Strong Copyleft licence in distribution ({spdx_id})",
                        description=(
                            f"Component '{comp.name}@{comp.version}' is governed by strong copyleft ('{spdx_id}'). "
                            "Distributing a binary or application linked with GPL components requires releasing "
                            "the entire combined work's source code under GPL terms."
                        ),
                        remediation=(
                            f"Replace '{comp.name}' with a permissive alternative, isolate it into a separate "
                            "process via clean IPC, or license the entire distribution under GPL."
                        ),
                    )
                )

        # 4. Weak Copyleft (LGPL / MPL / EPL / CDDL)
        elif lic.risk_category == LicenseRiskCategory.WEAK_COPYLEFT:
            is_lgpl = "LGPL" in spdx_id.upper() or any("LGPL" in c.upper() for c in choices)
            effective_src = (
                comp.source_url
                or comp.homepage
                or (
                    f"https://pypi.org/project/{comp.name}/{comp.version}/#files"
                    if comp.version and comp.version != "unknown"
                    else f"https://pypi.org/project/{comp.name}/"
                )
            )
            is_opaque_bundle = (
                layout == DistributionLayout.MONOLITHIC_BINARY
                or comp.is_statically_compiled
                or not comp.has_dynamic_relinking
            )
            if is_lgpl and mode == AuditMode.COMPILED_DIST and is_opaque_bundle:
                findings.append(
                    ComplianceFinding(
                        rule_id="LIC-LGPL-MONOLITHIC",
                        component_name=comp.name,
                        component_version=comp.version,
                        license_spdx=spdx_id,
                        risk_category=lic.risk_category,
                        severity=Severity.HIGH,
                        title=f"LGPL component locked in monolithic/static binary without relinking ({spdx_id})",
                        description=(
                            f"Component '{comp.name}@{comp.version}' ({spdx_id}) is bundled inside an opaque "
                            f"monolithic executable or statically compiled C module ({layout.value}). "
                            "LGPL Section 4(d) / Section 6 requires that recipients be able to modify the "
                            "LGPL library and relink or replace it in the executable, and access complete corresponding "
                            f"source code (Source Code: {effective_src})."
                        ),
                        remediation=(
                            "Switch from a monolithic onefile build to a standalone directory build where "
                            f"'{comp.name}' remains a dynamically loaded shared library (.so / .dll) or separate "
                            "Python module, provide relinkable object files alongside the binary, and provide "
                            f"source code access via: {effective_src}"
                        ),
                    )
                )
            elif is_lgpl:
                sev = Severity.MEDIUM if mode == AuditMode.COMPILED_DIST else Severity.LOW
                findings.append(
                    ComplianceFinding(
                        rule_id="LIC-LGPL-DYNAMIC",
                        component_name=comp.name,
                        component_version=comp.version,
                        license_spdx=spdx_id,
                        risk_category=lic.risk_category,
                        severity=sev,
                        title=f"Weak Copyleft (LGPL) dynamic relinking & attribution obligation ({spdx_id})",
                        description=(
                            f"Component '{comp.name}@{comp.version}' is licensed under '{spdx_id}'. "
                            "Commercial redistribution is permitted provided the library remains dynamically "
                            "replaceable, full LGPL licence text and copyright notices are included, and complete "
                            f"corresponding source code is made available (Source Code: {effective_src})."
                        ),
                        remediation=(
                            f"Include THIRD_PARTY_NOTICES with full '{spdx_id}' text, keep '{comp.name}' "
                            f"as a dynamically linked library or replaceable module, and provide source code access via: {effective_src}"
                        ),
                    )
                )
            else:
                findings.append(
                    ComplianceFinding(
                        rule_id="LIC-COP-WEAK",
                        component_name=comp.name,
                        component_version=comp.version,
                        license_spdx=spdx_id,
                        risk_category=lic.risk_category,
                        severity=Severity.LOW,
                        title=f"File-level Weak Copyleft obligation ({spdx_id})",
                        description=(
                            f"Component '{comp.name}@{comp.version}' is licensed under '{spdx_id}'. "
                            "Any modifications directly to files originating from this component must be "
                            "made available under the same licence."
                        ),
                        remediation="Include attribution in THIRD_PARTY_NOTICES and retain unmodified upstream files.",
                    )
                )

        # 5. Proprietary / Commercial Licence
        elif lic.risk_category == LicenseRiskCategory.PROPRIETARY:
            if not is_explicitly_allowed:
                findings.append(
                    ComplianceFinding(
                        rule_id="LIC-PROPRIETARY",
                        component_name=comp.name,
                        component_version=comp.version,
                        license_spdx=spdx_id,
                        risk_category=lic.risk_category,
                        severity=Severity.HIGH,
                        title=f"Proprietary or commercial licence detected ({spdx_id})",
                        description=(
                            f"Component '{comp.name}@{comp.version}' declares a proprietary or non-OSI "
                            f"commercial licence ('{lic.declared_raw}')."
                        ),
                        remediation=(
                            f"Verify that your organisation holds a valid redistribution licence for '{comp.name}', "
                            "or approve it via --allow-licence if this is an internal or approved commercial licence."
                        ),
                    )
                )

        # 6. Unknown / Unasserted Licence
        elif lic.risk_category == LicenseRiskCategory.UNKNOWN:
            if not is_explicitly_allowed:
                sev = Severity.LOW if config.allow_unknown_license else Severity.MEDIUM
                findings.append(
                    ComplianceFinding(
                        rule_id="LIC-UNKNOWN",
                        component_name=comp.name,
                        component_version=comp.version,
                        license_spdx=spdx_id,
                        risk_category=lic.risk_category,
                        severity=sev,
                        title=f"Undeclared or unrecognised licence for '{comp.name}'",
                        description=(
                            f"Component '{comp.name}@{comp.version}' has raw licence metadata '{lic.declared_raw}' "
                            "which could not be resolved to a recognised SPDX identifier."
                        ),
                        remediation=(
                            f"Inspect the upstream repository for '{comp.name}' to confirm redistribution rights "
                            "and record its SPDX identifier, or approve it via --allow-licence."
                        ),
                    )
                )

        # 7. Missing verbatim licence text check for non-public-domain components
        if (
            not is_explicitly_allowed
            and not lic.license_texts
            and lic.risk_category not in (LicenseRiskCategory.PUBLIC_DOMAIN, LicenseRiskCategory.UNKNOWN)
        ):
            findings.append(
                ComplianceFinding(
                    rule_id="LIC-MISSING-TEXT",
                    component_name=comp.name,
                    component_version=comp.version,
                    license_spdx=spdx_id,
                    risk_category=lic.risk_category,
                    severity=Severity.LOW,
                    title=f"Missing verbatim LICENSE file in package metadata ({comp.name})",
                    description=(
                        f"Component '{comp.name}@{comp.version}' declares licence '{spdx_id}', "
                        "but its .dist-info metadata did not bundle a verbatim LICENSE file."
                    ),
                    remediation="Ensure canonical licence text is included in THIRD_PARTY_NOTICES.",
                )
            )

    # 8. Cross-Component License Incompatibility Checks in Compiled Distributions
    if mode == AuditMode.COMPILED_DIST:
        active_bundled = [c for c in components if c.is_bundled]

        # 8a. GPL-2.0-only incompatibility with Apache-2.0
        # Under FSF analysis, Apache-2.0 patent termination (Sec. 3) and indemnity (Sec. 9) clauses
        # are "further restrictions" prohibited by GPL-2.0 Section 6.
        has_gpl2 = any(c.license_info.spdx_id in ("GPL-2.0-only", "GPL-2.0") for c in active_bundled)
        if has_gpl2:
            findings.extend(
                ComplianceFinding(
                    rule_id="LIC-INCOMPATIBLE-COMBINATION",
                    component_name=ac.name,
                    component_version=ac.version,
                    license_spdx=ac.license_info.spdx_id,
                    risk_category=ac.license_info.risk_category,
                    severity=Severity.CRITICAL,
                    title="License incompatibility: Apache-2.0 statically linked with GPL-2.0-only",
                    description=(
                        f"Component '{ac.name}@{ac.version}' ({ac.license_info.spdx_id}) is bundled in the same "
                        "compiled binary as a GPL-2.0-only component. Apache-2.0 patent termination "
                        "and indemnity terms are considered 'further restrictions' prohibited by GPL-2.0 Section 6."
                    ),
                    remediation=(
                        "Upgrade the GPL-2.0 component to GPL-3.0 (or GPL-2.0-or-later), "
                        f"or replace the Apache-2.0 dependency '{ac.name}'."
                    ),
                )
                for ac in active_bundled
                if (
                    ac.license_info.spdx_id == "Apache-2.0"
                    or (not ac.license_info.is_dual_licensed and "Apache-2.0" in ac.license_info.license_choices)
                )
            )

        # 8b. Strong Copyleft combined with Proprietary components
        has_strong_copyleft = any(
            c.license_info.risk_category == LicenseRiskCategory.STRONG_COPYLEFT for c in active_bundled
        )
        if has_strong_copyleft:
            findings.extend(
                ComplianceFinding(
                    rule_id="LIC-INCOMPATIBLE-PROPRIETARY-GPL",
                    component_name=pc.name,
                    component_version=pc.version,
                    license_spdx=pc.license_info.spdx_id,
                    risk_category=pc.license_info.risk_category,
                    severity=Severity.CRITICAL,
                    title=f"License conflict: Proprietary code bundled with Strong Copyleft ({pc.name})",
                    description=(
                        f"Proprietary component '{pc.name}@{pc.version}' is bundled into the same compiled "
                        "distribution as strong copyleft (GPL) components. GPL requires the complete combined "
                        "work to be licensed under the GPL."
                    ),
                    remediation=(
                        f"Isolate '{pc.name}' into an independent process communicating over standard IPC, "
                        "or replace the strong copyleft dependencies with permissive alternatives."
                    ),
                )
                for pc in active_bundled
                if pc.license_info.risk_category == LicenseRiskCategory.PROPRIETARY
            )

    return findings


def generate_third_party_notices(report: AuditReport) -> str:
    """
    Generate a THIRD_PARTY_NOTICES attribution file suitable for
    distribution alongside Python or compiled software.
    """
    bundled = [c for c in report.components if c.is_bundled and not c.is_internal]
    bundled_sorted = sorted(bundled, key=lambda c: (c.name.lower(), c.version))

    lines: list[str] = [
        "================================================================================",
        "                          THIRD-PARTY SOFTWARE NOTICES                          ",
        "================================================================================",
        "",
        f"Application: {report.target_name} ({report.target_version})",
        f"Audit Mode:  {report.mode.value} ({report.layout.value})",
        "",
        "This product includes or links to third-party open-source software components.",
        "Acknowledgements, copyright notices, and licence terms for each component are",
        "reproduced below in accordance with their respective licence obligations.",
        "",
        "LEGAL DISCLAIMER:",
        "  These third-party notices were automatically compiled by Rhada based on package",
        "  metadata and static file analysis. Rhada is not a legal advisor and does not",
        "  provide legal advice or warranty of compliance. Software distributors should",
        "  review these notices with qualified legal counsel before commercial distribution.",
        "",
        "--------------------------------------------------------------------------------",
        "COMPONENT SUMMARY",
        "--------------------------------------------------------------------------------",
    ]

    if not bundled_sorted:
        lines.append("No third-party runtime components detected.")
    else:
        for idx, comp in enumerate(bundled_sorted, start=1):
            lic_str = comp.license_info.spdx_id
            ctype = "Native Library" if comp.component_type.value == "native-library" else "Python Package"
            lines.append(f"  {idx:2d}. {comp.name} ({comp.version}) - {lic_str} [{ctype}]")

    lines.append("")

    for comp in bundled_sorted:
        lic = comp.license_info
        lines.extend(
            [
                "================================================================================",
                f"Component: {comp.name}",
                f"Version:   {comp.version}",
                f"Type:      {comp.component_type.value}",
                f"PURL:      {comp.purl}",
                f"License:   {lic.spdx_id}",
            ]
        )
        if comp.homepage:
            lines.append(f"Homepage:    {comp.homepage}")
        if comp.source_url and comp.source_url != comp.homepage:
            lines.append(f"Source Code: {comp.source_url}")
        if lic.is_dual_licensed and lic.license_choices:
            lines.append(
                f"Note:        Dual-licensed ({' OR '.join(lic.license_choices)}); "
                f"redistributed under the least restrictive applicable terms."
            )
        is_lgpl = "LGPL" in lic.spdx_id.upper() or any("LGPL" in c.upper() for c in (lic.license_choices or []))
        if is_lgpl:
            src_link = (
                comp.source_url
                or comp.homepage
                or (
                    f"https://pypi.org/project/{comp.name}/{comp.version}/#files"
                    if comp.version and comp.version != "unknown"
                    else f"https://pypi.org/project/{comp.name}/"
                )
            )
            lines.extend(
                [
                    "",
                    "LGPL Compliance & Source Code Offer:",
                    f"  This component is governed by the {lic.spdx_id} licence.",
                    "  In accordance with LGPL requirements (Section 4(d) / Section 6), recipients of",
                    "  this distribution are entitled to obtain the complete corresponding source code",
                    "  for this library. The upstream source code is accessible at:",
                    f"    {src_link}",
                    "  Alternatively, if you received this binary distribution and require the exact",
                    "  source code archive, you may request it from the software distributor.",
                ]
            )
        lines.append("--------------------------------------------------------------------------------")
        lines.append("")

        # Copyright notices
        if lic.copyright_notices:
            lines.append("Copyright Notices:")
            lines.extend(f"  {notice}" for notice in lic.copyright_notices)
            lines.append("")
        elif comp.author:
            lines.append("Copyright Notices:")
            lines.append(f"  Copyright (c) {comp.author}")
            lines.append("")

        # Verbatim NOTICE / AUTHORS texts (mandatory for Apache-2.0 Section 4(d))
        if lic.notice_texts:
            for notice_filename, notice_body in sorted(lic.notice_texts.items()):
                lines.append(f"--- Begin {notice_filename} ---")
                lines.append(notice_body.strip())
                lines.append(f"--- End {notice_filename} ---")
                lines.append("")

        # Verbatim LICENSE texts or canonical fallback
        if lic.license_texts:
            for lic_filename, lic_body in sorted(lic.license_texts.items()):
                lines.append(f"--- Begin {lic_filename} ---")
                lines.append(lic_body.strip())
                lines.append(f"--- End {lic_filename} ---")
                lines.append("")
        else:
            primary_choice = lic.license_choices[0] if lic.license_choices else lic.spdx_id
            fallback_text = CANONICAL_LICENSE_FALLBACKS.get(primary_choice) or CANONICAL_LICENSE_FALLBACKS.get(
                lic.spdx_id
            )
            if fallback_text:
                lines.append(f"--- Standard {primary_choice} License Notice ---")
                lines.append(fallback_text)
                lines.append(f"--- End Standard {primary_choice} License Notice ---")
                lines.append("")
            else:
                lines.append(f"Declared License: {lic.declared_raw} ({lic.spdx_id})")
                lines.append("")

    lines.append("================================================================================")
    lines.append("End of Third-Party Software Notices")
    lines.append("================================================================================")
    return "\n".join(lines) + "\n"


def write_third_party_notices(report: AuditReport, output_path: Path) -> Path:
    """Write the generated THIRD_PARTY_NOTICES content to disk."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    content = generate_third_party_notices(report)
    output_path.write_text(content, encoding="utf-8")
    return output_path
