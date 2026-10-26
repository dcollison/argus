"""Unit tests for SPDX normalization, compound expressions, compliance rules, and THIRD_PARTY_NOTICES."""

from __future__ import annotations

from pathlib import Path

from rhada.compliance import (
    evaluate_compliance,
    write_third_party_notices,
)
from rhada.models import (
    AuditConfig,
    AuditMode,
    AuditReport,
    Component,
    ComponentType,
    DistributionLayout,
    LicenseRiskCategory,
    Severity,
)
from rhada.spdx import (
    build_license_info,
    extract_copyright_notices,
    infer_spdx_from_license_text,
    normalize_single_license,
    parse_spdx_expression,
)


def test_normalize_single_license_variants() -> None:
    assert normalize_single_license("MIT License") == "MIT"
    assert normalize_single_license("Apache Software License 2.0") == "Apache-2.0"
    assert normalize_single_license("3-Clause BSD") == "BSD-3-Clause"
    assert normalize_single_license("GNU Lesser General Public License v2.1 or later") == "LGPL-2.1-or-later"
    assert normalize_single_license("GNU Affero General Public License v3") == "AGPL-3.0-only"
    assert normalize_single_license("GPL-3.0-with-GCC-exception") == "GPL-3.0-with-GCC-exception"
    assert normalize_single_license("UNKNOWN") == "NOASSERTION"
    assert normalize_single_license("") == "NOASSERTION"


def test_compound_spdx_or_and_expressions() -> None:
    # Dual-licensed OR expression selects least restrictive category (MIT -> permissive)
    spdx_or, cat_or, is_dual_or, choices_or = parse_spdx_expression("Apache-2.0 OR GPL-2.0-only")
    assert spdx_or == "Apache-2.0 OR GPL-2.0-only"
    assert cat_or == LicenseRiskCategory.PERMISSIVE
    assert is_dual_or is True
    assert choices_or == ["Apache-2.0", "GPL-2.0-only"]

    # Conjunctive AND expression selects most restrictive category (GPL-2.0-only -> strong-copyleft)
    spdx_and, cat_and, is_dual_and, choices_and = parse_spdx_expression("MIT AND GPL-2.0-only")
    assert spdx_and == "MIT AND GPL-2.0-only"
    assert cat_and == LicenseRiskCategory.STRONG_COPYLEFT
    assert is_dual_and is False
    assert choices_and == ["MIT", "GPL-2.0-only"]


def test_infer_spdx_from_license_text_and_copyrights() -> None:
    mit_text = (
        "Copyright (c) 2024 Acme Corp.\n"
        "Permission is hereby granted, free of charge, to any person obtaining a copy of this software..."
    )
    assert infer_spdx_from_license_text(mit_text) == "MIT"
    notices = extract_copyright_notices({"LICENSE": mit_text})
    assert notices == ["Copyright (c) 2024 Acme Corp."]

    info = build_license_info(
        declared_raw="UNKNOWN",
        license_texts={"LICENSE": mit_text},
        notice_texts={"NOTICE": "Acme Notice Attribution"},
    )
    assert info.spdx_id == "MIT"
    assert info.risk_category == LicenseRiskCategory.PERMISSIVE
    assert info.copyright_notices == ["Copyright (c) 2024 Acme Corp."]


def test_compliance_lgpl_monolithic_vs_dynamic() -> None:
    lgpl_info = build_license_info(
        declared_raw="LGPL-2.1-only",
        license_texts={"COPYING.LESSER": "GNU LESSER GENERAL PUBLIC LICENSE Version 2.1"},
    )

    # 1. LGPL bundled in a monolithic onefile binary without dynamic relinking -> HIGH violation
    comp_mono = Component(
        name="py-lgpl-lib",
        version="1.4.0",
        license_info=lgpl_info,
        is_bundled=True,
        is_statically_compiled=True,
        has_dynamic_relinking=False,
    )
    findings_mono = evaluate_compliance(
        [comp_mono],
        mode=AuditMode.COMPILED_DIST,
        layout=DistributionLayout.MONOLITHIC_BINARY,
        config=AuditConfig(),
    )
    rule_ids_mono = {f.rule_id: f for f in findings_mono}
    assert "LIC-LGPL-MONOLITHIC" in rule_ids_mono
    assert rule_ids_mono["LIC-LGPL-MONOLITHIC"].severity == Severity.HIGH

    # 2. LGPL in a standalone directory with dynamic relinking -> MEDIUM warning
    comp_dyn = Component(
        name="py-lgpl-lib",
        version="1.4.0",
        license_info=lgpl_info,
        is_bundled=True,
        is_statically_compiled=False,
        has_dynamic_relinking=True,
    )
    findings_dyn = evaluate_compliance(
        [comp_dyn],
        mode=AuditMode.COMPILED_DIST,
        layout=DistributionLayout.STANDALONE_DIR,
        config=AuditConfig(),
    )
    rule_ids_dyn = {f.rule_id: f for f in findings_dyn}
    assert "LIC-LGPL-DYNAMIC" in rule_ids_dyn
    assert rule_ids_dyn["LIC-LGPL-DYNAMIC"].severity == Severity.MEDIUM


def test_compliance_strong_copyleft_and_policy_lists() -> None:
    agpl_comp = Component(
        name="agpl-engine",
        version="3.0.0",
        license_info=build_license_info(
            declared_raw="AGPL-3.0-only",
            license_texts={"LICENSE": "GNU AFFERO GENERAL PUBLIC LICENSE Version 3"},
        ),
    )
    mit_comp = Component(
        name="mit-helper",
        version="1.0.0",
        license_info=build_license_info(
            declared_raw="MIT",
            license_texts={"LICENSE": "MIT License..."},
        ),
    )

    config = AuditConfig(
        denied_licenses={"MIT"},
        allowed_licenses={"Apache-2.0"},
    )
    findings = evaluate_compliance(
        [agpl_comp, mit_comp],
        mode=AuditMode.SOURCE,
        layout=DistributionLayout.SOURCE_WORKSPACE,
        config=config,
    )
    by_rule = {f.rule_id: f for f in findings}
    assert "LIC-COP-NETWORK" in by_rule
    assert by_rule["LIC-COP-NETWORK"].severity == Severity.CRITICAL
    assert "LIC-POLICY-DENIED" in by_rule
    assert by_rule["LIC-POLICY-DENIED"].component_name == "mit-helper"


def test_generate_third_party_notices(tmp_path: Path) -> None:
    c1 = Component(
        name="httpx",
        version="0.27.0",
        component_type=ComponentType.PYTHON_PACKAGE,
        homepage="https://www.python-httpx.org/",
        license_info=build_license_info(
            declared_raw="BSD-3-Clause",
            license_texts={"LICENSE.md": "Copyright © 2019, Encode OSS Ltd. All rights reserved.\nBSD 3-Clause..."},
            notice_texts={"NOTICE": "Encode OSS Notice file content"},
        ),
    )
    c2 = Component(
        name="openssl",
        version="3.0.13",
        component_type=ComponentType.NATIVE_LIBRARY,
        license_info=build_license_info(
            declared_raw="Apache-2.0",
            author="The OpenSSL Project",
        ),
    )
    report = AuditReport(
        target_name="billing-service",
        target_version="2.1.0",
        mode=AuditMode.COMPILED_DIST,
        layout=DistributionLayout.STANDALONE_DIR,
        components=[c1, c2],
    )
    out_file = tmp_path / "THIRD_PARTY_NOTICES"
    write_third_party_notices(report, out_file)

    text = out_file.read_text(encoding="utf-8")
    assert "THIRD-PARTY SOFTWARE NOTICES" in text
    assert "LEGAL DISCLAIMER:" in text
    assert "Application: billing-service (2.1.0)" in text
    assert "httpx (0.27.0) - BSD-3-Clause [Python Package]" in text
    assert "openssl (3.0.13) - Apache-2.0 [Native Library]" in text
    assert "Copyright © 2019, Encode OSS Ltd." in text
    assert "Encode OSS Notice file content" in text
    assert "Standard Apache-2.0 License Notice" in text


def test_lgpl_source_code_link_in_findings_and_notices(tmp_path: Path) -> None:
    comp_lgpl = Component(
        name="py-lgpl-core",
        version="2.0.1",
        component_type=ComponentType.PYTHON_PACKAGE,
        homepage="https://example.org/py-lgpl",
        source_url="https://github.com/example/py-lgpl-core",
        license_info=build_license_info(
            declared_raw="LGPL-3.0-only",
            license_texts={"COPYING.LESSER": "GNU LESSER GENERAL PUBLIC LICENSE Version 3"},
        ),
        is_bundled=True,
    )

    findings = evaluate_compliance(
        [comp_lgpl],
        mode=AuditMode.SOURCE,
        layout=DistributionLayout.SOURCE_WORKSPACE,
        config=AuditConfig(),
    )
    lgpl_findings = [f for f in findings if f.rule_id == "LIC-LGPL-DYNAMIC"]
    assert len(lgpl_findings) == 1
    finding = lgpl_findings[0]
    assert "https://github.com/example/py-lgpl-core" in finding.description
    assert "https://github.com/example/py-lgpl-core" in finding.remediation

    report = AuditReport(
        target_name="test-app",
        target_version="1.0.0",
        mode=AuditMode.SOURCE,
        components=[comp_lgpl],
    )
    out_file = tmp_path / "THIRD_PARTY_NOTICES"
    write_third_party_notices(report, out_file)
    content = out_file.read_text(encoding="utf-8")
    assert "LGPL Compliance & Source Code Offer:" in content
    assert "https://github.com/example/py-lgpl-core" in content
    assert "Source Code: https://github.com/example/py-lgpl-core" in content


def test_company_internal_license_suppresses_violations() -> None:
    corp_comp = Component(
        name="acme-internal-auth",
        version="1.0.0",
        component_type=ComponentType.PYTHON_PACKAGE,
        license_info=build_license_info(
            declared_raw="LicenseRef-Acme-Proprietary",
        ),
        is_bundled=True,
    )

    # 1. Without approving the internal licence, LIC-PROPRIETARY triggers
    findings_default = evaluate_compliance(
        [corp_comp],
        mode=AuditMode.SOURCE,
        layout=DistributionLayout.SOURCE_WORKSPACE,
        config=AuditConfig(),
    )
    assert any(f.rule_id == "LIC-PROPRIETARY" for f in findings_default)

    # 2. Approved via company_licenses -> No violations
    findings_company = evaluate_compliance(
        [corp_comp],
        mode=AuditMode.SOURCE,
        layout=DistributionLayout.SOURCE_WORKSPACE,
        config=AuditConfig(company_licenses={"LicenseRef-Acme-Proprietary"}),
    )
    assert not any(f.rule_id in ("LIC-PROPRIETARY", "LIC-POLICY-NOT-ALLOWED", "LIC-UNKNOWN") for f in findings_company)

    # 3. Approved via allowed_licenses -> No violations
    findings_allowed = evaluate_compliance(
        [corp_comp],
        mode=AuditMode.SOURCE,
        layout=DistributionLayout.SOURCE_WORKSPACE,
        config=AuditConfig(allowed_licenses={"LicenseRef-Acme-Proprietary"}),
    )
    assert not any(f.rule_id in ("LIC-PROPRIETARY", "LIC-UNKNOWN") for f in findings_allowed)


def test_legal_disclaimer_coverage() -> None:
    from rhada.models import LEGAL_DISCLAIMER
    from rhada.reporter import format_report_text

    report = AuditReport(
        target_name="disclaimer-test",
        target_version="1.0.0",
        mode=AuditMode.SOURCE,
    )
    assert report.disclaimer == LEGAL_DISCLAIMER
    assert report.to_dict()["disclaimer"] == LEGAL_DISCLAIMER

    text_report = format_report_text(report)
    assert "Rhada is an automated analysis tool, not a provider of legal advice" in text_report

