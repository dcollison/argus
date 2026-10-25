"""Unit tests for uv workspace inspection and OSV.dev vulnerability auditing."""

from __future__ import annotations

from pathlib import Path

import httpx

from argus.models import Component, ComponentScope, ComponentType, Severity
from argus.osv import OsvClient, compute_cvss_v3_score, parse_osv_vulnerability
from argus.workspace import inspect_workspace
from tests.helpers import create_dist_info


def test_inspect_uv_workspace_separates_runtime_and_dev(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        """
[project]
name = "demo-app"
version = "1.2.3"
dependencies = [
    "requests>=2.31.0",
]

[dependency-groups]
dev = [
    "pytest>=8.0.0",
]
""".strip()
        + "\n",
        encoding="utf-8",
    )

    uv_lock = tmp_path / "uv.lock"
    uv_lock.write_text(
        """
version = 1

[[package]]
name = "demo-app"
version = "1.2.3"
source = { virtual = "." }
dependencies = [
    { name = "requests" },
]

[package.dev-dependencies]
dev = [
    { name = "pytest" },
]

[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
dependencies = [
    { name = "urllib3" },
]
sdist = { url = "https://example.com/requests-2.31.0.tar.gz", hash = "sha256:1111111111111111111111111111111111111111111111111111111111111111" }

[[package]]
name = "urllib3"
version = "2.0.7"
source = { registry = "https://pypi.org/simple" }
wheels = [
    { url = "https://example.com/urllib3-2.0.7-py3-none-any.whl", hash = "sha256:2222222222222222222222222222222222222222222222222222222222222222" },
]

[[package]]
name = "pytest"
version = "8.2.0"
source = { registry = "https://pypi.org/simple" }
""".strip()
        + "\n",
        encoding="utf-8",
    )

    site_packages = tmp_path / ".venv" / "Lib" / "site-packages"
    create_dist_info(
        site_packages,
        "requests",
        "2.31.0",
        license_str="Apache-2.0",
        requires_dist=["urllib3>=1.21.1"],
        top_level=["requests"],
        license_files={"LICENSE": "Apache License\nVersion 2.0, January 2004\nCopyright 2023 Kenneth Reitz"},
    )
    create_dist_info(
        site_packages,
        "urllib3",
        "2.0.7",
        license_expression="MIT",
        top_level=["urllib3"],
        license_files={"LICENSE.txt": "Copyright (c) 2008-2023 Andrey Petrov\nPermission is hereby granted, free of charge, to any person obtaining a copy"},
    )
    create_dist_info(
        site_packages,
        "pytest",
        "8.2.0",
        license_str="MIT",
        top_level=["pytest", "_pytest"],
    )

    ws = inspect_workspace(tmp_path, include_dev=False)
    assert ws.project_name == "demo-app"
    assert ws.project_version == "1.2.3"
    assert "requests" in ws.components
    assert "urllib3" in ws.components
    assert "pytest" in ws.components

    req_comp = ws.components["requests"]
    assert req_comp.is_bundled is True
    assert req_comp.scope == ComponentScope.REQUIRED
    assert req_comp.license_info.spdx_id == "Apache-2.0"
    assert req_comp.hashes["SHA256"].startswith("11111111")

    urllib_comp = ws.components["urllib3"]
    assert urllib_comp.is_bundled is True
    assert urllib_comp.scope == ComponentScope.REQUIRED
    assert urllib_comp.license_info.spdx_id == "MIT"

    pytest_comp = ws.components["pytest"]
    assert pytest_comp.is_bundled is False
    assert pytest_comp.scope == ComponentScope.DEV_EXCLUDED


def test_cvss_v3_calculator_and_osv_parsing() -> None:
    # Critical 9.8 vector
    assert compute_cvss_v3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    # High 7.5 vector
    assert compute_cvss_v3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == 7.5
    # Medium 5.3 vector
    assert compute_cvss_v3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N") == 5.3
    # Scope changed 10.0 vector
    assert compute_cvss_v3_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0

    raw_advisory = {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "summary": "Remote code execution in demo-pkg",
        "aliases": ["CVE-2025-99999"],
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
        "affected": [
            {
                "package": {"name": "demo-pkg", "ecosystem": "PyPI"},
                "ranges": [
                    {
                        "type": "ECOSYSTEM",
                        "events": [{"introduced": "0"}, {"fixed": "2.4.1"}],
                    }
                ],
            }
        ],
        "references": [{"type": "ADVISORY", "url": "https://osv.dev/vulnerability/GHSA-xxxx-yyyy-zzzz"}],
    }
    vuln = parse_osv_vulnerability(raw_advisory, "demo-pkg", "2.3.0")
    assert vuln.id == "GHSA-xxxx-yyyy-zzzz"
    assert vuln.primary_cve == "CVE-2025-99999"
    assert vuln.severity == Severity.CRITICAL
    assert vuln.cvss_score == 9.8
    assert vuln.fixed_versions == ["2.4.1"]
    assert "Upgrade demo-pkg to version >= 2.4.1" in vuln.remediation


def test_osv_client_batch_and_hydration() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {"vulns": [{"id": "PYSEC-2024-101", "modified": "2024-05-01T00:00:00Z"}]},
                        {"vulns": []},
                    ]
                },
            )
        if request.url.path == "/v1/vulns/PYSEC-2024-101":
            return httpx.Response(
                200,
                json={
                    "id": "PYSEC-2024-101",
                    "summary": "Header injection in urllib3",
                    "aliases": ["CVE-2024-12345"],
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N"}],
                    "affected": [
                        {
                            "package": {"name": "urllib3", "ecosystem": "PyPI"},
                            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.8"}]}],
                        }
                    ],
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    mock_http = httpx.Client(transport=transport)

    c1 = Component(name="urllib3", version="2.0.7", component_type=ComponentType.PYTHON_PACKAGE)
    c2 = Component(name="openssl", version="3.0.13", component_type=ComponentType.NATIVE_LIBRARY)

    osv = OsvClient(http_client=mock_http)
    warnings = osv.audit_components([c1, c2])
    assert warnings == []
    assert len(c1.vulnerabilities) == 1
    assert c1.vulnerabilities[0].id == "PYSEC-2024-101"
    assert c1.vulnerabilities[0].primary_cve == "CVE-2024-12345"
    assert c1.vulnerabilities[0].severity == Severity.HIGH
    assert c1.vulnerabilities[0].fixed_versions == ["2.0.8"]
    assert len(c2.vulnerabilities) == 0


def test_pip_audit_service_integration() -> None:
    from packaging.version import Version
    from pip_audit._service.interface import ResolvedDependency, VulnerabilityID, VulnerabilityResult
    from pip_audit._service.osv import OsvService

    class StubPipAuditOsvService(OsvService):
        def __init__(self) -> None:
            pass

        def query(self, spec: ResolvedDependency) -> tuple[ResolvedDependency, list[VulnerabilityResult]]:  # type: ignore[override]
            if spec.canonical_name == "requests":
                return (
                    spec,
                    [
                        VulnerabilityResult(
                            id=VulnerabilityID("PYSEC-2023-74"),
                            description="Unintended leak of Proxy-Authorization header in requests",
                            fix_versions=[Version("2.31.0")],
                            aliases={VulnerabilityID("CVE-2023-32681")},
                        )
                    ],
                )
            return spec, []

    comp = Component(name="requests", version="2.30.0", component_type=ComponentType.PYTHON_PACKAGE)
    osv = OsvClient(pip_audit_service=StubPipAuditOsvService())
    warnings = osv.audit_components([comp])
    assert warnings == []
    assert len(comp.vulnerabilities) == 1
    assert comp.vulnerabilities[0].id == "PYSEC-2023-74"
    assert comp.vulnerabilities[0].primary_cve == "CVE-2023-32681"
    assert comp.vulnerabilities[0].fixed_versions == ["2.31.0"]

    # Also verify CVSS severity hydration and native library auditing when http_client is provided alongside pip_audit_service
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/vulns/PYSEC-2023-74":
            return httpx.Response(
                200,
                json={
                    "id": "PYSEC-2023-74",
                    "summary": "Unintended leak of Proxy-Authorization header in requests",
                    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:N/A:N"}],
                },
            )
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200,
                json={
                    "results": [
                        {
                            "vulns": [
                                {
                                    "id": "OSV-2024-OPENSSL",
                                    "summary": "Buffer overread in openssl",
                                    "database_specific": {"severity": "HIGH", "cvss_score": 7.5},
                                }
                            ]
                        }
                    ]
                },
            )
        return httpx.Response(404)

    py_comp = Component(name="requests", version="2.30.0", component_type=ComponentType.PYTHON_PACKAGE)
    nat_comp = Component(name="openssl", version="3.0.12", component_type=ComponentType.NATIVE_LIBRARY)
    osv_hydrated = OsvClient(
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
        pip_audit_service=StubPipAuditOsvService(),
    )
    warnings_h = osv_hydrated.audit_components([py_comp, nat_comp])
    assert warnings_h == []
    assert py_comp.vulnerabilities[0].cvss_score == 6.1
    assert py_comp.vulnerabilities[0].severity == Severity.MEDIUM
    assert len(nat_comp.vulnerabilities) == 1
    assert nat_comp.vulnerabilities[0].id == "OSV-2024-OPENSSL"
    assert nat_comp.vulnerabilities[0].severity == Severity.HIGH


