import re

import pytest

pytest.importorskip(
    "flask",
    reason="Install requirements.txt to run Flask route tests"
)

import app as app_module
from cloudguard.database.db_manager import DatabaseManager


def sample_scan():
    """Return a small simulated scan for application route tests."""

    return {
        "tool": "CloudGuard",
        "scan_started_at": "2026-11-11T10:00:00+00:00",
        "scan_completed_at": "2026-11-11T10:00:05+00:00",
        "duration_seconds": 5.0,
        "summary": {
            "total_scanners": 6,
            "completed_scanners": 6,
            "total_findings": 1,
            "total_errors": 0,
            "severity_counts": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 1,
                "LOW": 0,
                "INFO": 0
            }
        },
        "services": {
            "IAM": {
                "service": "IAM",
                "findings": [],
                "errors": []
            }
        },
        "findings": [
            {
                "service": "IAM",
                "resource": "test-user",
                "check": "IAM_USER_WITHOUT_MFA",
                "severity": "MEDIUM",
                "title": "IAM user has no MFA",
                "description": "Test finding for route testing.",
                "recommendation": "Enable MFA.",
                "evidence": {
                    "registered_mfa_devices": 0
                }
            }
        ],
        "errors": []
    }


@pytest.fixture
def test_client(tmp_path, monkeypatch):
    """Create a Flask test client using an isolated temporary database."""

    test_database = DatabaseManager(
        db_path=tmp_path / "cloudguard_test.db"
    )

    monkeypatch.setattr(
        app_module,
        "database",
        test_database
    )

    app_module.app.config.update(TESTING=True)

    client = app_module.app.test_client()

    return client, test_database


def test_dashboard_loads_without_scans(test_client):
    client, database = test_client

    response = client.get("/")

    assert response.status_code == 200


def test_dashboard_loads_with_saved_scan(test_client):
    client, database = test_client

    database.save_scan(sample_scan())

    response = client.get("/")

    assert response.status_code == 200


def test_scan_details_page_loads(test_client):
    client, database = test_client

    scan_id = database.save_scan(sample_scan())

    response = client.get(f"/scans/{scan_id}")

    assert response.status_code == 200


def test_missing_scan_pages_return_404(test_client):
    client, database = test_client

    details_response = client.get("/scans/999999")
    report_response = client.get("/scans/999999/report")

    assert details_response.status_code == 404
    assert report_response.status_code == 404


def test_pdf_report_download(test_client, tmp_path, monkeypatch):
    client, database = test_client

    scan_id = database.save_scan(sample_scan())

    class FakePDFReportGenerator:
        """Create a small test PDF without using the real report generator."""

        def generate_report(self, results, scan_id=None):
            assert results["tool"] == "CloudGuard"

            summary = results["summary"]

            assert summary["total_findings"] == 1
            assert summary["successful_scanners"] == 0
            assert summary["partial_scanners"] == 0
            assert summary["failed_scanners"] == 0
            assert summary["unknown_scanners"] == 6

            assert scan_id is not None

            report_path = tmp_path / "test_report.pdf"

            report_path.write_bytes(
                b"%PDF-1.4\n% CloudGuard test report\n%%EOF\n"
            )

            return report_path

    monkeypatch.setattr(
        app_module,
        "PDFReportGenerator",
        FakePDFReportGenerator
    )

    response = client.get(f"/scans/{scan_id}/report")

    assert response.status_code == 200
    assert response.content_type == "application/pdf"
    assert response.data.startswith(b"%PDF-1.4")

    assert "attachment" in response.headers.get(
        "Content-Disposition", ""
    )


def test_health_endpoint(test_client):
    client, database = test_client

    database.save_scan(sample_scan())

    response = client.get("/health")

    assert response.status_code == 200

    data = response.get_json()

    assert data["application"] == "CloudGuard"
    assert data["status"] == "running"
    assert data["database"] == "connected"
    assert data["saved_scans"] == 1


def test_csv_export_download(test_client):
    client, database = test_client

    scan_id = database.save_scan(sample_scan())

    response = client.get(f"/scans/{scan_id}/export.csv")

    assert response.status_code == 200
    assert response.mimetype == "text/csv"

    assert (
        b"rule_id,resource_type,resource_id,resource"
        in response.data
    )

    assert (
        b"IAM-02,iam_user,test-user,test-user"
        in response.data
    )


# --------------------------------------------------
# CSRF SECURITY TESTS
# --------------------------------------------------

@pytest.mark.parametrize(
    "endpoint",
    [
        "/connect-aws",
        "/disconnect-aws",
        "/run-scan",
    ],
)
def test_post_routes_reject_requests_without_csrf_token(
    test_client,
    endpoint
):
    """All state-changing routes must reject requests without CSRF tokens."""

    client, database = test_client

    response = client.post(endpoint)

    assert response.status_code == 400


# --------------------------------------------------
# SCAN NOTIFICATION AND REPORTING TESTS
# --------------------------------------------------

@pytest.mark.parametrize(
    "statuses, expected_category, expected_message",
    [
        (
            ["success", "success"],
            "success",
            "All 2 scanners succeeded.",
        ),
        (
            ["success", "partial", "failed"],
            "warning",
            "Successful: 1, Partial: 1, Failed: 1, Unknown: 0.",
        ),
        (
            ["failed", "failed"],
            "danger",
            "all 2 scanners failed.",
        ),
    ],
)
def test_run_scan_reports_accurate_scanner_outcomes(
    test_client,
    monkeypatch,
    statuses,
    expected_category,
    expected_message,
):
    """Test scan notifications without making real AWS requests."""

    client, database = test_client

    # Obtain a valid CSRF token from the dashboard.
    page = client.get("/")

    assert page.status_code == 200

    match = re.search(
        r'name="csrf_token"\s+value="([^"]+)"',
        page.get_data(as_text=True),
    )

    assert match, "Dashboard did not provide a CSRF token."

    csrf_token = match.group(1)

    # Simulate an already verified AWS account.
    with client.session_transaction() as flask_session:
        flask_session["aws_account_email"] = "test@example.com"
        flask_session["aws_profile"] = "test-profile"
        flask_session["aws_region"] = "eu-north-1"
        flask_session["aws_account_id"] = "123456789012"

    fake_aws_session = object()

    fake_identity = {
        "account_id": "123456789012",
        "arn": "arn:aws:iam::123456789012:user/cloudguard-test",
    }

    monkeypatch.setattr(
        app_module,
        "reconnect_verified_profile",
        lambda **kwargs: (fake_aws_session, fake_identity),
    )

    services = {}
    all_errors = []

    for index, status in enumerate(statuses, start=1):
        service_name = f"TestService{index}"
        service_errors = []

        if status in ("partial", "failed"):
            error = {
                "service": service_name,
                "operation": "simulated_test",
                "message": "Simulated scanner error",
            }

            service_errors.append(error)
            all_errors.append(error)

        services[service_name] = {
            "service": service_name,
            "status": status,
            "findings": [],
            "errors": service_errors,
        }

    successful = statuses.count("success")
    partial = statuses.count("partial")
    failed = statuses.count("failed")
    total = len(statuses)

    fake_results = {
        "tool": "CloudGuard",
        "scan_started_at": "2026-11-14T10:00:00+00:00",
        "scan_completed_at": "2026-11-14T10:00:05+00:00",
        "duration_seconds": 5.0,
        "summary": {
            "total_scanners": total,
            "completed_scanners": successful + partial,
            "successful_scanners": successful,
            "partial_scanners": partial,
            "failed_scanners": failed,
            "unknown_scanners": 0,
            "total_findings": 0,
            "total_errors": len(all_errors),
            "severity_counts": {},
        },
        "services": services,
        "findings": [],
        "errors": all_errors,
    }

    class FakeScanManager:

        def __init__(self, session=None):
            assert session is fake_aws_session

        def run_all(self):
            return fake_results

    monkeypatch.setattr(
        app_module,
        "ScanManager",
        FakeScanManager,
    )

    # Submit the scan request with a valid CSRF token.
    response = client.post(
        "/run-scan",
        data={"csrf_token": csrf_token},
    )

    assert response.status_code == 302

    # Inspect Flask's flashed notification.
    with client.session_transaction() as flask_session:
        flashes = flask_session.get("_flashes", [])

    assert any(
        category == expected_category
        and expected_message in message
        for category, message in flashes
    ), flashes

    # Confirm every simulated scan was saved.
    history = database.get_scan_history()

    assert len(history) == 1

    assert history[0]["successful_scanners"] == successful
    assert history[0]["partial_scanners"] == partial
    assert history[0]["failed_scanners"] == failed