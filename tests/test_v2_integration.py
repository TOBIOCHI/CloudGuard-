import csv
import io
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from cloudguard.scanners.s3_scanner import S3Scanner
from cloudguard.core.scan_manager import ScanManager
from cloudguard.core.rules import attach_rule_metadata
from evaluation.evaluate import evaluate
from cloudguard.core.export import findings_to_csv
from cloudguard.database.db_manager import DatabaseManager


class MultiBucketSession:
    def __init__(self):
        self.s3 = MultiBucketS3()
    def client(self, name):
        if name == "s3": return self.s3
        if name == "s3control": return AccountBPA()
        if name == "sts": return STS()
        raise AssertionError(name)

class STS:
    def get_caller_identity(self): return {"Account": "123456789012"}
class AccountBPA:
    def get_public_access_block(self, AccountId):
        return {"PublicAccessBlockConfiguration": {
            "BlockPublicAcls": True, "IgnorePublicAcls": True,
            "BlockPublicPolicy": True, "RestrictPublicBuckets": True}}
class MultiBucketS3:
    def list_buckets(self): return {"Buckets": [{"Name": "good"}, {"Name": "bad"}, {"Name": "also-good"}]}
    def get_public_access_block(self, Bucket):
        if Bucket == "bad":
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "GetPublicAccessBlock")
        return {"PublicAccessBlockConfiguration": {}}
    def get_bucket_policy_status(self, Bucket): return {"PolicyStatus": {"IsPublic": False}}
    def get_bucket_acl(self, Bucket): return {"Grants": []}


def test_account_bpa_is_effective_per_flag():
    scanner = object.__new__(S3Scanner)
    scanner.findings, scanner.errors = [], []
    scanner.check_block_public_access("bucket",
        {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}, {})
    assert not scanner.findings
    scanner.check_block_public_access("bucket",
        {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True},
        {"BlockPublicAcls": False})
    assert not scanner.findings  # account-level True overrides bucket-level False
    scanner.check_block_public_access("bucket", {}, {})
    assert scanner.findings and "disabled_flags" in scanner.findings[-1]["evidence"]


def test_s3_bucket_failure_is_isolated():
    result = S3Scanner(session=MultiBucketSession()).scan()
    assert result["discovered_buckets"] == 3
    assert result["attempted_buckets"] == 3
    assert result["successfully_inspected_buckets"] == 2
    assert result["scanned_buckets"] == 2
    assert any(e.get("resource") == "bad" for e in result["errors"])
    assert len(result["errors"]) == 1


def test_legacy_finding_gets_optional_rule_metadata():
    finding = {"check": "PUBLIC_BUCKET_POLICY", "severity": "HIGH", "resource": "demo"}
    attach_rule_metadata(finding)
    assert finding["rule_id"] == "S3-01"
    assert finding["category"] == "Storage"
    assert finding["severity"] == "HIGH"


def test_evaluation_confusion_matrix_and_metrics_inputs():
    gt = [
        {"resource_type": "s3_bucket", "resource_id": "public-bucket", "rule_id": "S3-01", "expected": "FAIL"},
        {"resource_type": "s3_bucket", "resource_id": "private-bucket", "rule_id": "S3-01", "expected": "PASS"},
        {"resource_type": "s3_bucket", "resource_id": "missing-bucket", "rule_id": "S3-01", "expected": "FAIL"},
        {"resource_type": "s3_bucket", "resource_id": "clean-bucket", "rule_id": "S3-01", "expected": "PASS"},
    ]
    findings = [
        {"resource_type": "s3_bucket", "resource_id": "public-bucket", "rule_id": "S3-01"},
        {"resource_type": "s3_bucket", "resource_id": "private-bucket", "rule_id": "S3-01"},
    ]
    tp, fp, fn, tn, detail, unlabelled = evaluate(gt, findings)
    assert (tp, fp, fn, tn) == (1, 1, 1, 1)
    assert len(detail) == 4 and unlabelled == []


def test_scan_manager_records_module_timings(monkeypatch):
    class FakeScanner:
        def scan(self): return {"service": "fake", "findings": [], "errors": []}
    manager = ScanManager()
    manager.scanners = [("Fake", FakeScanner)]
    result = manager.run_all()
    assert result["summary"]["total_scanners"] == 1
    assert result["summary"]["completed_scanners"] == 1
    assert result["services"]["Fake"]["duration_seconds"] >= 0
    assert result["duration_seconds"] >= 0


def test_pdf_generator_writes_valid_pdf(tmp_path):
    from cloudguard.reports.pdf_generator import PDFReportGenerator
    result = {
        "tool": "CloudGuard",
        "scan_started_at": "2026-11-12T10:00:00+00:00",
        "scan_completed_at": "2026-11-12T10:00:01+00:00",
        "duration_seconds": 1.0,
        "summary": {"total_scanners": 6, "completed_scanners": 6,
                    "total_findings": 0, "total_errors": 0,
                    "severity_counts": {"HIGH": 0, "MEDIUM": 0, "LOW": 0}},
        "services": {}, "findings": [], "errors": [],
    }
    path = PDFReportGenerator(output_dir=tmp_path).generate_report(result, scan_id=987)
    data = path.read_bytes()
    assert data.startswith(b"%PDF")
    assert len(data) > 500


def test_csv_export_contains_rule_id_and_resource():
    csv_text = findings_to_csv({"findings": [{
        "check_name": "PUBLIC_BUCKET_POLICY", "resource": "demo-bucket",
        "service": "S3", "severity": "HIGH", "title": "Public policy",
        "description": "Test", "recommendation": "Restrict access",
    }]})
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert rows[0]["rule_id"] == "S3-01"
    assert rows[0]["resource_type"] == "s3_bucket"
    assert rows[0]["resource_id"] == "demo-bucket"
    assert rows[0]["resource"] == "demo-bucket"


def test_module_timing_survives_existing_database_storage(tmp_path):
    db = DatabaseManager(db_path=tmp_path / "timing.db")
    sample = {
        "scan_started_at": "2026-11-12T10:00:00+00:00",
        "scan_completed_at": "2026-11-12T10:00:01+00:00",
        "duration_seconds": 1.0,
        "summary": {"total_scanners": 1, "completed_scanners": 1,
                    "total_findings": 0, "total_errors": 0, "severity_counts": {}},
        "services": {"S3": {"service": "S3", "findings": [], "errors": [], "duration_seconds": 0.25}},
        "findings": [], "errors": [],
    }
    scan_id = db.save_scan(sample)
    details = db.get_scan_details(scan_id)
    assert details["services"]["S3"]["duration_seconds"] == 0.25


def test_scan_manager_passes_same_session_to_all_scanners():
    """Verify every scanner receives the selected AWS session."""

    fake_session = object()
    received_sessions = []

    class FakeScanner:
        def __init__(self, session=None):
            received_sessions.append(session)

        def scan(self):
            return {
                "service": "fake",
                "findings": [],
                "errors": [],
            }

    manager = ScanManager(session=fake_session)

    manager.scanners = [
        ("FakeS3", FakeScanner),
        ("FakeIAM", FakeScanner),
        ("FakeEC2", FakeScanner),
    ]

    result = manager.run_all()

    assert received_sessions == [
        fake_session,
        fake_session,
        fake_session,
    ]

    assert result["summary"]["completed_scanners"] == 3
    assert result["summary"]["total_errors"] == 0

def test_pdf_report_includes_scanner_status_breakdown():
    from cloudguard.reports.pdf_generator import PDFReportGenerator

    generator = PDFReportGenerator.__new__(PDFReportGenerator)

    # Capture the report content without creating a PDF file.
    generator._section = lambda text: str(text)
    generator._paragraph = lambda text, style=None: str(text)
    generator._make_table = lambda rows, widths: rows

    results = {
        "summary": {
            "total_scanners": 3,
            "completed_scanners": 2,
            "successful_scanners": 1,
            "partial_scanners": 1,
            "failed_scanners": 1,
            "unknown_scanners": 0,
            "total_findings": 0,
            "total_errors": 2,
            "severity_counts": {},
        },
        "services": {
            "S3": {
                "status": "success",
                "scanned_buckets": 2,
                "findings": [],
                "errors": [],
            },
            "IAM": {
                "status": "partial",
                "scanned_users": 1,
                "findings": [],
                "errors": [{"message": "AccessDenied"}],
            },
            "EC2": {
                "status": "failed",
                "scanned_security_groups": 0,
                "findings": [],
                "errors": [{"message": "Scanner failed"}],
            },
        },
        "findings": [],
        "errors": [],
    }

    story = []

    generator._add_executive_summary(story, results)
    generator._add_service_results(story, results)

    def collect_text(item):
        if isinstance(item, str):
            return item

        if isinstance(item, (list, tuple)):
            return " ".join(collect_text(value) for value in item)

        return ""

    report_text = collect_text(story)

    for expected in [
        "Successful",
        "Partial",
        "Failed",
        "Unknown",
        "S3",
        "IAM",
        "EC2",
    ]:
        assert expected in report_text