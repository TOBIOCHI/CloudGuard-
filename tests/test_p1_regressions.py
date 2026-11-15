"""P1 regression coverage: S3 BPA certainty, rule metadata, and evaluation."""
import csv
import io

import pytest
from botocore.exceptions import ClientError

from cloudguard.core.export import findings_to_csv
from cloudguard.core.rules import attach_rule_metadata
from cloudguard.scanners.s3_scanner import S3Scanner
from evaluation.evaluate import evaluate, load


PUBLIC_GROUP = "http://acs.amazonaws.com/groups/global/AllUsers"
ALL_BPA_FLAGS = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def aws_error(code, operation):
    return ClientError(
        {"Error": {"Code": code, "Message": f"simulated {code}"}}, operation
    )


class Identity:
    def get_caller_identity(self):
        return {"Account": "123456789012"}


class S3Stub:
    def __init__(self, bucket_bpa=None, policy_public=True, public_acl=True,
                 list_error=None, policy_error=None, acl_error=None):
        self.bucket_bpa = bucket_bpa
        self.policy_public = policy_public
        self.public_acl = public_acl
        self.list_error = list_error
        self.policy_error = policy_error
        self.acl_error = acl_error

    def list_buckets(self):
        if self.list_error:
            raise self.list_error
        return {"Buckets": [{"Name": "review-bucket"}]}

    def get_public_access_block(self, Bucket):
        if isinstance(self.bucket_bpa, Exception):
            raise self.bucket_bpa
        return {"PublicAccessBlockConfiguration": self.bucket_bpa or {}}

    def get_bucket_policy_status(self, Bucket):
        if self.policy_error:
            raise self.policy_error
        return {"PolicyStatus": {"IsPublic": self.policy_public}}

    def get_bucket_acl(self, Bucket):
        if self.acl_error:
            raise self.acl_error
        grants = []
        if self.public_acl:
            grants.append({
                "Grantee": {"Type": "Group", "URI": PUBLIC_GROUP},
                "Permission": "READ",
            })
        return {"Grants": grants}


class S3ControlStub:
    def __init__(self, account_bpa=None):
        self.account_bpa = account_bpa

    def get_public_access_block(self, AccountId):
        if isinstance(self.account_bpa, Exception):
            raise self.account_bpa
        return {"PublicAccessBlockConfiguration": self.account_bpa or {}}


class SessionStub:
    def __init__(self, account_bpa=None, bucket_bpa=None, **s3_kwargs):
        self.s3 = S3Stub(bucket_bpa=bucket_bpa, **s3_kwargs)
        self.s3control = S3ControlStub(account_bpa)

    def client(self, service):
        return {
            "s3": self.s3,
            "s3control": self.s3control,
            "sts": Identity(),
        }[service]


def scan(**kwargs):
    return S3Scanner(session=SessionStub(**kwargs)).scan()


def test_effective_flag_has_enabled_disabled_and_unknown_states():
    assert S3Scanner.effective_flag("RestrictPublicBuckets", ALL_BPA_FLAGS, None) == "enabled"
    assert S3Scanner.effective_flag("RestrictPublicBuckets", {}, {}) == "disabled"
    assert S3Scanner.effective_flag("RestrictPublicBuckets", None, {}) == "unknown"
    assert S3Scanner.effective_flag("RestrictPublicBuckets", {}, None) == "unknown"


def test_account_access_denied_does_not_confirm_public_policy_or_acl():
    result = scan(
        account_bpa=aws_error("AccessDenied", "GetAccountPublicAccessBlock"),
        bucket_bpa={},
    )
    checks = {finding["check"] for finding in result["findings"]}
    assert "PUBLIC_BUCKET_POLICY" not in checks
    assert "PUBLIC_BUCKET_ACL" not in checks
    assert "PUBLIC_BUCKET_POLICY_PROTECTION_UNKNOWN" in checks
    assert "PUBLIC_BUCKET_ACL_PROTECTION_UNKNOWN" in checks
    assert next(f for f in result["findings"] if f["check"] == "PUBLIC_BUCKET_POLICY_PROTECTION_UNKNOWN")["severity"] == "INFO"
    account_errors = [e for e in result["errors"] if e["operation"] == "GetAccountPublicAccessBlock"]
    assert len(account_errors) == 1
    assert account_errors[0]["scope"] == "account"
    assert account_errors[0]["error"] == "AccessDenied"
    assert result["successfully_inspected_buckets"] == 0


def test_bucket_access_denied_does_not_confirm_public_policy_or_acl():
    result = scan(
        account_bpa={},
        bucket_bpa=aws_error("AccessDenied", "GetPublicAccessBlock"),
    )
    checks = {finding["check"] for finding in result["findings"]}
    assert "PUBLIC_BUCKET_POLICY" not in checks
    assert "PUBLIC_BUCKET_ACL" not in checks
    assert "PUBLIC_BUCKET_POLICY_PROTECTION_UNKNOWN" in checks
    assert "PUBLIC_BUCKET_ACL_PROTECTION_UNKNOWN" in checks
    bucket_errors = [e for e in result["errors"] if e["operation"] == "GetPublicAccessBlock"]
    assert len(bucket_errors) == 1
    assert bucket_errors[0]["scope"] == "bucket"
    assert bucket_errors[0]["resource"] == "review-bucket"
    assert result["successfully_inspected_buckets"] == 0


def test_unknown_flags_are_not_misreported_as_disabled():
    scanner = S3Scanner(session=SessionStub(
        account_bpa=aws_error("AccessDenied", "GetAccountPublicAccessBlock"),
        bucket_bpa={},
        policy_public=False,
        public_acl=False,
    ))
    scanner.findings, scanner.errors = [], []
    scanner.check_block_public_access("review-bucket", None, {})
    finding = next(f for f in scanner.findings if f["check"] == "BLOCK_PUBLIC_ACCESS_CONFIGURATION_UNKNOWN")
    states = finding["evidence"]["effective_protection_flags"]
    assert set(states.values()) == {"unknown"}
    assert finding["evidence"]["disabled_flags"] == []
    assert finding["evidence"]["unknown_flags"] == list(states)


def test_account_and_bucket_access_denied_are_recorded_separately():
    result = scan(
        account_bpa=aws_error("AccessDenied", "GetAccountPublicAccessBlock"),
        bucket_bpa=aws_error("AccessDenied", "GetPublicAccessBlock"),
    )
    failures = [e for e in result["errors"] if e["error"] == "AccessDenied"]
    assert {(e["scope"], e["operation"]) for e in failures} == {
        ("account", "GetAccountPublicAccessBlock"),
        ("bucket", "GetPublicAccessBlock"),
    }


def test_account_error_is_preserved_when_list_buckets_later_fails():
    result = scan(
        account_bpa=aws_error("AccessDenied", "GetAccountPublicAccessBlock"),
        bucket_bpa={},
        list_error=aws_error("ServiceUnavailable", "ListBuckets"),
    )
    operations = [error["operation"] for error in result["errors"]]
    assert operations == ["GetAccountPublicAccessBlock", "ListBuckets"]
    assert result["discovered_buckets"] == 0
    assert result["attempted_buckets"] == 0
    assert result["successfully_inspected_buckets"] == 0


def test_missing_configuration_is_known_disabled_not_unknown():
    result = scan(account_bpa={}, bucket_bpa={}, policy_public=True, public_acl=True)
    checks = {finding["check"] for finding in result["findings"]}
    assert "PUBLIC_BUCKET_POLICY" in checks
    assert "PUBLIC_BUCKET_ACL" in checks
    assert "PUBLIC_BUCKET_POLICY_PROTECTION_UNKNOWN" not in checks
    assert "PUBLIC_BUCKET_ACL_PROTECTION_UNKNOWN" not in checks
    assert result["successfully_inspected_buckets"] == 1


def test_rule_metadata_preserves_low_acl_context():
    finding = {
        "check": "PUBLIC_BUCKET_ACL",
        "severity": "LOW",
        "recommendation": "Remove residual ACL grants after confirming they are ignored.",
    }
    original_recommendation = finding["recommendation"]
    attach_rule_metadata(finding)
    assert finding["rule_id"] == "S3-02"
    assert finding["severity"] == "LOW"
    assert finding["recommendation"] == original_recommendation


def test_rule_metadata_preserves_medium_policy_context():
    finding = {
        "check": "PUBLIC_BUCKET_POLICY",
        "severity": "MEDIUM",
        "recommendation": "Review the public policy; RestrictPublicBuckets is active.",
    }
    original_recommendation = finding["recommendation"]
    attach_rule_metadata(finding)
    assert finding["rule_id"] == "S3-01"
    assert finding["severity"] == "MEDIUM"
    assert finding["recommendation"] == original_recommendation


def test_rule_metadata_still_supplies_missing_defaults():
    finding = {"check": "EBS_VOLUME_UNENCRYPTED"}
    attach_rule_metadata(finding)
    assert finding["severity"] == "MEDIUM"
    assert finding["recommendation"]
    assert finding["rule_id"] == "ENC-02"


def test_evaluation_requires_exact_resource_id_not_substring_match():
    ground_truth = [{
        "resource_type": "ec2_security_group", "resource_id": "sg-1",
        "rule_id": "EC2-01", "expected": "FAIL",
    }]
    findings = [{
        "resource_type": "ec2_security_group", "resource_id": "sg-10",
        "rule_id": "EC2-01",
    }]
    tp, fp, fn, tn, detail, unlabelled = evaluate(ground_truth, findings)
    assert (tp, fp, fn, tn) == (0, 0, 1, 0)
    assert len(unlabelled) == 1


def test_evaluation_requires_exact_resource_type_and_rule():
    ground_truth = [{
        "resource_type": "iam_user", "resource_id": "admin-user",
        "rule_id": "IAM-03", "expected": "FAIL",
    }]
    wrong_type = [{
        "resource_type": "s3_bucket", "resource_id": "admin-user",
        "rule_id": "IAM-03",
    }]
    tp, fp, fn, tn, _, _ = evaluate(ground_truth, wrong_type)
    assert (tp, fp, fn, tn) == (0, 0, 1, 0)


@pytest.mark.parametrize("bad_expected", ["", "MAYBE", "TRUE", "N/A"])
def test_evaluation_rejects_invalid_expected_labels(bad_expected):
    ground_truth = [{
        "resource_type": "s3_bucket", "resource_id": "bucket-a",
        "rule_id": "S3-01", "expected": bad_expected,
    }]
    with pytest.raises(ValueError, match="expected must be PASS or FAIL"):
        evaluate(ground_truth, [])


@pytest.mark.parametrize("field", ["resource_type", "resource_id", "rule_id"])
def test_evaluation_rejects_empty_identity_fields(field):
    row = {
        "resource_type": "s3_bucket", "resource_id": "bucket-a",
        "rule_id": "S3-01", "expected": "PASS",
    }
    row[field] = "  "
    with pytest.raises(ValueError, match="must not be empty"):
        evaluate([row], [])


def test_evaluation_rejects_duplicate_ground_truth_records():
    row = {
        "resource_type": "s3_bucket", "resource_id": "bucket-a",
        "rule_id": "S3-01", "expected": "PASS",
    }
    with pytest.raises(ValueError, match="duplicate record"):
        evaluate([row, dict(row, expected="FAIL")], [])


def test_evaluation_rejects_findings_missing_explicit_identity():
    gt = [{
        "resource_type": "s3_bucket", "resource_id": "bucket-a",
        "rule_id": "S3-01", "expected": "FAIL",
    }]
    with pytest.raises(ValueError, match="missing required field"):
        evaluate(gt, [{"resource_id": "bucket-a", "rule_id": "S3-01"}])


def test_evaluation_csv_loader_and_export_schema_are_compatible(tmp_path):
    csv_text = findings_to_csv({"findings": [{
        "service": "EC2", "resource": "sg-0123", "check": "INTERNET_EXPOSED_SSH",
        "severity": "HIGH", "title": "SSH open", "description": "test",
        "recommendation": "restrict ingress",
    }]})
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert rows[0]["resource_type"] == "ec2_security_group"
    assert rows[0]["resource_id"] == "sg-0123"
    path = tmp_path / "findings.csv"
    path.write_text(csv_text, encoding="utf-8")
    loaded = load(path)
    gt = [{
        "resource_type": "ec2_security_group", "resource_id": "sg-0123",
        "rule_id": "EC2-01", "expected": "FAIL",
    }]
    assert evaluate(gt, loaded)[0:4] == (1, 0, 0, 0)


def test_ground_truth_template_contains_only_implemented_rule_checks():
    from pathlib import Path

    sample_path = Path(__file__).resolve().parents[1] / "evaluation" / "ground_truth_template.csv"
    records = load(sample_path)
    normalized = [row["rule_id"] for row in records]
    assert set(normalized) == {
        "S3-01", "S3-02", "S3-03", "EC2-01", "EC2-02",
        "IAM-02", "IAM-03", "ENC-02", "LOG-02",
    }
    assert "LOG-01" not in normalized  # no CloudTrail no-trail evaluation rule mapping
    assert "ENC-01" not in normalized  # EBS encryption-by-default is not scanned
    # The evaluation template itself must pass all strict CSV validation.
    from evaluation.evaluate import validate_ground_truth
    assert len(validate_ground_truth(records)) == len(records)


def test_no_such_public_access_block_is_a_known_disabled_configuration():
    result = scan(
        account_bpa=aws_error(
            "NoSuchPublicAccessBlockConfiguration", "GetAccountPublicAccessBlock"
        ),
        bucket_bpa=aws_error(
            "NoSuchPublicAccessBlockConfiguration", "GetPublicAccessBlock"
        ),
    )
    checks = {finding["check"] for finding in result["findings"]}
    assert "PUBLIC_BUCKET_POLICY" in checks
    assert "PUBLIC_BUCKET_ACL" in checks
    assert "PUBLIC_BUCKET_POLICY_PROTECTION_UNKNOWN" not in checks
    assert "PUBLIC_BUCKET_ACL_PROTECTION_UNKNOWN" not in checks
    assert result["errors"] == []
    assert result["successfully_inspected_buckets"] == 1


def test_bucket_can_be_fully_inspected_when_bucket_settings_resolve_unknown_account_flags():
    result = scan(
        account_bpa=aws_error("AccessDenied", "GetAccountPublicAccessBlock"),
        bucket_bpa=ALL_BPA_FLAGS,
        policy_public=False,
        public_acl=False,
    )
    assert result["discovered_buckets"] == 1
    assert result["attempted_buckets"] == 1
    assert result["successfully_inspected_buckets"] == 1
    # Account-level failure remains visible independently of bucket-level success.
    assert result["errors"][0]["scope"] == "account"


def test_unmapped_findings_remain_unlabelled_instead_of_invalidating_evaluation():
    gt = [{
        "resource_type": "s3_bucket", "resource_id": "expected-bucket",
        "rule_id": "S3-01", "expected": "FAIL",
    }]
    findings = [{
        "resource_type": "rds_db_instance", "resource_id": "public-db",
        "rule_id": "",  # RDS_PUBLICLY_ACCESSIBLE is not in the P1 rule mapping.
    }]
    tp, fp, fn, tn, detail, unlabelled = evaluate(gt, findings)
    assert (tp, fp, fn, tn) == (0, 0, 1, 0)
    assert unlabelled == findings


@pytest.mark.parametrize("flag", [
    "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets",
])
def test_each_bpa_flag_uses_or_effective_state_across_account_and_bucket(flag):
    account_enabled = {flag: True}
    bucket_disabled = {flag: False}
    account_disabled = {flag: False}
    bucket_enabled = {flag: True}
    assert S3Scanner.effective_flag(flag, account_enabled, bucket_disabled) == "enabled"
    assert S3Scanner.effective_flag(flag, account_disabled, bucket_enabled) == "enabled"
    assert S3Scanner.effective_flag(flag, account_disabled, bucket_disabled) == "disabled"
    assert S3Scanner.effective_flag(flag, None, bucket_disabled) == "unknown"


@pytest.mark.parametrize(
    "payload",
    [
        "=1+1",
        "+SUM(A1:A2)",
        "-1+2",
        "@SUM(A1:A2)",
        "  =1+1",
        "\t=1+1",
        "\r=1+1",
        "\n=1+1",
        "\ufeff=1+1",
    ],
)
def test_csv_export_neutralizes_spreadsheet_formula_prefixes(payload):
    csv_text = findings_to_csv({
        "findings": [{
            "service": "S3",
            "resource": payload,
            "title": payload,
            "description": payload,
            "recommendation": payload,
        }]
    })

    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(rows) == 1

    row = rows[0]
    expected = "'" + payload

    assert row["title"] == expected
    assert row["description"] == expected
    assert row["recommendation"] == expected

    # Resource IDs are stripped by the existing export logic.
    assert row["resource_id"] == "'" + payload.strip()
    assert row["resource"] == "'" + payload.strip()


def test_csv_export_preserves_normal_text():
    csv_text = findings_to_csv({
        "findings": [{
            "service": "S3",
            "resource": "demo-bucket",
            "title": "Public bucket detected",
            "description": "Bucket access needs review.",
            "recommendation": "Restrict public access.",
        }]
    })

    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert rows[0]["title"] == "Public bucket detected"
    assert rows[0]["description"] == "Bucket access needs review."
    assert rows[0]["recommendation"] == "Restrict public access."