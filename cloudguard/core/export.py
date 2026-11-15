
"""Export helpers shared by Flask routes and offline tests."""

import csv
import io

from cloudguard.core.rules import CHECK_TO_RULE


RESOURCE_TYPE_BY_SERVICE = {
    "S3": "s3_bucket",
    "EC2": "ec2_security_group",
    "IAM": "iam_user",
    "EBS": "ebs_volume",
    "RDS": "rds_db_instance",
    "CLOUDTRAIL": "cloudtrail_trail",
}


def _safe_csv_cell(value):
    """
    Neutralize values that spreadsheet applications might execute as formulas.

    Protects formula prefixes even when preceded by whitespace or a BOM.
    Also protects leading tab, carriage return and newline characters.
    """
    if value is None:
        return ""

    text = str(value)

    for char in text:
        if char in ("\t", "\r", "\n", "=", "+", "-", "@"):
            return "'" + text

        if char.isspace() or char == "\ufeff":
            continue

        # First meaningful character is not dangerous.
        break

    return text


def findings_to_csv(details):
    """Return a UTF-8 CSV string compatible with evaluation/evaluate.py."""

    output = io.StringIO(newline="")
    writer = csv.writer(output)

    # These headers are static and do not contain user-controlled values.
    writer.writerow([
        "rule_id",
        "resource_type",
        "resource_id",
        "resource",
        "service",
        "check",
        "severity",
        "category",
        "title",
        "description",
        "recommendation",
    ])

    for finding in details.get("findings", []):
        check = finding.get("check_name") or finding.get("check") or ""

        rule_id = (
            finding.get("rule_id")
            or CHECK_TO_RULE.get(check, "")
        )

        service = str(
            finding.get("service", "")
        ).strip().upper()

        resource_id = str(
            finding.get("resource", "")
        ).strip()

        resource_type = (
            finding.get("resource_type")
            or RESOURCE_TYPE_BY_SERVICE.get(service, "")
        )

        row = [
            rule_id,
            resource_type,
            resource_id,
            resource_id,
            service,
            check,
            finding.get("severity", ""),
            finding.get("category", ""),
            finding.get("title", ""),
            finding.get("description", ""),
            finding.get("recommendation", ""),
        ]

        # Sanitize every dynamic cell before writing the CSV row.
        writer.writerow([
            _safe_csv_cell(value)
            for value in row
        ])

    return output.getvalue()