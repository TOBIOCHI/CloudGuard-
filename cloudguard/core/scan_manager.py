"""Run CloudGuard scanners and aggregate their results."""

from datetime import datetime, timezone
from time import perf_counter

from cloudguard.core.rules import attach_rule_metadata
from cloudguard.scanners.s3_scanner import S3Scanner
from cloudguard.scanners.iam_scanner import IAMScanner
from cloudguard.scanners.ec2_scanner import EC2Scanner
from cloudguard.scanners.ebs_scanner import EBSScanner
from cloudguard.scanners.rds_scanner import RDSScanner
from cloudguard.scanners.cloudtrail_scanner import CloudTrailScanner


class ScanManager:
    """Run six read-only scanners and track their execution status."""

    def __init__(self, session=None):
        self.session = session

        self.scanners = [
            ("S3", S3Scanner),
            ("IAM", IAMScanner),
            ("EC2", EC2Scanner),
            ("EBS", EBSScanner),
            ("RDS", RDSScanner),
            ("CloudTrail", CloudTrailScanner),
        ]

    def run_all(self):
        started_at = datetime.now(timezone.utc)
        wall_start = perf_counter()

        service_results = {}
        all_findings = []
        all_errors = []

        completed_scanners = 0
        successful_scanners = 0
        partial_scanners = 0
        failed_scanners = 0

        for service_name, scanner_class in self.scanners:
            print(f"[CloudGuard] Scanning {service_name}...")

            module_start = perf_counter()

            try:
                # Reuse the verified AWS session when supplied.
                if self.session is None:
                    scanner = scanner_class()
                else:
                    scanner = scanner_class(session=self.session)

                result = scanner.scan()

                # Validate the scanner output contract.
                if not isinstance(result, dict):
                    raise ValueError(
                        "Scanner returned no valid result dictionary."
                    )

                if "findings" not in result or "errors" not in result:
                    raise ValueError(
                        "Scanner result must contain findings and errors."
                    )

                findings = result["findings"]
                errors = result["errors"]

                if not isinstance(findings, list):
                    raise ValueError(
                        "Scanner findings must be a list."
                    )

                if not isinstance(errors, list):
                    raise ValueError(
                        "Scanner errors must be a list."
                    )

                if not all(isinstance(item, dict) for item in findings):
                    raise ValueError(
                        "Scanner returned a malformed finding."
                    )

                # Attach rule metadata before aggregation.
                for finding in findings:
                    attach_rule_metadata(finding)

                # Normalize errors for the combined scan report.
                normalized_errors = []

                for error in errors:
                    if isinstance(error, dict):
                        error_entry = dict(error)
                        error_entry["service"] = service_name
                    else:
                        error_entry = {
                            "service": service_name,
                            "message": str(error),
                        }

                    normalized_errors.append(error_entry)

                all_findings.extend(findings)
                all_errors.extend(normalized_errors)

                result["service"] = service_name
                result["status"] = (
                    "partial" if errors else "success"
                )

                result["duration_seconds"] = round(
                    perf_counter() - module_start, 4
                )

                service_results[service_name] = result

                # A valid result counts as completed.
                completed_scanners += 1

                if errors:
                    partial_scanners += 1
                else:
                    successful_scanners += 1

                print(
                    f"[CloudGuard] {service_name}: "
                    f"{result['status']}, "
                    f"{len(findings)} finding(s), "
                    f"{len(errors)} error(s), "
                    f"{result['duration_seconds']} s"
                )

            except Exception as error:
                duration = round(
                    perf_counter() - module_start, 4
                )

                failed_scanners += 1

                error_result = {
                    "service": service_name,
                    "operation": "scanner_execution",
                    "message": str(error),
                }

                all_errors.append(error_result)

                service_results[service_name] = {
                    "service": service_name,
                    "status": "failed",
                    "findings": [],
                    "errors": [error_result],
                    "duration_seconds": duration,
                }

                print(
                    f"[CloudGuard] {service_name} failed "
                    f"after {duration} s: {error}"
                )

        completed_at = datetime.now(timezone.utc)

        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0,
        }

        for finding in all_findings:
            severity = str(
                finding.get("severity", "INFO")
            ).upper()

            severity_counts[severity] = (
                severity_counts.get(severity, 0) + 1
            )

        return {
            "tool": "CloudGuard",
            "scan_started_at": started_at.isoformat(),
            "scan_completed_at": completed_at.isoformat(),
            "duration_seconds": round(
                perf_counter() - wall_start, 4
            ),
            "summary": {
                "total_scanners": len(self.scanners),
                "completed_scanners": completed_scanners,
                "successful_scanners": successful_scanners,
                "partial_scanners": partial_scanners,
                "failed_scanners": failed_scanners,
                "total_findings": len(all_findings),
                "total_errors": len(all_errors),
                "severity_counts": severity_counts,
            },
            "services": service_results,
            "findings": all_findings,
            "errors": all_errors,
        }