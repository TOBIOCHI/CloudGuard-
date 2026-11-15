"""Regression tests for scanner execution status reporting."""

from cloudguard.core.scan_manager import ScanManager


def test_scan_manager_distinguishes_success_partial_and_failure():
    class SuccessfulScanner:
        def scan(self):
            return {
                "findings": [],
                "errors": [],
            }

    class PartialScanner:
        def scan(self):
            return {
                "findings": [],
                "errors": [
                    {
                        "operation": "list_resources",
                        "message": "AccessDenied",
                    }
                ],
            }

    class FailedScanner:
        def scan(self):
            return None

    manager = ScanManager()

    manager.scanners = [
        ("Success", SuccessfulScanner),
        ("Partial", PartialScanner),
        ("Failure", FailedScanner),
    ]

    result = manager.run_all()
    summary = result["summary"]

    assert summary["total_scanners"] == 3
    assert summary["successful_scanners"] == 1
    assert summary["partial_scanners"] == 1
    assert summary["failed_scanners"] == 1

    # Completed means a valid result was returned.
    assert summary["completed_scanners"] == 2

    assert summary["total_errors"] == 2

    assert result["services"]["Success"]["status"] == "success"
    assert result["services"]["Partial"]["status"] == "partial"
    assert result["services"]["Failure"]["status"] == "failed"

    assert (
        summary["successful_scanners"]
        + summary["partial_scanners"]
        + summary["failed_scanners"]
        == summary["total_scanners"]
    )


def test_scan_manager_rejects_malformed_scanner_results():
    class MalformedScanner:
        def scan(self):
            return {
                "findings": [],
                # Missing errors field.
            }

    manager = ScanManager()
    manager.scanners = [("Malformed", MalformedScanner)]

    result = manager.run_all()
    summary = result["summary"]

    assert summary["successful_scanners"] == 0
    assert summary["partial_scanners"] == 0
    assert summary["failed_scanners"] == 1
    assert summary["completed_scanners"] == 0
    assert result["services"]["Malformed"]["status"] == "failed"