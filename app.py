
import os
import re
import secrets
import webbrowser
from threading import Timer
from pathlib import Path

from dotenv import load_dotenv

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    abort,
    send_file,
    Response,
    session as flask_session,
)

from flask_wtf.csrf import CSRFProtect

from cloudguard.database.db_manager import DatabaseManager
from cloudguard.core.scan_manager import ScanManager
from cloudguard.reports.pdf_generator import PDFReportGenerator
from cloudguard.core.aws_connection import (
    connect_aws_profile,
    list_aws_profiles,
    reconnect_verified_profile,
)


# --------------------------------------------------
# PROJECT CONFIGURATION
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent

# Load local environment variables.
load_dotenv(PROJECT_ROOT / ".env")

app = Flask(
    __name__,
    template_folder=str(PROJECT_ROOT / "templates"),
    static_folder=str(PROJECT_ROOT / "static"),
)

# --------------------------------------------------
# SECURITY CONFIGURATION
# --------------------------------------------------

app.config.update(
    SECRET_KEY=(
        os.getenv("FLASK_SECRET_KEY")
        or secrets.token_hex(32)
    ),

    # Session cookie security.
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",

    # Keep False for local HTTP development.
    # Set FLASK_COOKIE_SECURE=true when deployed over HTTPS.
    SESSION_COOKIE_SECURE=(
        os.getenv("FLASK_COOKIE_SECURE", "false")
        .strip()
        .lower()
        in {"1", "true", "yes", "on"}
    ),

    # CSRF protection.
    WTF_CSRF_ENABLED=True,
    WTF_CSRF_CHECK_DEFAULT=True,
    WTF_CSRF_TIME_LIMIT=3600,
)

# Protect all POST, PUT, PATCH and DELETE requests.
csrf = CSRFProtect(app)

database = DatabaseManager()


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/")
def index():
    """Display the latest scan and dashboard overview."""

    scan_history = database.get_scan_history(limit=20)

    latest_scan = scan_history[0] if scan_history else None

    latest_details = None
    findings = []
    services = {}

    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }

    if latest_scan:

        latest_details = database.get_scan_details(
            latest_scan["id"]
        )

        if latest_details:
            findings = latest_details.get("findings", [])
            services = latest_details.get("services", {})

        severity_counts.update(
            latest_scan.get("severity_counts", {})
        )

    # --------------------------------------------------
    # OPTIONAL FINDING FILTERS
    # --------------------------------------------------

    selected_severity = request.args.get(
        "severity", ""
    ).upper()

    selected_service = request.args.get(
        "service", ""
    ).upper()

    if selected_severity in severity_counts:

        findings = [
            finding for finding in findings
            if finding.get("severity", "").upper()
            == selected_severity
        ]

    else:
        selected_severity = ""

    if selected_service:

        findings = [
            finding for finding in findings
            if finding.get("service", "").upper()
            == selected_service
        ]

    # --------------------------------------------------
    # RENDER DASHBOARD
    # --------------------------------------------------

    return render_template(
        "index.html",
        latest_scan=latest_scan,
        latest_details=latest_details,
        scan_history=scan_history,
        findings=findings,
        services=services,
        severity_counts=severity_counts,
        selected_severity=selected_severity,
        selected_service=selected_service,

        # AWS account connection information.
        aws_profiles=list_aws_profiles(),

        aws_connection={
            "email": flask_session.get(
                "aws_account_email", ""
            ),
            "profile": flask_session.get(
                "aws_profile", ""
            ),
            "region": flask_session.get(
                "aws_region", "eu-north-1"
            ),
            "account_id": flask_session.get(
                "aws_account_id", ""
            ),
            "arn": flask_session.get(
                "aws_identity_arn", ""
            ),
            "connected": bool(
                flask_session.get("aws_account_id")
            ),
        }
    )


# --------------------------------------------------
# INDIVIDUAL SCAN DETAILS
# --------------------------------------------------

@app.route("/scans/<int:scan_id>")
def scan_details(scan_id):
    """Display the complete details of one saved scan."""

    details = database.get_scan_details(scan_id)

    if details is None:
        abort(404)

    return render_template(
        "scan_details.html",
        details=details,
        scan=details["scan"],
    )


# --------------------------------------------------
# AWS ACCOUNT CONNECTION
# --------------------------------------------------

@app.route("/connect-aws", methods=["POST"])
def connect_aws():
    """Verify an AWS CLI profile and remember its non-secret identity."""

    email = request.form.get(
        "aws_email", ""
    ).strip().lower()

    profile = request.form.get(
        "aws_profile", ""
    ).strip()

    region = request.form.get(
        "aws_region", ""
    ).strip()

    # The email is an account label, not an authentication credential.
    if not re.fullmatch(
        r"[^@\s]+@[^@\s]+\.[^@\s]+",
        email
    ):
        flash(
            "Enter a valid AWS account email address.",
            "danger"
        )
        return redirect(url_for("index"))

    try:

        _, identity = connect_aws_profile(
            profile,
            region
        )

        # Only store non-secret account information.
        flask_session["aws_account_email"] = email
        flask_session["aws_profile"] = profile
        flask_session["aws_region"] = region
        flask_session["aws_account_id"] = identity["account_id"]
        flask_session["aws_identity_arn"] = identity["arn"]

        flash(
            f"AWS identity verified. Connected account: "
            f"{identity['account_id']}",
            "success"
        )

    except (ValueError, ConnectionError) as error:

        # Remove any previous connection if verification fails.
        for key in (
            "aws_account_email",
            "aws_profile",
            "aws_region",
            "aws_account_id",
            "aws_identity_arn",
        ):
            flask_session.pop(key, None)

        flash(str(error), "danger")

    return redirect(url_for("index"))


# --------------------------------------------------
# DISCONNECT AWS ACCOUNT
# --------------------------------------------------

@app.route("/disconnect-aws", methods=["POST"])
def disconnect_aws():
    """Remove the current browser's saved AWS connection."""

    for key in (
        "aws_account_email",
        "aws_profile",
        "aws_region",
        "aws_account_id",
        "aws_identity_arn",
    ):
        flask_session.pop(key, None)

    flash(
        "AWS account disconnected.",
        "info"
    )

    return redirect(url_for("index"))


# --------------------------------------------------
# DOWNLOAD PDF REPORT
# --------------------------------------------------

@app.route("/scans/<int:scan_id>/report")
def download_scan_report(scan_id):
    """Generate and download a PDF for a saved scan."""

    details = database.get_scan_details(scan_id)

    if details is None:
        abort(404)

    scan = details["scan"]

    # Reconstruct the structure expected by PDFReportGenerator.
    results = {
        "tool": "CloudGuard",
        "scan_started_at": scan.get("scan_started_at"),
        "scan_completed_at": scan.get("scan_completed_at"),
        "duration_seconds": scan.get("duration_seconds", 0),

        "summary": {
            "total_scanners": scan.get("total_scanners", 0),
            "completed_scanners": scan.get("completed_scanners", 0),
            "successful_scanners": scan.get("successful_scanners", 0),
            "partial_scanners": scan.get("partial_scanners", 0),
            "failed_scanners": scan.get("failed_scanners", 0),
            "unknown_scanners": scan.get("unknown_scanners", 0),
            "total_findings": scan.get("total_findings", 0),
            "total_errors": scan.get("total_errors", 0),
            "severity_counts": scan.get("severity_counts", {}),
        },

        "services": details.get("services", {}),
        "findings": details.get("findings", []),
        "errors": details.get("errors", []),
    }

    try:

        generator = PDFReportGenerator()

        report_path = generator.generate_report(
            results,
            scan_id=scan_id
        )

        report_path = Path(report_path)

        if not report_path.is_file():
            raise FileNotFoundError(
                "The PDF generator did not create the report file."
            )

        return send_file(
            report_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=report_path.name,
        )

    except Exception:

        app.logger.exception(
            "Failed to generate PDF report for scan %s",
            scan_id
        )

        flash(
            "The PDF report could not be generated. "
            "Check the application console for details.",
            "danger"
        )

        return redirect(
            url_for(
                "scan_details",
                scan_id=scan_id
            )
        )


# --------------------------------------------------
# DOWNLOAD CSV FOR CHAPTER 4 EVALUATION
# --------------------------------------------------

@app.route("/scans/<int:scan_id>/export.csv")
def export_scan_csv(scan_id):
    """Export findings in a format accepted by evaluation/evaluate.py."""

    details = database.get_scan_details(scan_id)

    if details is None:
        abort(404)

    from cloudguard.core.export import findings_to_csv

    csv_text = findings_to_csv(details)

    return Response(
        csv_text,
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition":
                f"attachment; filename=cloudguard_scan_{scan_id}.csv"
        },
    )


# --------------------------------------------------
# RUN NEW AWS SCAN
# --------------------------------------------------

@app.route("/run-scan", methods=["POST"])
def run_scan():
    """Run scanners only against the previously verified AWS account."""

    required_keys = (
        "aws_account_email",
        "aws_profile",
        "aws_region",
        "aws_account_id",
    )

    if not all(
        flask_session.get(key)
        for key in required_keys
    ):
        flash(
            "Connect and verify an AWS account before scanning.",
            "warning"
        )
        return redirect(url_for("index"))

    try:
        # Re-authenticate and verify the previously selected AWS account.
        aws_session, identity = reconnect_verified_profile(
            profile_name=flask_session["aws_profile"],
            region_name=flask_session["aws_region"],
            expected_account_id=flask_session["aws_account_id"],
        )

        # Run all six scanners using the verified AWS session.
        manager = ScanManager(session=aws_session)
        results = manager.run_all()

        # Record the assessed AWS account.
        results["aws_account"] = {
            "account_id": identity["account_id"],
            "identity_arn": identity["arn"],
            "region": flask_session["aws_region"],
        }

        summary = results.get("summary", {})

        total = summary.get("total_scanners", 0)
        successful = summary.get("successful_scanners", 0)
        partial = summary.get("partial_scanners", 0)
        failed = summary.get("failed_scanners", 0)
        unknown = summary.get("unknown_scanners", 0)

        # Save the scan even when some scanners fail.
        scan_id = database.save_scan(results)

        if (
            total > 0
            and successful == total
            and partial == 0
            and failed == 0
            and unknown == 0
        ):
            flash(
                f"Scan #{scan_id} completed successfully. "
                f"All {total} scanners succeeded.",
                "success"
            )

        elif (
            total > 0
            and failed == total
            and successful == 0
            and partial == 0
            and unknown == 0
        ):
            flash(
                f"Scan #{scan_id} was saved, but all "
                f"{total} scanners failed. Review the scan errors.",
                "danger"
            )

        else:
            flash(
                f"Scan #{scan_id} was saved with incomplete results. "
                f"Successful: {successful}, "
                f"Partial: {partial}, "
                f"Failed: {failed}, "
                f"Unknown: {unknown}.",
                "warning"
            )

        return redirect(
            url_for("scan_details", scan_id=scan_id)
        )

    except (ValueError, ConnectionError) as error:

        # Require a fresh connection if identity verification fails.
        for key in required_keys + ("aws_identity_arn",):
            flask_session.pop(key, None)

        flash(
            f"AWS connection verification failed: {error}",
            "danger"
        )

    except Exception:

        app.logger.exception("CloudGuard scan failed")

        flash(
            "The scan failed. Check the application console.",
            "danger"
        )

    return redirect(url_for("index"))


# --------------------------------------------------
# APPLICATION HEALTH CHECK
# --------------------------------------------------

@app.route("/health")
def health():
    """Check whether the application and database are available."""

    try:

        history = database.get_scan_history(limit=1)

        return {
            "application": "CloudGuard",
            "status": "running",
            "database": "connected",
            "saved_scans": len(history),
        }

    except Exception:

        app.logger.exception(
            "Database health check failed"
        )

        return {
            "application": "CloudGuard",
            "status": "error",
            "database": "disconnected",
        }, 500


# --------------------------------------------------
# 404 ERROR HANDLER
# --------------------------------------------------

@app.errorhandler(404)
def not_found(error):
    """Display the custom 404 page."""

    return render_template("404.html"), 404


# --------------------------------------------------
# START APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    dashboard_url = "http://127.0.0.1:5000/"

    print("\n========== CLOUDGUARD DASHBOARD ==========")
    print(f"Dashboard: {dashboard_url}")
    print("Press CTRL+C to stop the server.\n")

    # Open the dashboard in the default browser.
    Timer(
        1.0,
        lambda: webbrowser.open(
            dashboard_url,
            new=2
        )
    ).start()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
