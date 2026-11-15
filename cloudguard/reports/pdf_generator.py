
"""
CloudGuard PDF Report Generator

Creates professional PDF security assessment reports from
CloudGuard scan results.

This module is read-only: it does not modify AWS resources.
"""

from pathlib import Path
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    KeepTogether,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REPORT_DIR = PROJECT_ROOT / "data" / "reports"

NAVY = colors.HexColor("#101B35")
BLUE = colors.HexColor("#3157A4")
LIGHT_BLUE = colors.HexColor("#EAF0FC")
LIGHT_GREY = colors.HexColor("#F1F3F6")
DARK_GREY = colors.HexColor("#394150")
WHITE = colors.white

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#991B1B"),
    "HIGH": colors.HexColor("#DC2626"),
    "MEDIUM": colors.HexColor("#D97706"),
    "LOW": colors.HexColor("#2563EB"),
    "INFO": colors.HexColor("#64748B"),
}

SCANNER_STATUS_LABELS = {
    "success": "Successful",
    "partial": "Partial",
    "failed": "Failed",
    "unknown": "Unknown",
}


class PDFReportGenerator:
    """Generate PDF reports from CloudGuard scan results."""

    def __init__(self, output_dir=None):
        self.output_dir = Path(output_dir or DEFAULT_REPORT_DIR)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.styles = self._build_styles()

    def _build_styles(self):
        styles = getSampleStyleSheet()

        styles.add(ParagraphStyle(
            name="ReportTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=25,
            leading=31,
            textColor=NAVY,
            alignment=TA_CENTER,
            spaceAfter=8,
        ))

        styles.add(ParagraphStyle(
            name="ReportSubtitle",
            parent=styles["Normal"],
            fontSize=11,
            leading=16,
            textColor=DARK_GREY,
            alignment=TA_CENTER,
        ))

        styles.add(ParagraphStyle(
            name="SectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=NAVY,
            spaceBefore=12,
            spaceAfter=8,
            keepWithNext=True,
        ))

        styles.add(ParagraphStyle(
            name="SubHeading",
            parent=styles["Heading3"],
            fontSize=10,
            leading=13,
            textColor=BLUE,
            spaceBefore=7,
            spaceAfter=4,
            keepWithNext=True,
        ))

        styles.add(ParagraphStyle(
            name="BodySmall",
            parent=styles["BodyText"],
            fontSize=8,
            leading=11,
            textColor=DARK_GREY,
        ))

        styles.add(ParagraphStyle(
            name="BodyTiny",
            parent=styles["BodyText"],
            fontSize=7,
            leading=9,
            textColor=DARK_GREY,
        ))

        styles.add(ParagraphStyle(
            name="FindingTitle",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=NAVY,
        ))

        styles.add(ParagraphStyle(
            name="WhiteText",
            parent=styles["Normal"],
            textColor=WHITE,
            fontName="Helvetica-Bold",
            fontSize=9,
        ))

        return styles

    @staticmethod
    def _safe(value):
        """Escape dynamic text before inserting it into a Paragraph."""

        if value is None:
            return "N/A"

        if isinstance(value, (dict, list, tuple)):
            value = str(value)

        return escape(str(value))

    def _paragraph(self, value, style="BodySmall"):
        return Paragraph(
            self._safe(value),
            self.styles[style]
        )

    def _header_footer(self, canvas, document):
        canvas.saveState()

        width, height = A4

        # Header
        canvas.setFillColor(NAVY)
        canvas.rect(
            0,
            height - 13 * mm,
            width,
            13 * mm,
            fill=1,
            stroke=0
        )

        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 9)

        canvas.drawString(
            18 * mm,
            height - 8.5 * mm,
            "CLOUDGUARD"
        )

        canvas.setFont("Helvetica", 7)

        canvas.drawRightString(
            width - 18 * mm,
            height - 8.5 * mm,
            "CLOUD SECURITY ASSESSMENT"
        )

        # Footer
        canvas.setStrokeColor(
            colors.HexColor("#D7DCE5")
        )

        canvas.line(
            18 * mm,
            15 * mm,
            width - 18 * mm,
            15 * mm
        )

        canvas.setFillColor(DARK_GREY)
        canvas.setFont("Helvetica", 7)

        canvas.drawString(
            18 * mm,
            10 * mm,
            "CloudGuard | Read-only AWS security assessment"
        )

        canvas.drawRightString(
            width - 18 * mm,
            10 * mm,
            f"Page {document.page}"
        )

        canvas.restoreState()

    def _section(self, title):
        return Paragraph(
            title,
            self.styles["SectionHeading"]
        )

    def _make_table(self, rows, widths, header=True):
        table = Table(
            rows,
            colWidths=widths,
            repeatRows=1 if header else 0,
            hAlign="LEFT",
        )

        commands = [
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.35,
                colors.HexColor("#D7DCE5")
            ),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]

        if header:
            commands.extend([
                ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ])

        if len(rows) > 1:
            for row_index in range(
                1 if header else 0,
                len(rows)
            ):
                if row_index % 2 == 0:
                    commands.append((
                        "BACKGROUND",
                        (0, row_index),
                        (-1, row_index),
                        LIGHT_GREY,
                    ))

        table.setStyle(TableStyle(commands))

        return table

    # --------------------------------------------------
    # COVER PAGE
    # --------------------------------------------------

    def _add_cover(self, story, results, scan_id):
        story.append(Spacer(1, 35 * mm))

        story.append(Paragraph(
            "CLOUDGUARD",
            self.styles["ReportTitle"]
        ))

        story.append(Paragraph(
            "Cloud Misconfiguration Detection Tool",
            self.styles["ReportSubtitle"]
        ))

        story.append(Spacer(1, 20 * mm))

        story.append(Paragraph(
            "AWS SECURITY ASSESSMENT REPORT",
            ParagraphStyle(
                "CoverLabel",
                parent=self.styles["ReportSubtitle"],
                fontName="Helvetica-Bold",
                fontSize=12,
                textColor=BLUE,
            )
        ))

        story.append(Spacer(1, 15 * mm))

        summary = results.get("summary", {})

        cover_data = [
            [
                self._paragraph("Report Reference"),
                self._paragraph(scan_id)
            ],
            [
                self._paragraph("Scan Started"),
                self._paragraph(
                    results.get("scan_started_at", "N/A")
                ),
            ],
            [
                self._paragraph("Scan Completed"),
                self._paragraph(
                    results.get("scan_completed_at", "N/A")
                ),
            ],
            [
                self._paragraph("Duration"),
                self._paragraph(
                    f"{summary.get('duration_seconds', results.get('duration_seconds', 0))} seconds"
                ),
            ],
            [
                self._paragraph("Assessment Type"),
                self._paragraph(
                    "Read-only AWS security assessment"
                ),
            ],
        ]

        story.append(self._make_table(
            [
                [
                    self._paragraph(
                        "REPORT INFORMATION",
                        "WhiteText"
                    ),
                    self._paragraph("VALUE", "WhiteText"),
                ]
            ] + cover_data,
            [55 * mm, 105 * mm],
        ))

        story.append(Spacer(1, 25 * mm))

        story.append(Paragraph(
            "CONFIDENTIALITY NOTICE",
            self.styles["SubHeading"]
        ))

        story.append(self._paragraph(
            "This report contains security assessment information. "
            "Share it only with authorized individuals responsible "
            "for the assessed AWS environment."
        ))

        story.append(PageBreak())

    # --------------------------------------------------
    # EXECUTIVE SUMMARY
    # --------------------------------------------------

    def _add_executive_summary(self, story, results):
        summary = results.get("summary", {})
        severity = summary.get("severity_counts", {})
        services = results.get("services", {})

        if not isinstance(services, dict):
            services = {}

        # Count statuses from individual service results.
        # Used as a fallback when summary counts are unavailable.
        statuses = [
            str(service.get("status", "unknown")).lower()
            for service in services.values()
            if isinstance(service, dict)
        ]

        derived = {
            "successful_scanners": statuses.count("success"),
            "partial_scanners": statuses.count("partial"),
            "failed_scanners": statuses.count("failed"),
        }

        total_scanners = (
            summary.get("total_scanners") or len(services)
        )

        successful = summary.get(
            "successful_scanners",
            derived["successful_scanners"]
        )

        partial = summary.get(
            "partial_scanners",
            derived["partial_scanners"]
        )

        failed = summary.get(
            "failed_scanners",
            derived["failed_scanners"]
        )

        unknown = summary.get(
            "unknown_scanners",
            max(
                0,
                total_scanners - successful - partial - failed
            )
        )

        story.append(self._section("1. Executive Summary"))

        story.append(self._paragraph(
            "CloudGuard performed a read-only assessment of selected "
            "AWS services to identify potential cloud configuration "
            "weaknesses. Findings are based on the resources and API "
            "responses available to the configured audit identity."
        ))

        story.append(Spacer(1, 8))

        # General scan metrics.
        metrics = [
            [
                self._paragraph(
                    "Total Findings",
                    "WhiteText"
                ),
                self._paragraph(
                    "Scanners Completed",
                    "WhiteText"
                ),
                self._paragraph(
                    "Scan Errors",
                    "WhiteText"
                ),
            ],
            [
                self._paragraph(
                    summary.get(
                        "total_findings",
                        len(results.get("findings", []))
                    )
                ),
                self._paragraph(
                    summary.get("completed_scanners", 0)
                ),
                self._paragraph(
                    summary.get(
                        "total_errors",
                        len(results.get("errors", []))
                    )
                ),
            ],
        ]

        story.append(self._make_table(
            metrics,
            [53 * mm, 53 * mm, 53 * mm],
        ))

        story.append(Spacer(1, 10))

        # Scanner outcome breakdown.
        status_rows = [
            [
                self._paragraph("Successful", "WhiteText"),
                self._paragraph("Partial", "WhiteText"),
                self._paragraph("Failed", "WhiteText"),
                self._paragraph("Unknown", "WhiteText"),
            ],
            [
                self._paragraph(successful),
                self._paragraph(partial),
                self._paragraph(failed),
                self._paragraph(unknown),
            ],
        ]

        story.append(self._make_table(
            status_rows,
            [40 * mm, 40 * mm, 40 * mm, 40 * mm],
        ))

        story.append(Spacer(1, 12))

        # Severity breakdown.
        story.append(self._section("2. Severity Breakdown"))

        severity_rows = [[
            self._paragraph("Severity", "WhiteText"),
            self._paragraph("Count", "WhiteText"),
        ]]

        for level in [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO"
        ]:
            severity_rows.append([
                self._paragraph(level),
                self._paragraph(severity.get(level, 0)),
            ])

        story.append(self._make_table(
            severity_rows,
            [80 * mm, 80 * mm],
        ))

    # --------------------------------------------------
    # AWS SERVICE RESULTS
    # --------------------------------------------------

    def _add_service_results(self, story, results):
        """Add service results using recorded scanner statuses."""

        story.append(
            self._section("3. AWS Service Scan Results")
        )

        services = results.get("services", {})

        if not isinstance(services, dict) or not services:
            story.append(self._paragraph(
                "No service result details were recorded."
            ))
            return

        count_fields = {
            "S3": "scanned_buckets",
            "IAM": "scanned_users",
            "EC2": "scanned_security_groups",
            "EBS": "scanned_volumes",
            "RDS": "scanned_instances",
            "CloudTrail": "scanned_trails",
        }

        rows = [[
            self._paragraph("Service", "WhiteText"),
            self._paragraph("Resources", "WhiteText"),
            self._paragraph("Findings", "WhiteText"),
            self._paragraph("Errors", "WhiteText"),
            self._paragraph("Status", "WhiteText"),
        ]]

        for name, service in services.items():
            if not isinstance(service, dict):
                continue

            resource_count = service.get(
                count_fields.get(name, ""),
                "N/A"
            )

            errors = service.get("errors") or []
            findings = service.get("findings") or []

            # Do not infer success from an empty error list.
            # Legacy scans without a saved status remain Unknown.
            status = str(
                service.get("status") or "unknown"
            ).strip().lower()

            display_status = SCANNER_STATUS_LABELS.get(
                status,
                "Unknown"
            )

            rows.append([
                self._paragraph(name),
                self._paragraph(resource_count),
                self._paragraph(len(findings)),
                self._paragraph(len(errors)),
                self._paragraph(display_status),
            ])

        story.append(self._make_table(
            rows,
            [32 * mm, 30 * mm, 28 * mm, 25 * mm, 45 * mm],
        ))

    # --------------------------------------------------
    # DETAILED SECURITY FINDINGS
    # --------------------------------------------------

    def _add_findings(self, story, results):
        story.append(
            self._section("4. Detailed Security Findings")
        )

        findings = results.get("findings", [])

        if not findings:
            story.append(self._paragraph(
                "No findings were returned by the completed checks. "
                "This does not establish that the entire AWS account "
                "or every AWS region is secure. Review scanner "
                "statuses and errors before interpreting the result."
            ))
            return

        for index, finding in enumerate(findings, start=1):
            if not isinstance(finding, dict):
                continue

            level = str(
                finding.get("severity", "INFO")
            ).upper()

            severity_color = SEVERITY_COLORS.get(
                level,
                DARK_GREY
            )

            heading = Paragraph(
                f'<font color="{severity_color.hexval()}">'
                f'<b>{index}. [{self._safe(level)}]</b></font> '
                f'<b>{self._safe(finding.get("title", "Untitled finding"))}</b>',
                self.styles["FindingTitle"],
            )

            details = [
                heading,
                Spacer(1, 4),

                self._paragraph(
                    f"Service: {finding.get('service', 'N/A')} | "
                    f"Resource: {finding.get('resource', finding.get('resource_id', 'N/A'))}"
                ),

                self._paragraph(
                    f"Check: {finding.get('check_name', finding.get('check', 'N/A'))}"
                ),

                self._paragraph(
                    f"Description: {finding.get('description', 'No description provided.')}"
                ),

                self._paragraph(
                    f"Recommendation: {finding.get('recommendation', 'Review this configuration.')}"
                ),
            ]

            evidence = finding.get("evidence")

            if evidence:
                details.append(
                    self._paragraph(
                        f"Evidence: {evidence}"
                    )
                )

            details.append(Spacer(1, 8))

            story.append(
                KeepTogether(details)
            )

    # --------------------------------------------------
    # SCAN ERRORS
    # --------------------------------------------------

    def _add_errors(self, story, results):
        errors = results.get("errors", [])

        story.append(
            self._section("5. Scan Errors")
        )

        if not errors:
            story.append(self._paragraph(
                "No scan-level errors were recorded."
            ))
            return

        rows = [[
            self._paragraph("Service", "WhiteText"),
            self._paragraph("Operation", "WhiteText"),
            self._paragraph("Error", "WhiteText"),
        ]]

        for error in errors:
            if not isinstance(error, dict):
                continue

            rows.append([
                self._paragraph(
                    error.get("service", "Unknown")
                ),
                self._paragraph(
                    error.get("operation", "Unknown")
                ),
                self._paragraph(
                    error.get(
                        "error",
                        error.get("message", "Unknown error")
                    )
                ),
            ])

        story.append(self._make_table(
            rows,
            [35 * mm, 45 * mm, 80 * mm],
        ))

    # --------------------------------------------------
    # ASSESSMENT LIMITATIONS
    # --------------------------------------------------

    def _add_limitations(self, story):
        story.append(
            self._section("6. Assessment Scope and Limitations")
        )

        limitations = [
            (
                "CloudGuard performs read-only checks and does not "
                "automatically remediate findings."
            ),
            (
                "Results are limited to resources visible to the "
                "configured AWS identity and the regions actually scanned."
            ),
            (
                "A resource count of zero means no resources were "
                "returned by that check; it does not prove the service is secure."
            ),
            (
                "Security group rules alone do not establish actual "
                "network reachability."
            ),
            (
                "An RDS PubliclyAccessible flag does not by itself "
                "prove internet accessibility."
            ),
            (
                "IAM policy analysis uses simplified checks and is "
                "not a complete AWS effective-permissions evaluation."
            ),
            (
                "A missing customer-managed CloudTrail trail in the "
                "selected region does not mean CloudTrail Event History "
                "is disabled or that no trail exists in another region."
            ),
            (
                "Findings should be manually validated before "
                "corrective action is taken."
            ),
        ]

        for item in limitations:
            story.append(Paragraph(
                f"&bull; {self._safe(item)}",
                self.styles["BodySmall"]
            ))

            story.append(Spacer(1, 4))

        story.append(Spacer(1, 10))

        story.append(self._paragraph(
            "This report is an assessment aid, not a guarantee of "
            "security or compliance. Review findings with the AWS "
            "account owner before making changes."
        ))

    # --------------------------------------------------
    # PDF GENERATION
    # --------------------------------------------------

    def generate_report(self, results, scan_id=None, filename=None):
        """
        Generate a PDF report.

        Args:
            results: CloudGuard scan result dictionary.
            scan_id: Optional saved database scan ID.
            filename: Optional output filename.

        Returns:
            pathlib.Path: Generated PDF path.
        """

        if not isinstance(results, dict):
            raise TypeError(
                "Scan results must be a dictionary."
            )

        if filename is None:
            timestamp = datetime.now(
                timezone.utc
            ).strftime("%Y%m%d_%H%M%S")

            reference = (
                f"scan_{scan_id}"
                if scan_id is not None
                else "scan"
            )

            filename = (
                f"cloudguard_{reference}_{timestamp}.pdf"
            )

        filename = Path(filename)

        if filename.suffix.lower() != ".pdf":
            filename = filename.with_suffix(".pdf")

        output_path = self.output_dir / filename.name

        document = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=18 * mm,
            leftMargin=18 * mm,
            topMargin=21 * mm,
            bottomMargin=21 * mm,
            title="CloudGuard Security Assessment Report",
            author="CloudGuard",
            subject="AWS Cloud Misconfiguration Assessment",
        )

        story = []

        self._add_cover(
            story,
            results,
            scan_id if scan_id is not None else "Not saved"
        )

        self._add_executive_summary(
            story,
            results
        )

        self._add_service_results(
            story,
            results
        )

        self._add_findings(
            story,
            results
        )

        self._add_errors(
            story,
            results
        )

        self._add_limitations(story)

        document.build(
            story,
            onFirstPage=self._header_footer,
            onLaterPages=self._header_footer,
        )

        if (
            not output_path.exists()
            or output_path.stat().st_size == 0
        ):
            raise RuntimeError(
                "PDF report generation failed."
            )

        return output_path
