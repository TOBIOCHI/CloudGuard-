# CloudGuard — AWS Cloud Misconfiguration Detection Tool

CloudGuard is a Python-based AWS security auditing tool designed to identify common cloud configuration weaknesses through read-only AWS API calls.

It combines modular security scanners, a central scan manager, risk classification, SQLite persistence, a Flask web dashboard, and downloadable PDF and CSV reports.

**Project status:** V2 implementation
**Automated tests:** 106 passing
**Cloud provider:** Amazon Web Services (AWS)

## 1. Features

CloudGuard currently includes six AWS security scanners:

| AWS service | Security checks |
|---|---|
| Amazon S3 | Public bucket policies, public ACLs, and Block Public Access configuration |
| AWS IAM | Users without MFA and potentially over-permissive policies |
| Amazon EC2 | Security groups exposing SSH, RDP, and other unrestricted inbound traffic |
| Amazon EBS | Unencrypted EBS volumes |
| Amazon RDS | Publicly accessible database configuration |
| AWS CloudTrail | Trail existence, logging status, multi-region configuration, and log-file validation |

Additional features:

- Sequential execution of security scanners.
- Central security rule catalogue.
- Severity classification: CRITICAL, HIGH, MEDIUM, LOW, and INFO.
- Per-scanner execution timing and status tracking.
- Successful, partial, failed, and unknown scanner status reporting.
- SQLite database for scan history and findings.
- Flask web dashboard and individual scan details.
- PDF security assessment reports.
- Findings CSV export with rule and resource identifiers.
- Application health endpoint.
- Automated regression and integration tests.

CloudGuard is designed for detection and reporting. It does not automatically modify AWS resources or perform remediation.

## 2. Technology Stack

- Python
- Boto3
- AWS CLI
- Flask
- Flask-WTF
- SQLite
- ReportLab
- HTML, CSS, JavaScript
- pytest
- Moto for simulated AWS testing

## 3. Project Structure

```text
CloudGuard-V2/
│
├── app.py
├── config.py
├── run_cloudguard.py
├── run_s3_scan.py
├── aws_identity_diagnostic.py
├── aws_permissions_diagnostic.py
│
├── cloudguard/
│   ├── core/
│   │   ├── aws_connection.py
│   │   ├── export.py
│   │   ├── rules.py
│   │   └── scan_manager.py
│   │
│   ├── database/
│   │   └── db_manager.py
│   │
│   ├── reports/
│   │   └── pdf_generator.py
│   │
│   └── scanners/
│       ├── cloudtrail_scanner.py
│       ├── ebs_scanner.py
│       ├── ec2_scanner.py
│       ├── iam_scanner.py
│       ├── rds_scanner.py
│       └── s3_scanner.py
│
├── evaluation/
│   ├── evaluate.py
│   └── ground_truth_template.csv
│
├── static/
│   ├── css/
│   │   └── style.css
│   └── js/
│       └── dashboard.js
│
├── templates/
│   ├── 404.html
│   ├── base.html
│   ├── index.html
│   └── scan_details.html
│
├── tests/
│   ├── test_app.py
│   ├── test_cloudtrail_scanner.py
│   ├── test_database.py
│   ├── test_ebs_scanner.py
│   ├── test_ec2_scanner.py
│   ├── test_iam_scanner.py
│   ├── test_moto_smoke.py
│   ├── test_p1_regressions.py
│   ├── test_rds_scanner.py
│   ├── test_s3_scanner.py
│   ├── test_scan_manager_status.py
│   └── test_v2_integration.py
│
├── requirements.txt
├── requirements-dev.txt
├── .env.example
├── .gitignore
├── README.md
└── CHANGES.md
```

Generated databases, reports, environment files, and virtual environments are excluded from source control.

## 4. Requirements

- Python 3
- pip
- AWS CLI v2 (for AWS CLI profile configuration)
- An AWS account with appropriate read-only audit permissions

The current development environment was tested with Python 3.14.

## 5. Installation

Clone the repository:

```powershell
git clone https://github.com/TOBIOCHI/CloudGuard-.git
cd CloudGuard-
```

Create a virtual environment:

```powershell
py -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install application dependencies:

```powershell
python -m pip install -r requirements.txt
```

For development and testing:

```powershell
python -m pip install -r requirements-dev.txt
```

## 6. Environment Configuration

Create a private environment file:

```powershell
Copy-Item .env.example .env
```

Generate a secure Flask secret key:

```powershell
python -c "import secrets; print(secrets.token_hex(32))"
```

Add the generated value to `.env`:

```text
FLASK_SECRET_KEY=your_generated_secret_key
```

Keep `.env` private. Never upload it to GitHub or share its contents.

## 7. AWS Configuration

CloudGuard uses Boto3 to communicate with AWS.

Install AWS CLI v2 and configure a dedicated audit profile:

```powershell
aws configure --profile cloudguard-audit
```

Enter your AWS credentials locally when prompted. Do not paste credentials into source code or commit them to GitHub.

The recommended approach is to use an IAM identity with the AWS-managed `SecurityAudit` policy, together with any additional read permissions required by the implemented checks.

Verify the configured identity:

```powershell
aws sts get-caller-identity --profile cloudguard-audit
```

Always confirm the AWS account, region, and permissions before scanning.

## 8. Running CloudGuard

Run the complete scan:

```powershell
python run_cloudguard.py
```

The scan executes the six security scanners and gathers findings, severity summaries, scanner results, and errors.

The web application also provides scan execution through its dashboard.

## 9. Running the Web Dashboard

Start the Flask application:

```powershell
python app.py
```

Open the dashboard:

```text
http://127.0.0.1:5000
```

The dashboard provides:

- Latest scan overview.
- Severity summaries.
- AWS service results.
- Individual security findings.
- Scan history.
- Scanner execution statuses.
- Individual scan details.
- PDF report downloads.
- Findings CSV exports.

Health endpoint:

```text
http://127.0.0.1:5000/health
```

Stop the application using `CTRL+C`.

## 10. Automated Testing

Install development dependencies:

```powershell
python -m pip install -r requirements-dev.txt
```

Run the complete test suite:

```powershell
python -m pytest -q -rs
```

**Latest verified test result:**

```text
106 passed in 59.23s
```

The tests cover scanner logic, simulated AWS responses, database operations, dashboard routes, scan status handling, exports, security regressions, and integration behaviour.

The test suite uses simulated AWS responses and does not require a live AWS scan.

The scripts `aws_identity_diagnostic.py` and `aws_permissions_diagnostic.py` are manual diagnostics that contact AWS. Do not run them during offline testing.

## 11. Scanner Status Tracking

CloudGuard distinguishes between:

- **Successful:** The scanner completed without reported errors.
- **Partial:** The scanner returned results but also reported errors.
- **Failed:** The scanner failed or returned an invalid result.
- **Unknown:** Status cannot be established for older scan records.

These statuses are reflected in scan summaries, service results, history, and PDF reports.

## 12. Risk Severity Classification

| Severity | Meaning |
|---|---|
| CRITICAL | Potentially severe security exposure |
| HIGH | Significant security weakness |
| MEDIUM | Configuration weakness requiring attention |
| LOW | Lower-impact security improvement |
| INFO | Informational observation |

Severity represents the scanner's assessment of a detected configuration. It does not guarantee exploitability or actual compromise.

## 13. Chapter 4 Evaluation

The `evaluation/` directory contains tools for evaluating scanner results against a controlled ground-truth dataset.

Copy the template:

```powershell
Copy-Item evaluation/ground_truth_template.csv evaluation/ground_truth.csv
```

Replace the sample entries with the controlled resources used in your experiment.

Expected labels are:

- `PASS`
- `FAIL`

After conducting an authorised scan, export the findings CSV from the scan details page.

Run the evaluation:

```powershell
python evaluation/evaluate.py evaluation/ground_truth.csv cloudguard_scan_1.csv
```

Evaluation matches records using exact, case-sensitive resource type, resource identifier, and rule ID.

Invalid labels, empty identity fields, and duplicate ground-truth records are rejected. Findings without mapped rule IDs remain visible but are not counted as matched evaluation results.

Only use controlled resources and ground-truth labels that have been independently verified.

## 14. Security Considerations and Limitations

CloudGuard is an educational and research-oriented prototype. Its results should be reviewed and validated before operational decisions are made.

Known limitations include:

- IAM policy analysis uses simplified wildcard and administrator-policy checks. It is not a complete AWS effective-permissions evaluator.
- IAM users without MFA may be programmatic identities that do not use console sign-in.
- EC2 security-group rules alone do not prove that a resource is reachable from the internet.
- An RDS `PubliclyAccessible` setting does not independently prove internet reachability.
- EBS checks currently focus on encryption status of existing volumes.
- CloudTrail findings are based on trails returned in the selected region. They do not establish that AWS Event History is unavailable.
- Some AWS resources and services are region-specific.
- Zero findings do not prove that an AWS account is completely secure.

CloudGuard performs read-only security checks and does not automatically remediate detected issues.

Only scan AWS accounts and resources for which you have explicit authorisation.

## 15. Project Status

Current V2 implementation:

- Six modular AWS security scanners.
- Central scan manager.
- Central rule catalogue.
- Improved S3 Block Public Access evaluation.
- Scanner execution timing and status tracking.
- SQLite persistence.
- Flask dashboard.
- PDF and CSV report generation.
- Health monitoring endpoint.
- Environment-based Flask secret configuration.
- Automated test suite: 106 passing tests.

## 16. Disclaimer

CloudGuard is an educational and research-oriented cloud security auditing project.

It is provided for learning, experimentation, and authorised security assessment. The tool is not a replacement for a comprehensive professional cloud security assessment.

Always obtain explicit permission before scanning AWS accounts or resources.
