
# CloudGuard V2

CloudGuard V2 is a read-only AWS cloud misconfiguration detection tool built with Python, Flask, Boto3, SQLite, and ReportLab.

It scans selected AWS services for common security misconfigurations, records findings, classifies risk severity, and generates reports through a local web dashboard.

CloudGuard is designed for security auditing and educational evaluation. It does not modify AWS resources.

## 1. Features

- Read-only AWS security scanning.
- Amazon S3 security configuration checks.
- Amazon EC2 security group checks.
- Amazon EBS encryption checks.
- Amazon RDS public accessibility checks.
- AWS IAM security configuration checks.
- AWS CloudTrail configuration checks.
- Risk severity classification.
- Scan history stored in SQLite.
- Scanner execution status tracking.
- CSV export with formula-injection protection.
- PDF security reports.
- Local Flask web dashboard.
- Automated tests using pytest and Moto.

## 2. Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| Web framework | Flask |
| AWS integration | Boto3 |
| Database | SQLite |
| PDF reports | ReportLab |
| Testing | pytest |
| AWS simulation | Moto |
| Frontend | HTML, CSS, JavaScript |

## 3. Project Structure

```text
CloudGuard-V2/
|
|-- app.py
|-- config.py
|-- run_cloudguard.py
|-- run_s3_scan.py
|-- aws_identity_diagnostic.py
|-- aws_permissions_diagnostic.py
|-- install_windows.bat
|-- start_cloudguard.bat
|
|-- cloudguard/
|   |-- core/
|   |   |-- aws_connection.py
|   |   |-- export.py
|   |   |-- rules.py
|   |   `-- scan_manager.py
|   |
|   |-- database/
|   |   `-- db_manager.py
|   |
|   |-- reports/
|   |   `-- pdf_generator.py
|   |
|   `-- scanners/
|       |-- cloudtrail_scanner.py
|       |-- ebs_scanner.py
|       |-- ec2_scanner.py
|       |-- iam_scanner.py
|       |-- rds_scanner.py
|       `-- s3_scanner.py
|
|-- evaluation/
|   |-- evaluate.py
|   `-- ground_truth_template.csv
|
|-- static/
|   |-- css/
|   |   `-- style.css
|   `-- js/
|       `-- dashboard.js
|
|-- templates/
|   |-- 404.html
|   |-- base.html
|   |-- index.html
|   `-- scan_details.html
|
|-- tests/
|   |-- test_app.py
|   |-- test_cloudtrail_scanner.py
|   |-- test_database.py
|   |-- test_ebs_scanner.py
|   |-- test_ec2_scanner.py
|   |-- test_iam_scanner.py
|   |-- test_moto_smoke.py
|   |-- test_p1_regressions.py
|   |-- test_rds_scanner.py
|   |-- test_s3_scanner.py
|   |-- test_scan_manager_status.py
|   `-- test_v2_integration.py
|
|-- requirements.txt
|-- requirements-dev.txt
|-- .env.example
|-- .gitignore
|-- README.md
`-- CHANGES.md
```

Generated databases, reports, environment files, and virtual environments are excluded from source control.

## 4. Requirements

- Windows 10/11, 64-bit, or a compatible Linux/macOS system.
- Python 3.11 or newer.
- Internet connection for initial dependency installation.
- AWS CLI v2 for AWS profile configuration.
- An AWS account with an appropriately restricted read-only audit identity for live scanning.

## 5. Windows Quick Installation

### Step 1: Download CloudGuard

Download and extract the CloudGuard V2 release ZIP.

Open the extracted `CloudGuard-V2` folder.

### Step 2: Install CloudGuard

Double-click:

`install_windows.bat`

The installer:

- Checks the installed Python version.
- Creates a project-specific Python virtual environment.
- Installs the required Python dependencies.
- Creates `.env` from `.env.example` if it does not already exist.
- Generates a random Flask secret key if the example placeholder is still present.
- Checks whether AWS CLI is installed.

The installer does not configure AWS credentials or initiate an AWS scan.

### Step 3: Start CloudGuard

Double-click:

`start_cloudguard.bat`

The local dashboard will be available at:

`http://127.0.0.1:5000/`

Keep the terminal window open while using CloudGuard.

Press `Ctrl + C` in the terminal to stop the application.

### Step 4: Configure AWS

Install AWS CLI v2 and configure your own restricted audit profile.

Do not share your AWS credentials or `.env` file.

## 6. Manual Installation

If you prefer installing CloudGuard manually, clone the repository:

```powershell
git clone https://github.com/TOBIOCHI/CloudGuard-.git
```

Enter the project directory:

```powershell
cd CloudGuard-
```

Create a virtual environment:

```powershell
py -3 -m venv .venv
```

Activate it:

```powershell
.\.venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

Create your local environment file:

```powershell
Copy-Item .env.example .env
```

Generate a Flask secret key and configure it in `.env` before running the application.

## 7. Environment Configuration

CloudGuard uses environment variables for local configuration.

The `.env.example` file contains:

```ini
AWS_PROFILE=cloudguard-audit
AWS_REGION=eu-north-1
FLASK_SECRET_KEY=replace_this_with_a_long_random_secret_key
```

Update the AWS profile and region to match your own configuration.

Replace the Flask secret placeholder with a long, randomly generated secret.

Never commit `.env` to GitHub or share it publicly.

## 8. AWS Configuration

CloudGuard uses Boto3 to communicate with AWS.

Configure an AWS CLI profile using an appropriately restricted read-only identity.

Example:

```powershell
aws configure --profile cloudguard-audit
```

Check the configured identity:

```powershell
aws sts get-caller-identity --profile cloudguard-audit
```

CloudGuard does not require permission to create, modify, or delete AWS resources.

Use only an AWS identity with the minimum permissions needed for the intended audit.

## 9. Running CloudGuard

Start the application:

```powershell
python app.py
```

The Flask application runs locally at:

`http://127.0.0.1:5000/`

The application uses:

- Localhost binding.
- Port 5000.
- Debug mode disabled.

The dashboard is intended for local access.

## 10. Automated Testing

CloudGuard includes automated tests for scanners, database operations, application routes, scan management, and integration behavior.

Install development dependencies:

```powershell
python -m pip install -r requirements-dev.txt
```

Run the complete test suite:

```powershell
python -m pytest -q -rs
```

Latest locally verified result:

**106 tests passed.**

The automated AWS tests use mocks and Moto rather than modifying real AWS resources.

## 11. Scanner Status Tracking

CloudGuard tracks scanner execution outcomes.

| Status | Meaning |
|---|---|
| Successful | Scanner completed without reported errors. |
| Partial | Scanner returned results but also reported errors. |
| Failed | Scanner failed, raised an exception, or returned an invalid result. |
| Unknown | Status cannot be reliably established from the available historical data. |

The application stores service-level results and reconstructs status information from persisted scan records.

A successful scan does not necessarily mean that every AWS resource is secure.

## 12. Risk Severity Classification

CloudGuard classifies detected findings by risk severity.

The classification helps users prioritize potential security issues.

Severity classifications are based on the detection rules implemented by individual scanners. They should not be interpreted as a complete assessment of an AWS environment.

## 13. Chapter 4 Evaluation

CloudGuard includes an evaluation module and a ground-truth template.

The evaluation tools are intended to support comparison between scanner findings and manually established expected results.

The evaluation dataset should be reviewed and populated with verified ground-truth labels before drawing conclusions about detection accuracy.

## 14. Security Considerations and Limitations

CloudGuard is a security auditing aid, not a complete AWS security assessment platform.

Important limitations:

- IAM policy checks are simplified configuration checks, not a complete effective-permissions evaluator.
- IAM MFA findings may concern console users and do not necessarily indicate the absence of MFA for every programmatic identity.
- EC2 security group rules do not independently prove that a resource is reachable from the internet.
- An RDS instance marked publicly accessible is not necessarily reachable from the public internet; network configuration also matters.
- EBS encryption checks identify encryption configuration but do not assess every aspect of key management.
- CloudTrail coverage depends on the regions and trail configurations examined.
- Zero findings does not prove that an AWS environment is secure.
- Results depend on the permissions and visibility of the configured AWS audit identity.

Always review findings manually before making security decisions.

## 15. Project Status

CloudGuard V2 has completed its current local validation phase.

Verified locally:

- Application and dashboard startup.
- Dependency installation.
- SQLite operations.
- Scanner status tracking.
- CSV export protections.
- PDF report generation.
- Automated test suite: 106 passing tests.
- Fresh Windows installer test.
- Local dashboard accessibility.

A fresh Windows installation and local dashboard startup were tested successfully in an isolated test copy.

Live AWS scanning has not been claimed as part of this validation.

## 16. Disclaimer

CloudGuard is provided for educational, research, and authorized security auditing purposes.

Only scan AWS accounts and resources for which you have explicit authorization.

The developers are not responsible for unauthorized use or decisions made solely on the basis of scanner output.
