"""
CloudGuard - S3 Security Scanner

Read-only checks:
1. Public bucket policies
2. Public bucket ACLs
3. Bucket-level Block Public Access
4. Account-level Block Public Access

Block Public Access is evaluated per setting as enabled, disabled, or
unknown. An inaccessible configuration is never treated as disabled.
"""

import boto3
from botocore.exceptions import ClientError


PUBLIC_GROUPS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}

BPA_FLAGS = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


class S3Scanner:
    def __init__(self, session=None):
        self.session = session or boto3.Session(
            profile_name="cloudguard-audit",
            region_name="eu-north-1",
        )
        self.s3 = self.session.client("s3")
        self.s3control = self.session.client("s3control")
        self.sts = self.session.client("sts")
        self.findings = []
        self.errors = []

    def add_finding(
        self, bucket, check, severity, title, description,
        recommendation, evidence=None,
    ):
        self.findings.append({
            "service": "S3",
            "resource": bucket,
            "check": check,
            "severity": severity,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "evidence": evidence or {},
        })

    @staticmethod
    def error_code(error):
        if isinstance(error, ClientError):
            return error.response.get("Error", {}).get("Code", "UnknownError")
        return type(error).__name__

    def _record_configuration_error(self, resource, scope, operation, error):
        """Keep account and bucket configuration failures independently visible."""
        self.errors.append({
            "resource": resource,
            "scope": scope,
            "operation": operation,
            "error": self.error_code(error),
            "message": str(error),
        })

    def get_account_public_access_block(self, account_id):
        try:
            response = self.s3control.get_public_access_block(AccountId=account_id)
            configuration = response.get("PublicAccessBlockConfiguration")
            # A successful response containing no configuration is treated as
            # an absent configuration (all flags disabled), like NoSuch... .
            return configuration if configuration is not None else {}
        except ClientError as error:
            if self.error_code(error) == "NoSuchPublicAccessBlockConfiguration":
                return {}
            self._record_configuration_error(
                "AWS Account", "account", "GetAccountPublicAccessBlock", error
            )
            return None
        except Exception as error:
            self._record_configuration_error(
                "AWS Account", "account", "GetAccountPublicAccessBlock", error
            )
            return None

    def get_bucket_public_access_block(self, bucket):
        try:
            response = self.s3.get_public_access_block(Bucket=bucket)
            configuration = response.get("PublicAccessBlockConfiguration")
            return configuration if configuration is not None else {}
        except ClientError as error:
            if self.error_code(error) == "NoSuchPublicAccessBlockConfiguration":
                return {}
            self._record_configuration_error(
                bucket, "bucket", "GetPublicAccessBlock", error
            )
            return None
        except Exception as error:
            self._record_configuration_error(
                bucket, "bucket", "GetPublicAccessBlock", error
            )
            return None

    @staticmethod
    def effective_flag(flag, account_block, bucket_block):
        """Return enabled, disabled, or unknown for an account/bucket flag.

        A confirmed True at either level enables the effective control. The
        control is disabled only when both levels were successfully inspected
        and neither enables it. Otherwise its effective state is unknown.
        """
        configurations = (account_block, bucket_block)
        if any(
            configuration is not None and bool(configuration.get(flag, False))
            for configuration in configurations
        ):
            return "enabled"
        if any(configuration is None for configuration in configurations):
            return "unknown"
        return "disabled"

    def _add_unknown_protection_finding(self, bucket, check, title, message, evidence):
        self.add_finding(
            bucket,
            check,
            "INFO",
            title,
            message,
            "Grant the read-only audit role permission to retrieve both account- and bucket-level "
            "S3 Block Public Access settings, then repeat the assessment.",
            evidence,
        )

    def check_bucket_policy(self, bucket, account_block, bucket_block):
        try:
            response = self.s3.get_bucket_policy_status(Bucket=bucket)
            is_public = response.get("PolicyStatus", {}).get("IsPublic", False)
        except ClientError as error:
            if self.error_code(error) == "NoSuchBucketPolicy":
                return
            self.errors.append({
                "resource": bucket,
                "scope": "bucket",
                "operation": "GetBucketPolicyStatus",
                "error": self.error_code(error),
                "message": str(error),
            })
            return
        except Exception as error:
            self.errors.append({
                "resource": bucket,
                "scope": "bucket",
                "operation": "GetBucketPolicyStatus",
                "error": self.error_code(error),
                "message": str(error),
            })
            return

        if not is_public:
            return

        protection_state = self.effective_flag(
            "RestrictPublicBuckets", account_block, bucket_block
        )
        evidence = {
            "is_public": True,
            "restrict_public_buckets_state": protection_state,
        }

        if protection_state == "unknown":
            self._add_unknown_protection_finding(
                bucket,
                "PUBLIC_BUCKET_POLICY_PROTECTION_UNKNOWN",
                "Public bucket policy detected; effective restriction is unknown",
                "AWS identifies this policy as public, but CloudGuard could not determine whether "
                "account- or bucket-level RestrictPublicBuckets neutralises public access. "
                "This is inconclusive and is not classified as confirmed public exposure.",
                evidence,
            )
            return

        if protection_state == "enabled":
            severity = "MEDIUM"
            title = "Public policy detected with access restriction"
            description = (
                "AWS identifies the bucket policy as public, but RestrictPublicBuckets is "
                "enabled at the account or bucket level."
            )
            recommendation = (
                "Review the policy and remove unnecessary public access. Verify effective access restrictions."
            )
        else:
            severity = "HIGH"
            title = "Public bucket policy detected"
            description = (
                "AWS identifies this bucket policy as public, and neither the account nor bucket "
                "configuration enables RestrictPublicBuckets."
            )
            recommendation = (
                "Review the bucket policy and remove unintended public access. Enable appropriate "
                "Block Public Access protections."
            )

        self.add_finding(
            bucket, "PUBLIC_BUCKET_POLICY", severity, title,
            description, recommendation, evidence,
        )

    def check_bucket_acl(self, bucket, account_block, bucket_block):
        try:
            response = self.s3.get_bucket_acl(Bucket=bucket)
        except ClientError as error:
            self.errors.append({
                "resource": bucket,
                "scope": "bucket",
                "operation": "GetBucketAcl",
                "error": self.error_code(error),
                "message": str(error),
            })
            return
        except Exception as error:
            self.errors.append({
                "resource": bucket,
                "scope": "bucket",
                "operation": "GetBucketAcl",
                "error": self.error_code(error),
                "message": str(error),
            })
            return

        public_grants = []
        for grant in response.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI")
            if uri in PUBLIC_GROUPS:
                public_grants.append({
                    "permission": grant.get("Permission"),
                    "group": uri,
                })

        if not public_grants:
            return

        protection_state = self.effective_flag(
            "IgnorePublicAcls", account_block, bucket_block
        )
        evidence = {
            "public_grants": public_grants,
            "ignore_public_acls_state": protection_state,
        }

        if protection_state == "unknown":
            self._add_unknown_protection_finding(
                bucket,
                "PUBLIC_BUCKET_ACL_PROTECTION_UNKNOWN",
                "Public ACL grants detected; effective ACL handling is unknown",
                "The bucket ACL contains public grants, but CloudGuard could not determine whether "
                "account- or bucket-level IgnorePublicAcls prevents them from granting access. "
                "This is inconclusive and is not classified as confirmed public exposure.",
                evidence,
            )
            return

        if protection_state == "enabled":
            severity = "LOW"
            title = "Public ACL grants detected but ignored"
            description = (
                "The bucket ACL contains public grants, but IgnorePublicAcls is enabled at the "
                "account or bucket level."
            )
            recommendation = (
                "Remove unnecessary public ACL grants and prefer bucket policies with Block Public Access."
            )
        else:
            severity = "HIGH"
            title = "Public bucket ACL detected"
            description = (
                "The bucket ACL grants permissions to a public or broadly authenticated AWS group, "
                "and neither account nor bucket configuration enables IgnorePublicAcls."
            )
            recommendation = (
                "Remove unintended public ACL grants and enable IgnorePublicAcls or appropriate "
                "Block Public Access protections."
            )

        self.add_finding(
            bucket, "PUBLIC_BUCKET_ACL", severity, title,
            description, recommendation, evidence,
        )

    def check_block_public_access(self, bucket, account_block, bucket_block):
        states = {
            flag: self.effective_flag(flag, account_block, bucket_block)
            for flag in BPA_FLAGS
        }
        disabled = [flag for flag, state in states.items() if state == "disabled"]
        unknown = [flag for flag, state in states.items() if state == "unknown"]

        if disabled:
            self.add_finding(
                bucket,
                "BLOCK_PUBLIC_ACCESS_DISABLED",
                "MEDIUM",
                "Some Block Public Access protections are not enabled",
                "The following effective Block Public Access controls are confirmed disabled: "
                + ", ".join(disabled) + "."
                + (" The following controls could not be determined: " + ", ".join(unknown) + "." if unknown else ""),
                "Enable all four S3 Block Public Access settings at account level, or apply the "
                "required settings to this bucket after reviewing documented exceptions.",
                {
                    "effective_protection_flags": states,
                    "disabled_flags": disabled,
                    "unknown_flags": unknown,
                },
            )

        if unknown:
            self._add_unknown_protection_finding(
                bucket,
                "BLOCK_PUBLIC_ACCESS_CONFIGURATION_UNKNOWN",
                "Some Block Public Access settings could not be determined",
                "CloudGuard could not retrieve all account- and bucket-level configuration needed "
                "to determine effective protection for: " + ", ".join(unknown) + ".",
                {
                    "effective_protection_flags": states,
                    "disabled_flags": disabled,
                    "unknown_flags": unknown,
                },
            )
        return states

    def scan(self):
        self.findings = []
        self.errors = []
        attempted_buckets = 0
        successfully_inspected_buckets = 0

        try:
            identity = self.sts.get_caller_identity()
            account_id = identity["Account"]
        except Exception as error:
            self.errors.append({
                "resource": "AWS Account",
                "scope": "account",
                "operation": "GetCallerIdentity",
                "error": self.error_code(error),
                "message": str(error),
            })
            return self._scan_result(0, attempted_buckets, successfully_inspected_buckets)

        account_block = self.get_account_public_access_block(account_id)

        try:
            buckets = self.s3.list_buckets().get("Buckets", [])
        except Exception as error:
            # Preserve account-level errors recorded before ListBuckets failed.
            self.errors.append({
                "resource": "AWS Account",
                "scope": "account",
                "operation": "ListBuckets",
                "error": self.error_code(error),
                "message": str(error),
            })
            return self._scan_result(0, attempted_buckets, successfully_inspected_buckets)

        discovered_buckets = len(buckets)
        for item in buckets:
            bucket = item.get("Name")
            if not bucket:
                self.errors.append({
                    "resource": "AWS Account",
                    "scope": "account",
                    "operation": "InspectBucket",
                    "error": "InvalidBucketRecord",
                    "message": "ListBuckets returned a bucket record without a Name.",
                })
                continue

            attempted_buckets += 1
            errors_before_inspection = len(self.errors)
            try:
                bucket_block = self.get_bucket_public_access_block(bucket)
                self.check_bucket_policy(bucket, account_block, bucket_block)
                self.check_bucket_acl(bucket, account_block, bucket_block)
                effective_states = self.check_block_public_access(
                    bucket, account_block, bucket_block
                )
            except Exception as error:
                self.errors.append({
                    "resource": bucket,
                    "scope": "bucket",
                    "operation": "InspectBucket",
                    "error": self.error_code(error),
                    "message": str(error),
                })
                continue

            # A complete inspection requires successful retrieval of shared
            # account configuration and all per-bucket data used by these checks.
            if (
                len(self.errors) == errors_before_inspection
                and all(state != "unknown" for state in effective_states.values())
            ):
                successfully_inspected_buckets += 1

        return self._scan_result(
            discovered_buckets, attempted_buckets, successfully_inspected_buckets
        )

    def _scan_result(self, discovered, attempted, successful):
        return {
            "service": "S3",
            "discovered_buckets": discovered,
            "attempted_buckets": attempted,
            "successfully_inspected_buckets": successful,
            # Retain the historical key; it now means fully inspected buckets.
            "scanned_buckets": successful,
            "findings": self.findings,
            "errors": self.errors,
        }


if __name__ == "__main__":
    scanner = S3Scanner()
    results = scanner.scan()
    print("\n========== CLOUDGUARD S3 SCAN ==========")
    print("Buckets discovered:", results["discovered_buckets"])
    print("Buckets attempted:", results["attempted_buckets"])
    print("Buckets successfully inspected:", results["successfully_inspected_buckets"])
    print("Findings:", len(results["findings"]))
    print("Errors:", len(results["errors"]))
    for finding in results["findings"]:
        print("\n----------------------------------------")
        print("Bucket:", finding["resource"])
        print("Severity:", finding["severity"])
        print("Issue:", finding["title"])
        print("Recommendation:", finding["recommendation"])
    for error in results["errors"]:
        print("\n[SCAN ERROR]", error)
    print("\n========== SCAN COMPLETE ==========")
