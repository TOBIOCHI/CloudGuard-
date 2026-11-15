"""
Rule catalogue for CloudGuard.

Every check the tool performs is listed here once, with its severity and the
fix advice shown to the user. Chapter 2 (Table 2.1) and Chapter 3 describe the
same rules, so if you change a severity here, change it in the chapters too.

Severity levels (three only, to match Chapter 1 and Chapter 2):
  HIGH   - directly exposed to the internet, or gives wide control with no other condition
  MEDIUM - reduces protection or visibility, but needs other conditions to cause harm
  LOW    - hygiene issue with limited direct impact
"""

RULES = {
    # ---- Storage (Amazon S3) ----
    "S3-01": {
        "category": "Storage",
        "severity": "HIGH",
        "title": "S3 bucket policy allows public access",
        "recommendation": "Remove the public principal (\"*\") or the public condition from the bucket policy, "
                          "then turn on all four S3 Block Public Access settings.",
    },
    "S3-02": {
        "category": "Storage",
        "severity": "HIGH",
        "title": "S3 bucket ACL grants access to a public group",
        "recommendation": "Remove the AllUsers / AuthenticatedUsers grant and set Object Ownership to "
                          "'Bucket owner enforced' so ACLs are disabled.",
    },
    "S3-03": {
        "category": "Storage",
        "severity": "MEDIUM",
        "title": "S3 Block Public Access is not fully enabled (account and bucket level)",
        "recommendation": "Turn on all four Block Public Access settings at account level, or at least on this bucket, "
                          "unless the bucket is meant to be public and that is documented.",
    },
    # ---- Network (EC2 security groups) ----
    "EC2-01": {
        "category": "Network",
        "severity": "HIGH",
        "title": "Security group allows SSH (port 22) from the whole internet",
        "recommendation": "Replace 0.0.0.0/0 or ::/0 with your own IP range, or use AWS Systems Manager Session Manager "
                          "instead of opening SSH.",
    },
    "EC2-02": {
        "category": "Network",
        "severity": "HIGH",
        "title": "Security group allows RDP (port 3389) from the whole internet",
        "recommendation": "Replace 0.0.0.0/0 or ::/0 with your own IP range, or connect through a bastion host or VPN.",
    },
    # ---- Identity and access (IAM) ----
    "IAM-01": {
        "category": "Identity",
        "severity": "HIGH",
        "title": "Root account does not have MFA enabled",
        "recommendation": "Sign in as root and add an MFA device under Security credentials. Do not use root for daily work.",
    },
    "IAM-02": {
        "category": "Identity",
        "severity": "MEDIUM",
        "title": "IAM user can sign in to the console without MFA",
        "recommendation": "Assign an MFA device to the user, or remove the console password if the user does not need it.",
    },
    "IAM-03": {
        "category": "Identity",
        "severity": "HIGH",
        "title": "Identity has full administrative access (\"*\" actions on \"*\" resources)",
        "recommendation": "Replace the policy with one that grants only the actions and resources this identity needs "
                          "(least privilege).",
    },
    "IAM-04": {
        "category": "Identity",
        "severity": "LOW",
        "title": "Active access key is older than 90 days",
        "recommendation": "Create a new access key, update the applications that use it, then deactivate and delete the old key.",
    },
    # ---- Logging and encryption ----
    "LOG-01": {
        "category": "Logging",
        "severity": "MEDIUM",
        "title": "No CloudTrail trail is logging in this Region",
        "recommendation": "Create a multi-Region CloudTrail trail that records management events and start logging.",
    },
    "LOG-02": {
        "category": "Logging",
        "severity": "LOW",
        "title": "CloudTrail log file validation is disabled",
        "recommendation": "Enable log file validation on the trail so tampering with log files can be detected.",
    },
    "ENC-01": {
        "category": "Encryption",
        "severity": "MEDIUM",
        "title": "EBS encryption by default is turned off in this Region",
        "recommendation": "In EC2 settings, turn on 'Always encrypt new EBS volumes' for this Region.",
    },
    "ENC-02": {
        "category": "Encryption",
        "severity": "MEDIUM",
        "title": "EBS volume is not encrypted",
        "recommendation": "Create an encrypted snapshot copy of the volume, restore it to a new encrypted volume, "
                          "and replace the unencrypted one.",
    },
}

SEVERITY_ORDER = {"HIGH": 1, "MEDIUM": 2, "LOW": 3}


def finding(rule_id, resource, detail=""):
    """Build one finding from the rule catalogue so every module reports the same shape."""
    rule = RULES[rule_id]
    return {
        "rule_id": rule_id,
        "category": rule["category"],
        "resource": resource,
        "severity": rule["severity"],
        "title": rule["title"],
        "description": detail or rule["title"],
        "recommendation": rule["recommendation"],
    }


# Compatibility map: original scanner check names -> Chapter 4 rule IDs.
CHECK_TO_RULE = {
    "PUBLIC_BUCKET_POLICY": "S3-01",
    "PUBLIC_BUCKET_ACL": "S3-02",
    "BLOCK_PUBLIC_ACCESS_DISABLED": "S3-03",
    "INTERNET_EXPOSED_SSH": "EC2-01",
    "INTERNET_EXPOSED_RDP": "EC2-02",
    "IAM_USER_WITHOUT_MFA": "IAM-02",
    "IAM_ADMINISTRATOR_ACCESS": "IAM-03",
    "IAM_OVERLY_PERMISSIVE_POLICY": "IAM-03",
    "CLOUDTRAIL_LOG_FILE_VALIDATION_DISABLED": "LOG-02",
    "EBS_VOLUME_UNENCRYPTED": "ENC-02",
}

# Checks retained from the original project that are outside the updated
# 13-rule evaluation set intentionally have no rule_id mapping.

def attach_rule_metadata(finding):
    """Add optional rule metadata without changing legacy finding fields."""
    check = finding.get("check") or finding.get("check_name")
    rule_id = CHECK_TO_RULE.get(check)
    if rule_id:
        rule = RULES[rule_id]
        finding["rule_id"] = rule_id
        finding["category"] = rule["category"]
        # Scanner-specific context takes precedence. The catalogue supplies
        # defaults only when a scanner did not provide these fields.
        finding.setdefault("severity", rule["severity"])
        finding.setdefault("recommendation", rule["recommendation"])
    return finding
