
"""AWS connection and account identity verification for CloudGuard.

Credentials are loaded through the local AWS SDK credential chain.
CloudGuard never accepts or stores AWS passwords or secret access keys.
"""

import re

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
)


REGION_PATTERN = re.compile(
    r"^[a-z]{2}(?:-[a-z0-9]+)+-\d+$"
)

ACCOUNT_ID_PATTERN = re.compile(r"^\d{12}$")


def list_aws_profiles():
    """Return locally configured AWS CLI profiles.

    This reads local AWS configuration only. It makes no AWS API calls.
    """
    try:
        profiles = boto3.Session().available_profiles
    except Exception:
        profiles = []

    # Include the default profile as a selectable option.
    return sorted(set(profiles) | {"default"})


def create_profile_session(profile_name, region_name):
    """Create a Boto3 session from an existing AWS CLI profile."""
    profile_name = (profile_name or "").strip()
    region_name = (region_name or "").strip()

    if not profile_name:
        raise ValueError("Select an AWS CLI profile.")

    if profile_name not in list_aws_profiles():
        raise ValueError(
            "That AWS CLI profile is not configured on this computer."
        )

    if not REGION_PATTERN.fullmatch(region_name):
        raise ValueError("Enter a valid AWS region.")

    try:
        return boto3.Session(
            profile_name=profile_name,
            region_name=region_name,
        )
    except ProfileNotFound as error:
        raise ValueError(
            "The selected AWS profile could not be found."
        ) from error


def verify_aws_session(aws_session, region_name):
    """Verify AWS credentials and return the actual caller identity.

    STS GetCallerIdentity is used only to identify the authenticated
    AWS account and principal. It does not modify AWS resources.
    """
    try:
        sts = aws_session.client(
            "sts",
            region_name=region_name,
        )

        identity = sts.get_caller_identity()

    except NoCredentialsError as error:
        raise ConnectionError(
            "No usable AWS credentials were found. "
            "Configure or sign in to the selected AWS profile."
        ) from error

    except ProfileNotFound as error:
        raise ConnectionError(
            "The selected AWS profile was not found."
        ) from error

    except (BotoCoreError, ClientError) as error:
        raise ConnectionError(
            "AWS identity verification failed. Check the profile, "
            "network connection and AWS sign-in status."
        ) from error

    account_id = str(identity.get("Account", ""))
    arn = identity.get("Arn", "")
    user_id = identity.get("UserId", "")

    if not ACCOUNT_ID_PATTERN.fullmatch(account_id):
        raise ConnectionError(
            "AWS returned an invalid account identity response."
        )

    if not arn:
        raise ConnectionError(
            "AWS did not return the authenticated identity ARN."
        )

    return {
        "account_id": account_id,
        "arn": arn,
        "user_id": user_id,
    }


def connect_aws_profile(profile_name, region_name):
    """Create an AWS session and verify its identity."""
    aws_session = create_profile_session(
        profile_name,
        region_name,
    )

    identity = verify_aws_session(
        aws_session,
        region_name,
    )

    return aws_session, identity


def reconnect_verified_profile(
    profile_name,
    region_name,
    expected_account_id,
):
    """Recreate a session and reject unexpected account changes."""
    aws_session, identity = connect_aws_profile(
        profile_name,
        region_name,
    )

    if identity["account_id"] != str(expected_account_id):
        raise ConnectionError(
            "The AWS profile now points to a different account. "
            "Reconnect and verify the intended account before scanning."
        )

    return aws_session, identity
