import os
import pytest

moto = pytest.importorskip("moto")
from moto import mock_aws
import boto3

from cloudguard.scanners.s3_scanner import S3Scanner


@mock_aws
def test_s3_scanner_runs_offline_against_moto(monkeypatch):
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3")
    s3.create_bucket(Bucket="cloudguard-v2-moto-test")

    result = S3Scanner(session=session).scan()

    assert result["scanned_buckets"] == 1
    # A new bucket without BPA settings should be identified for review.
    assert any(f["check"] == "BLOCK_PUBLIC_ACCESS_DISABLED" for f in result["findings"])
