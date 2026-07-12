"""
Unit tests for _get_aws_session (backend/app/workers/tasks/cloud_utils.py).

Strategy: mock boto3.client/boto3.Session directly rather than moto — the point
under test is *which credentials sign the STS AssumeRole call*, not whether STS
itself behaves correctly (moto accepts any credentials without validating them,
so it can't distinguish "used the static keys" from "used ambient creds").
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.workers.tasks.cloud_utils import _get_aws_session


@pytest.mark.unit
class TestGetAwsSession:
    def test_role_arn_with_static_keys_signs_sts_client_with_them(self, mocker) -> None:
        """
        Regression test: assuming a role from a static-key base identity (e.g. a
        local-dev tenant_config with both role_arn and static keys set, no ambient
        instance-profile credentials available) must sign the AssumeRole call with
        those keys — previously this branch always built an unauthenticated STS
        client, which only worked when the process happened to have ambient AWS
        credentials (true in production on an EC2/ECS instance profile, never true
        in a local Docker container).
        """
        mock_sts_client = MagicMock()
        mock_sts_client.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "ASSUMED_KEY",
                "SecretAccessKey": "ASSUMED_SECRET",
                "SessionToken": "ASSUMED_TOKEN",
            }
        }
        mock_boto_client = mocker.patch("app.workers.tasks.cloud_utils.boto3.client", return_value=mock_sts_client)
        mock_session_cls = mocker.patch("app.workers.tasks.cloud_utils.boto3.Session")

        _get_aws_session(
            role_arn="arn:aws:iam::590608352058:role/ogum-scanner",
            external_id="ogum-dev-dev",
            aws_access_key_id="AKIABASE",
            aws_secret_access_key="base-secret",
        )

        mock_boto_client.assert_called_once_with(
            "sts",
            region_name="us-east-1",
            aws_access_key_id="AKIABASE",
            aws_secret_access_key="base-secret",
        )
        mock_sts_client.assume_role.assert_called_once_with(
            RoleArn="arn:aws:iam::590608352058:role/ogum-scanner",
            RoleSessionName="ogum-discovery",
            DurationSeconds=3600,
            ExternalId="ogum-dev-dev",
        )
        mock_session_cls.assert_called_once_with(
            aws_access_key_id="ASSUMED_KEY",
            aws_secret_access_key="ASSUMED_SECRET",
            aws_session_token="ASSUMED_TOKEN",
        )

    def test_role_arn_without_static_keys_uses_ambient_sts_client(self, mocker) -> None:
        """Production path: no static keys given → STS client built with no explicit
        credentials, so boto3 falls back to ambient (instance profile / IRSA)."""
        mock_sts_client = MagicMock()
        mock_sts_client.assume_role.return_value = {
            "Credentials": {"AccessKeyId": "K", "SecretAccessKey": "S", "SessionToken": "T"}
        }
        mock_boto_client = mocker.patch("app.workers.tasks.cloud_utils.boto3.client", return_value=mock_sts_client)
        mocker.patch("app.workers.tasks.cloud_utils.boto3.Session")

        _get_aws_session(role_arn="arn:aws:iam::123456789012:role/customer-role")

        mock_boto_client.assert_called_once_with("sts", region_name="us-east-1")

    def test_role_arn_without_external_id_omits_it(self, mocker) -> None:
        mock_sts_client = MagicMock()
        mock_sts_client.assume_role.return_value = {
            "Credentials": {"AccessKeyId": "K", "SecretAccessKey": "S", "SessionToken": "T"}
        }
        mocker.patch("app.workers.tasks.cloud_utils.boto3.client", return_value=mock_sts_client)
        mocker.patch("app.workers.tasks.cloud_utils.boto3.Session")

        _get_aws_session(role_arn="arn:aws:iam::123456789012:role/customer-role")

        call_kwargs = mock_sts_client.assume_role.call_args.kwargs
        assert "ExternalId" not in call_kwargs

    def test_static_keys_without_role_arn_returns_direct_session(self, mocker) -> None:
        mock_session_cls = mocker.patch("app.workers.tasks.cloud_utils.boto3.Session")
        mock_boto_client = mocker.patch("app.workers.tasks.cloud_utils.boto3.client")

        _get_aws_session(aws_access_key_id="AKIADIRECT", aws_secret_access_key="direct-secret")

        mock_boto_client.assert_not_called()
        mock_session_cls.assert_called_once_with(
            aws_access_key_id="AKIADIRECT",
            aws_secret_access_key="direct-secret",
        )

    def test_no_credentials_returns_ambient_session(self, mocker) -> None:
        mock_session_cls = mocker.patch("app.workers.tasks.cloud_utils.boto3.Session")
        mock_boto_client = mocker.patch("app.workers.tasks.cloud_utils.boto3.client")

        _get_aws_session()

        mock_boto_client.assert_not_called()
        mock_session_cls.assert_called_once_with()
