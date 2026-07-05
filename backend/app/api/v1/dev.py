"""
Dev-only endpoints — available only when DEV_MODE=true.

NEVER register this router in production.
Used for seeding realistic demo findings without real cloud credentials.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from arango.database import StandardDatabase
from fastapi import APIRouter, Depends, Header, HTTPException

from app.api.v1.inventory import get_tenant_db
from app.core.config import settings
from app.db.init import init_tenant_schema
from app.models.api_responses import ApiResponse
from app.workers.tasks.discovery import _upsert

router = APIRouter(prefix="/api/v1/dev", tags=["dev"])

# ─── Fixture data ─────────────────────────────────────────────────────────────
# Represents realistic Prowler output for an AWS account.
# status_extended mirrors what prowler-core generates.

DEMO_ACCOUNT_ID = "123456789012"
DEMO_PROVIDER_KEY = "demo-aws-account"

_D_MFA = "Multi-Factor Authentication (MFA) adds an extra layer of protection on top of a username and password."
_D_S3_BLOCK = "S3 Block Public Access provides settings for buckets to help manage public access to S3 resources."
_D_S3_ENC = "Amazon S3 default encryption provides a way to set the default encryption behavior for an S3 bucket."
_D_S3_VER = "S3 versioning allows storing multiple versions of an object, protecting against accidental deletion."
_D_RDS_ENC = "Amazon RDS encrypted instances use AES-256 to encrypt your data on the server that hosts the DB."

_FINDINGS: list[dict[str, Any]] = [
    {
        "check_id": "iam_root_hardware_mfa_enabled",
        "title": "Ensure hardware MFA is enabled for the root account",
        "description": (
            "The root account is the most privileged user in an AWS account. "
            "Hardware MFA adds an extra layer of protection on top of a username and password."
        ),
        "severity": "CRITICAL",
        "status": "FAIL",
        "resource_type": "iam_root",
        "resource_id": "root",
        "resource_arn": "arn:aws:iam::123456789012:root",
        "region": "us-east-1",
        "status_extended": "Root account does not have hardware MFA enabled.",
        "remediation": "Enable a hardware MFA device for the root account via the IAM console.",
        "remediation_code": "aws iam get-account-summary --query 'SummaryMap.AccountMFAEnabled'",
        "framework_mapping": [
            "CIS-AWS-2.0/1.6",
            "PCI_DSS_v4/8.4.1",
            "SOC2/CC6.1",
        ],
    },
    {
        "check_id": "cloudtrail_enabled_all_regions",
        "title": "Ensure CloudTrail is enabled in all regions",
        "description": (
            "AWS CloudTrail records AWS API calls for your account. "
            "Without it you lose visibility into all activity in your account."
        ),
        "severity": "CRITICAL",
        "status": "FAIL",
        "resource_type": "cloudtrail_trail",
        "resource_id": "No trails found",
        "resource_arn": None,
        "region": "us-east-1",
        "status_extended": "No CloudTrail trails are enabled across all regions.",
        "remediation": "Create a CloudTrail trail covering all regions and enable log file validation.",
        "remediation_code": (
            "aws cloudtrail create-trail --name ogum-audit-trail "
            "--s3-bucket-name my-audit-bucket --is-multi-region-trail"
        ),
        "framework_mapping": [
            "CIS-AWS-2.0/3.1",
            "PCI_DSS_v4/10.2.1",
            "SOC2/CC7.1",
        ],
    },
    {
        "check_id": "guardduty_is_enabled",
        "title": "Ensure Amazon GuardDuty is enabled",
        "description": (
            "Amazon GuardDuty is a threat detection service that continuously monitors "
            "for malicious activity to protect your AWS accounts and workloads."
        ),
        "severity": "HIGH",
        "status": "FAIL",
        "resource_type": "guardduty_detector",
        "resource_id": "No detector",
        "resource_arn": None,
        "region": "us-east-1",
        "status_extended": "GuardDuty is not enabled in region us-east-1.",
        "remediation": "Enable GuardDuty in every region you use.",
        "remediation_code": ("aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES"),
        "framework_mapping": [
            "CIS-AWS-2.0/4.15",
            "SOC2/CC7.1",
        ],
    },
    {
        "check_id": "iam_user_mfa_enabled",
        "title": "Ensure MFA is enabled for all IAM users with console access",
        "description": _D_MFA,
        "severity": "HIGH",
        "status": "FAIL",
        "resource_type": "iam_user",
        "resource_id": "john.doe",
        "resource_arn": "arn:aws:iam::123456789012:user/john.doe",
        "region": "us-east-1",
        "status_extended": ("IAM user john.doe has console access enabled but MFA is not configured."),
        "remediation": "Enable MFA for the IAM user via the IAM console or AWS CLI.",
        "remediation_code": (
            "aws iam enable-mfa-device --user-name john.doe "
            "--serial-number arn:aws:iam::123456789012:mfa/john.doe "
            "--authentication-code1 <code1> --authentication-code2 <code2>"
        ),
        "framework_mapping": [
            "CIS-AWS-2.0/1.10",
            "PCI_DSS_v4/8.3.6",
            "SOC2/CC6.1",
        ],
    },
    {
        "check_id": "iam_user_mfa_enabled",
        "title": "Ensure MFA is enabled for all IAM users with console access",
        "description": _D_MFA,
        "severity": "HIGH",
        "status": "FAIL",
        "resource_type": "iam_user",
        "resource_id": "jane.smith",
        "resource_arn": "arn:aws:iam::123456789012:user/jane.smith",
        "region": "us-east-1",
        "status_extended": ("IAM user jane.smith has console access enabled but MFA is not configured."),
        "remediation": "Enable MFA for the IAM user via the IAM console or AWS CLI.",
        "remediation_code": (
            "aws iam enable-mfa-device --user-name jane.smith "
            "--serial-number arn:aws:iam::123456789012:mfa/jane.smith "
            "--authentication-code1 <code1> --authentication-code2 <code2>"
        ),
        "framework_mapping": [
            "CIS-AWS-2.0/1.10",
            "PCI_DSS_v4/8.3.6",
            "SOC2/CC6.1",
        ],
    },
    {
        "check_id": "s3_bucket_public_access_block",
        "title": "Ensure S3 bucket public access block is enabled",
        "description": _D_S3_BLOCK,
        "severity": "HIGH",
        "status": "FAIL",
        "resource_type": "s3_bucket",
        "resource_id": "my-company-data-lake-prod",
        "resource_arn": "arn:aws:s3:::my-company-data-lake-prod",
        "region": "us-east-1",
        "status_extended": ("S3 Bucket my-company-data-lake-prod does not have Block Public Access enabled."),
        "remediation": "Enable S3 Block Public Access at the bucket level.",
        "remediation_code": (
            "aws s3api put-public-access-block --bucket my-company-data-lake-prod "
            "--public-access-block-configuration "
            "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
        ),
        "framework_mapping": [
            "CIS-AWS-2.0/2.1.4",
            "PCI_DSS_v4/1.3.2",
            "SOC2/CC6.1",
        ],
    },
    {
        "check_id": "ec2_securitygroup_default_restrict_traffic",
        "title": "Ensure the default security group of every VPC restricts all traffic",
        "description": (
            "A VPC comes with a default security group whose initial settings allow all traffic "
            "between instances. Restrict this to enforce least-privilege networking."
        ),
        "severity": "HIGH",
        "status": "FAIL",
        "resource_type": "ec2_security_group",
        "resource_id": "sg-0abc123def456789a",
        "resource_arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123def456789a",
        "region": "us-east-1",
        "status_extended": (
            "Default security group sg-0abc123def456789a in VPC vpc-0123456789abcdef0 has rules that allow all traffic."
        ),
        "remediation": "Remove all rules from the default security group; use custom security groups instead.",
        "remediation_code": (
            "aws ec2 revoke-security-group-ingress --group-id sg-0abc123def456789a --protocol all --cidr 0.0.0.0/0"
        ),
        "framework_mapping": [
            "CIS-AWS-2.0/5.3",
            "SOC2/CC6.1",
        ],
    },
    {
        "check_id": "rds_instance_no_public_access",
        "title": "Ensure that AWS Database instances are not publicly accessible",
        "description": "Ensure that AWS RDS database instances are not publicly accessible to minimize security risks.",
        "severity": "HIGH",
        "status": "FAIL",
        "resource_type": "rds_instance",
        "resource_id": "prod-mysql-db",
        "resource_arn": "arn:aws:rds:us-east-1:123456789012:db:prod-mysql-db",
        "region": "us-east-1",
        "status_extended": "RDS instance prod-mysql-db is publicly accessible.",
        "remediation": "Disable public access on the RDS instance.",
        "remediation_code": (
            "aws rds modify-db-instance --db-instance-identifier prod-mysql-db "
            "--no-publicly-accessible --apply-immediately"
        ),
        "framework_mapping": [
            "CIS-AWS-2.0/2.3.3",
            "PCI_DSS_v4/1.3.2",
            "SOC2/CC6.1",
        ],
    },
    {
        "check_id": "iam_user_access_key_unused_45_days",
        "title": "Ensure access keys unused for 45 days or more are disabled",
        "description": "Removing or disabling access keys more than 45 days old reduces the attack surface.",
        "severity": "MEDIUM",
        "status": "FAIL",
        "resource_type": "iam_user",
        "resource_id": "svc-deploy",
        "resource_arn": "arn:aws:iam::123456789012:user/svc-deploy",
        "region": "us-east-1",
        "status_extended": ("IAM user svc-deploy has access key AKIAIOSFODNN7EXAMPLE last used 92 days ago."),
        "remediation": "Disable or delete access keys that have not been used for 45 days.",
        "remediation_code": (
            "aws iam update-access-key --access-key-id AKIAIOSFODNN7EXAMPLE --status Inactive --user-name svc-deploy"
        ),
        "framework_mapping": [
            "CIS-AWS-2.0/1.12",
            "SOC2/CC6.2",
        ],
    },
    {
        "check_id": "s3_bucket_default_encryption",
        "title": "Ensure all S3 buckets employ encryption-at-rest",
        "description": _D_S3_ENC,
        "severity": "MEDIUM",
        "status": "FAIL",
        "resource_type": "s3_bucket",
        "resource_id": "my-company-logs-2023",
        "resource_arn": "arn:aws:s3:::my-company-logs-2023",
        "region": "us-east-1",
        "status_extended": "S3 Bucket my-company-logs-2023 does not have default encryption enabled.",
        "remediation": "Enable default encryption using SSE-S3 or SSE-KMS.",
        "remediation_code": (
            "aws s3api put-bucket-encryption --bucket my-company-logs-2023 "
            "--server-side-encryption-configuration "
            '\'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}\''
        ),
        "framework_mapping": [
            "CIS-AWS-2.0/2.1.1",
            "PCI_DSS_v4/3.5.1",
            "SOC2/CC6.1",
        ],
    },
    {
        "check_id": "ec2_ebs_volume_encryption_enabled",
        "title": "Ensure that EBS volume encryption is enabled",
        "description": (
            "Enabling encryption on EBS volumes protects data at rest and data in transit "
            "between an instance and its attached EBS storage."
        ),
        "severity": "MEDIUM",
        "status": "FAIL",
        "resource_type": "ec2_volume",
        "resource_id": "vol-0a1b2c3d4e5f67890",
        "resource_arn": "arn:aws:ec2:us-east-1:123456789012:volume/vol-0a1b2c3d4e5f67890",
        "region": "us-east-1",
        "status_extended": (
            "EBS volume vol-0a1b2c3d4e5f67890 attached to instance i-0123456789abcdef0 is not encrypted."
        ),
        "remediation": "Create an encrypted snapshot of the volume and replace the original.",
        "remediation_code": (
            "aws ec2 create-snapshot --volume-id vol-0a1b2c3d4e5f67890 --description 'Pre-encryption snapshot'"
        ),
        "framework_mapping": [
            "CIS-AWS-2.0/2.2.1",
            "SOC2/CC6.1",
        ],
    },
    {
        "check_id": "vpc_flow_logs_enabled",
        "title": "Ensure VPC flow logging is enabled in all VPCs",
        "description": (
            "VPC Flow Logs captures information about IP traffic going to and from "
            "network interfaces in your VPC. Essential for incident investigation."
        ),
        "severity": "MEDIUM",
        "status": "FAIL",
        "resource_type": "vpc",
        "resource_id": "vpc-0123456789abcdef0",
        "resource_arn": "arn:aws:ec2:us-east-1:123456789012:vpc/vpc-0123456789abcdef0",
        "region": "us-east-1",
        "status_extended": "VPC vpc-0123456789abcdef0 does not have flow logs enabled.",
        "remediation": "Enable VPC flow logs and send them to CloudWatch Logs or S3.",
        "remediation_code": (
            "aws ec2 create-flow-logs --resource-type VPC "
            "--resource-ids vpc-0123456789abcdef0 --traffic-type ALL "
            "--log-destination-type cloud-watch-logs "
            "--log-group-name /aws/vpc/flow-logs"
        ),
        "framework_mapping": [
            "CIS-AWS-2.0/3.9",
            "SOC2/CC7.1",
        ],
    },
    {
        "check_id": "kms_cmk_rotation_enabled",
        "title": "Ensure rotation for customer created symmetric CMKs is enabled",
        "description": (
            "AWS KMS allows customers to rotate the backing key which is tied to the key ID of the CMK. "
            "Annual rotation reduces risk from key compromise."
        ),
        "severity": "MEDIUM",
        "status": "FAIL",
        "resource_type": "kms_key",
        "resource_id": "mrk-abc123def456ghi789",
        "resource_arn": "arn:aws:kms:us-east-1:123456789012:key/mrk-abc123def456ghi789",
        "region": "us-east-1",
        "status_extended": (
            "KMS key mrk-abc123def456ghi789 (alias: alias/prod-data-key) does not have automatic rotation enabled."
        ),
        "remediation": "Enable automatic key rotation for the CMK.",
        "remediation_code": "aws kms enable-key-rotation --key-id mrk-abc123def456ghi789",
        "framework_mapping": [
            "CIS-AWS-2.0/3.8",
            "PCI_DSS_v4/3.7.1",
        ],
    },
    {
        "check_id": "iam_password_policy_uppercase",
        "title": "Ensure IAM password policy requires at least one uppercase letter",
        "description": (
            "Password policies enforce password complexity requirements. "
            "Use IAM password policies to ensure passwords are composed of different character sets."
        ),
        "severity": "MEDIUM",
        "status": "FAIL",
        "resource_type": "iam_password_policy",
        "resource_id": "password_policy",
        "resource_arn": None,
        "region": "us-east-1",
        "status_extended": "IAM password policy does not require uppercase letters.",
        "remediation": "Update the IAM account password policy to require at least one uppercase letter.",
        "remediation_code": "aws iam update-account-password-policy --require-uppercase-characters",
        "framework_mapping": [
            "CIS-AWS-2.0/1.8",
            "PCI_DSS_v4/8.3.6",
        ],
    },
    {
        "check_id": "s3_bucket_versioning_enabled",
        "title": "Ensure that S3 Buckets have versioning enabled",
        "description": _D_S3_VER,
        "severity": "LOW",
        "status": "FAIL",
        "resource_type": "s3_bucket",
        "resource_id": "my-company-backups",
        "resource_arn": "arn:aws:s3:::my-company-backups",
        "region": "us-east-1",
        "status_extended": "S3 Bucket my-company-backups does not have versioning enabled.",
        "remediation": "Enable versioning on the S3 bucket.",
        "remediation_code": (
            "aws s3api put-bucket-versioning --bucket my-company-backups --versioning-configuration Status=Enabled"
        ),
        "framework_mapping": [
            "CIS-AWS-2.0/2.1.3",
        ],
    },
    {
        "check_id": "iam_user_mfa_enabled",
        "title": "Ensure MFA is enabled for all IAM users with console access",
        "description": _D_MFA,
        "severity": "HIGH",
        "status": "PASS",
        "resource_type": "iam_user",
        "resource_id": "admin.user",
        "resource_arn": "arn:aws:iam::123456789012:user/admin.user",
        "region": "us-east-1",
        "status_extended": "IAM user admin.user has MFA enabled (virtual device).",
        "remediation": None,
        "remediation_code": None,
        "framework_mapping": [
            "CIS-AWS-2.0/1.10",
            "PCI_DSS_v4/8.3.6",
            "SOC2/CC6.1",
        ],
    },
    {
        "check_id": "s3_bucket_public_access_block",
        "title": "Ensure S3 bucket public access block is enabled",
        "description": _D_S3_BLOCK,
        "severity": "HIGH",
        "status": "PASS",
        "resource_type": "s3_bucket",
        "resource_id": "my-company-secure-artifacts",
        "resource_arn": "arn:aws:s3:::my-company-secure-artifacts",
        "region": "us-east-1",
        "status_extended": "S3 Bucket my-company-secure-artifacts has Block Public Access enabled.",
        "remediation": None,
        "remediation_code": None,
        "framework_mapping": [
            "CIS-AWS-2.0/2.1.4",
            "PCI_DSS_v4/1.3.2",
            "SOC2/CC6.1",
        ],
    },
    {
        "check_id": "rds_instance_storage_encrypted",
        "title": "Ensure that RDS database instances have encryption-at-rest enabled",
        "description": _D_RDS_ENC,
        "severity": "MEDIUM",
        "status": "PASS",
        "resource_type": "rds_instance",
        "resource_id": "prod-postgres-replica",
        "resource_arn": "arn:aws:rds:us-east-1:123456789012:db:prod-postgres-replica",
        "region": "us-east-1",
        "status_extended": "RDS instance prod-postgres-replica has storage encryption enabled.",
        "remediation": None,
        "remediation_code": None,
        "framework_mapping": [
            "CIS-AWS-2.0/2.3.1",
            "PCI_DSS_v4/3.5.1",
        ],
    },
    {
        "check_id": "iam_user_access_key_unused_45_days",
        "title": "Ensure access keys unused for 45 days or more are disabled",
        "description": "Removing or disabling access keys more than 45 days old reduces the attack surface.",
        "severity": "MEDIUM",
        "status": "MUTED",
        "resource_type": "iam_user",
        "resource_id": "svc-legacy-integration",
        "resource_arn": "arn:aws:iam::123456789012:user/svc-legacy-integration",
        "region": "us-east-1",
        "status_extended": (
            "IAM user svc-legacy-integration has access key AKIAI44QH8DHBEXAMPLE last used 180 days ago."
        ),
        "remediation": "Disable or delete access keys that have not been used for 45 days.",
        "remediation_code": (
            "aws iam update-access-key --access-key-id AKIAI44QH8DHBEXAMPLE "
            "--status Inactive --user-name svc-legacy-integration"
        ),
        "framework_mapping": [
            "CIS-AWS-2.0/1.12",
            "SOC2/CC6.2",
        ],
        "mute_reason": "Legacy integration pending migration — scheduled removal Q3 2026",
    },
]


# ─── Seed logic ───────────────────────────────────────────────────────────────


def _build_finding_doc(
    raw: dict[str, Any],
    tenant_id: str,
    scan_job_id: str,
    detected_at: str,
) -> dict[str, Any]:
    resource_id = raw["resource_id"]
    check_id = raw["check_id"]
    key_parts = f"{check_id}_{resource_id}_{tenant_id}"
    key = key_parts.replace("/", "_").replace(":", "_").replace(" ", "_")[:240]

    muted_at = datetime.now(UTC).isoformat() if raw["status"] == "MUTED" else None

    return {
        "_key": key,
        "finding_id": str(uuid.uuid4()),
        "tenant_id": tenant_id,
        "check_id": check_id,
        "title": raw["title"],
        "description": raw["description"],
        "resource_id": resource_id,
        "resource_arn": raw.get("resource_arn"),
        "resource_type": raw["resource_type"],
        "severity": raw["severity"],
        "status": raw["status"],
        "provider": "aws",
        "region": raw.get("region", "us-east-1"),
        "account_id": DEMO_ACCOUNT_ID,
        "framework_mapping": raw["framework_mapping"],
        "remediation": raw.get("remediation"),
        "remediation_code": raw.get("remediation_code"),
        "source": "cspm",
        "detected_at": detected_at,
        "updated_at": muted_at or detected_at,
        "mute_reason": raw.get("mute_reason"),
        "scan_job_id": scan_job_id,
        "raw_output": {
            "status_extended": raw["status_extended"],
        },
    }


def _build_provider_doc(tenant_id: str) -> dict[str, Any]:
    now = datetime.now(UTC).isoformat()
    return {
        "_key": DEMO_PROVIDER_KEY,
        "tenant_id": tenant_id,
        "provider": "aws",
        "display_name": "AWS Demo Account",
        "account_id": DEMO_ACCOUNT_ID,
        "regions": ["us-east-1"],
        "enabled": True,
        "status": "active",
        "credential_type": "demo",
        "role_arn": None,
        "external_id": None,
        "last_discovery_at": now,
        "last_discovery_job_id": None,
        "created_at": now,
        "updated_at": now,
    }


def _build_scan_job_doc(
    tenant_id: str,
    job_id: str,
    findings: list[dict[str, Any]],
    started_at: str,
    completed_at: str,
) -> dict[str, Any]:
    fail_count = sum(1 for f in findings if f["status"] == "FAIL")
    return {
        "_key": job_id,
        "job_id": job_id,
        "tenant_id": tenant_id,
        "provider_id": DEMO_PROVIDER_KEY,
        "provider": "aws",
        "task_name": "discovery/cspm",
        "frameworks": ["CIS-AWS-2.0", "PCI_DSS_v4", "SOC2"],
        "regions": ["us-east-1"],
        "status": "completed",
        "checks_total": len(findings),
        "checks_completed": len(findings),
        "findings_found": len(findings),
        "findings_fail": fail_count,
        "started_at": started_at,
        "completed_at": completed_at,
        "created_at": started_at,
        "error_message": None,
    }


def seed_findings(db: StandardDatabase, tenant_id: str) -> dict[str, Any]:
    """Insert demo findings, a demo provider, and a demo scan_job into the tenant DB."""
    init_tenant_schema(db)

    now = datetime.now(UTC)
    detected_at = (now - timedelta(hours=2)).isoformat()
    scan_started = (now - timedelta(hours=2, minutes=5)).isoformat()
    scan_completed = (now - timedelta(hours=1, minutes=57)).isoformat()
    job_id = "demo-scan-job-001"

    # Provider
    _upsert(
        db,
        "tenant_config",
        _build_provider_doc(tenant_id),
        {"status": "active", "last_discovery_at": now.isoformat()},
    )

    # Build finding docs
    finding_docs = [_build_finding_doc(raw, tenant_id, job_id, detected_at) for raw in _FINDINGS]

    # Upsert findings
    inserted = 0
    for doc in finding_docs:
        update = {
            "status": doc["status"],
            "severity": doc["severity"],
            "updated_at": doc["updated_at"],
            "framework_mapping": doc["framework_mapping"],
            "remediation": doc["remediation"],
            "remediation_code": doc["remediation_code"],
            "raw_output": doc["raw_output"],
        }
        _upsert(db, "findings", doc, update)
        inserted += 1

    # Scan job
    job_doc = _build_scan_job_doc(tenant_id, job_id, finding_docs, scan_started, scan_completed)
    _upsert(db, "scan_jobs", job_doc, {"status": "completed", "completed_at": scan_completed})

    fail_count = sum(1 for d in finding_docs if d["status"] == "FAIL")
    pass_count = sum(1 for d in finding_docs if d["status"] == "PASS")
    muted_count = sum(1 for d in finding_docs if d["status"] == "MUTED")

    return {
        "seeded": True,
        "tenant_id": tenant_id,
        "findings_inserted": inserted,
        "findings_fail": fail_count,
        "findings_pass": pass_count,
        "findings_muted": muted_count,
        "scan_job_id": job_id,
        "account_id": DEMO_ACCOUNT_ID,
    }


# ─── Endpoints ────────────────────────────────────────────────────────────────


@router.post("/seed", response_model=ApiResponse[dict])
def seed_dev_data(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[dict]:
    """
    Seed realistic demo findings into the tenant database.

    Only available when DEV_MODE=true. Idempotent — safe to call multiple times.
    """
    if not settings.DEV_MODE:
        raise HTTPException(status_code=404, detail="Not found")

    result = seed_findings(db, x_tenant_id)
    return ApiResponse(data=result)


@router.delete("/seed", response_model=ApiResponse[dict])
def clear_dev_data(
    x_tenant_id: str = Header(..., alias="X-Tenant-Id"),
    db: StandardDatabase = Depends(get_tenant_db),
) -> ApiResponse[dict]:
    """
    Remove all findings and scan_jobs from the tenant database.

    Only available when DEV_MODE=true. Use to reset the demo state.
    """
    if not settings.DEV_MODE:
        raise HTTPException(status_code=404, detail="Not found")

    deleted_findings = 0
    deleted_jobs = 0

    try:
        cursor = db.aql.execute(
            "FOR f IN findings FILTER f.tenant_id == @tid REMOVE f IN findings RETURN 1",
            bind_vars={"tid": x_tenant_id},
        )
        deleted_findings = len(list(cursor))
    except Exception:
        pass

    try:
        cursor = db.aql.execute(
            "FOR j IN scan_jobs FILTER j.tenant_id == @tid REMOVE j IN scan_jobs RETURN 1",
            bind_vars={"tid": x_tenant_id},
        )
        deleted_jobs = len(list(cursor))
    except Exception:
        pass

    return ApiResponse(
        data={
            "cleared": True,
            "tenant_id": x_tenant_id,
            "deleted_findings": deleted_findings,
            "deleted_scan_jobs": deleted_jobs,
        }
    )
