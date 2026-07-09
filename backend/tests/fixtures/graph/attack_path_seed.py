"""
Graph seed data for attack path integration tests.

Topology:
    [internet-facing EC2] --ASSUMES_ROLE--> [IAM Role with admin policy]
                                                --STORES_SENSITIVE_DATA-->  [S3 bucket w/ credentials]
    [public S3 bucket]  (no edges — TC-02 toxic combination direct detection)
    [K8s pod w/ host_network]  (no edges — TC-04 detection)
    [overpermissioned IAM user] --STS_ASSUMEROLE_ALLOW--> [admin role] --STORES_SENSITIVE_DATA--> [RDS DB]

Edge collection naming convention:
    ASSUMES_ROLE          — resources→identities (EC2/Lambda → IAM Role)
    STS_ASSUMEROLE_ALLOW  — identities→identities (derived from role trust policies)
    ASSUMES               — identities→identities (active assumed-role sessions)
"""

from __future__ import annotations

TENANT_ID = "test-tenant-graph-001"

# ---- Vertex collections ----

RESOURCES = [
    {
        "_key": "ec2-public-001",
        "resource_id": "ec2-public-001",
        "tenant_id": TENANT_ID,
        "provider": "aws",
        "resource_type": "ec2_instance",
        "name": "public-web-server",
        "is_public": True,
        "is_internet_facing": False,
        "region": "us-east-1",
        "risk_score": 0,
        "status": "active",
    },
    {
        "_key": "k8s-pod-hostnet",
        "resource_id": "k8s-pod-hostnet",
        "tenant_id": TENANT_ID,
        "provider": "kubernetes",
        "resource_type": "k8s_pod",
        "name": "privileged-pod",
        "is_public": False,
        "host_network": True,
        "risk_score": 0,
        "status": "active",
    },
]

IDENTITIES = [
    {
        "_key": "iam-role-admin",
        "resource_id": "iam-role-admin",
        "tenant_id": TENANT_ID,
        "provider": "aws",
        "resource_type": "iam_role",
        "name": "AdminRole",
        "has_admin_policy": True,
        "dangerous_permissions": ["iam:*", "s3:*"],
        "risk_score": 0,
        "status": "active",
        "arn": f"arn:aws:iam::123456789012:role/AdminRole_{TENANT_ID}",
    },
    {
        "_key": "iam-user-overpriv",
        "resource_id": "iam-user-overpriv",
        "tenant_id": TENANT_ID,
        "provider": "aws",
        "resource_type": "iam_user",
        "name": "DevUser",
        "has_admin_policy": False,
        "dangerous_permissions": ["iam:PassRole", "sts:AssumeRole"],
        "risk_score": 0,
        "status": "active",
        "arn": f"arn:aws:iam::123456789012:user/DevUser_{TENANT_ID}",
    },
]

DATA_ASSETS = [
    {
        "_key": "s3-creds-bucket",
        "resource_id": "s3-creds-bucket",
        "tenant_id": TENANT_ID,
        "provider": "aws",
        "resource_type": "s3_bucket",
        "name": "credentials-backup-bucket",
        "is_public": True,
        "contains_credentials": True,
        "contains_secrets": True,
        "risk_score": 0,
        "status": "active",
        "arn": f"arn:aws:s3:::creds-backup_{TENANT_ID}",
    },
    {
        "_key": "rds-prod-db",
        "resource_id": "rds-prod-db",
        "tenant_id": TENANT_ID,
        "provider": "aws",
        "resource_type": "rds_db_instance",
        "name": "prod-postgres",
        "is_public": False,
        "contains_credentials": False,
        "risk_score": 0,
        "status": "active",
        "arn": f"arn:aws:rds:us-east-1:123456789012:db:prod-postgres_{TENANT_ID}",
    },
]

NETWORK_ENDPOINTS = [
    {
        "_key": "igw-001",
        "resource_id": "igw-001",
        "tenant_id": TENANT_ID,
        "provider": "aws",
        "resource_type": "internet_gateway",
        "name": "main-igw",
        "is_internet_facing": True,
        "is_public": True,
        "risk_score": 0,
        "status": "active",
    },
]

# ---- Edge collections ----

ASSUMES_ROLE_EDGES = [
    # EC2 → IAM Role (resource→identity: ASSUMES_ROLE is correct here)
    {
        "_key": "ec2-public-001__iam-role-admin",
        "_from": "resources/ec2-public-001",
        "_to": "identities/iam-role-admin",
        "tenant_id": TENANT_ID,
        "relation_type": "ASSUMES_ROLE",
    },
]

# STS_ASSUMEROLE_ALLOW: identity→identity assume-role relationships (derived from trust policies)
STS_ASSUMEROLE_ALLOW_EDGES = [
    # DevUser can assume the admin role (privilege escalation — identity→identity)
    {
        "_key": "iam-user-overpriv__iam-role-admin",
        "_from": "identities/iam-user-overpriv",
        "_to": "identities/iam-role-admin",
        "tenant_id": TENANT_ID,
        "relation_type": "STS_ASSUMEROLE_ALLOW",
    },
]

STORES_SENSITIVE_DATA_EDGES = [
    # AdminRole → S3 bucket with credentials
    {
        "_key": "iam-role-admin__s3-creds-bucket",
        "_from": "identities/iam-role-admin",
        "_to": "data_assets/s3-creds-bucket",
        "tenant_id": TENANT_ID,
        "relation_type": "STORES_SENSITIVE_DATA",
    },
    # AdminRole → RDS production DB
    {
        "_key": "iam-role-admin__rds-prod-db",
        "_from": "identities/iam-role-admin",
        "_to": "data_assets/rds-prod-db",
        "tenant_id": TENANT_ID,
        "relation_type": "STORES_SENSITIVE_DATA",
    },
]

# Findings for the public EC2 (to give it a risk score)
FINDINGS = [
    {
        "_key": "finding-ec2-critical-001",
        "tenant_id": TENANT_ID,
        "resource_id": "ec2-public-001",
        "check_id": "ec2_public_instance_imdsv2",
        "severity": "CRITICAL",
        "status": "FAIL",
        "provider": "aws",
        "title": "EC2 IMDSv2 not enforced",
    },
    {
        "_key": "finding-ec2-high-001",
        "tenant_id": TENANT_ID,
        "resource_id": "ec2-public-001",
        "check_id": "ec2_sg_wide_open",
        "severity": "HIGH",
        "status": "FAIL",
        "provider": "aws",
        "title": "Security group allows 0.0.0.0/0 ingress",
    },
    {
        "_key": "finding-iam-critical-001",
        "tenant_id": TENANT_ID,
        "resource_id": "iam-role-admin",
        "check_id": "iam_admin_policy_attached",
        "severity": "CRITICAL",
        "status": "FAIL",
        "provider": "aws",
        "title": "IAM role has AdministratorAccess policy",
    },
]


def seed_graph(db: object) -> None:
    """Insert all seed vertices and edges into the test database."""
    from arango.database import StandardDatabase

    assert isinstance(db, StandardDatabase)

    for collection_name, docs in [
        ("resources", RESOURCES),
        ("identities", IDENTITIES),
        ("data_assets", DATA_ASSETS),
        ("network_endpoints", NETWORK_ENDPOINTS),
        ("findings", FINDINGS),
    ]:
        col = db.collection(collection_name)
        for doc in docs:
            if not col.has(doc["_key"]):
                col.insert(doc)

    for collection_name, edges in [
        ("ASSUMES_ROLE", ASSUMES_ROLE_EDGES),
        ("STS_ASSUMEROLE_ALLOW", STS_ASSUMEROLE_ALLOW_EDGES),
        ("STORES_SENSITIVE_DATA", STORES_SENSITIVE_DATA_EDGES),
    ]:
        col = db.collection(collection_name)
        for edge in edges:
            if not col.has(edge["_key"]):
                col.insert(edge)


def teardown_graph(db: object) -> None:
    """Remove all seed data from the test database."""
    from arango.database import StandardDatabase

    assert isinstance(db, StandardDatabase)

    for collection_name, docs in [
        ("resources", RESOURCES),
        ("identities", IDENTITIES),
        ("data_assets", DATA_ASSETS),
        ("network_endpoints", NETWORK_ENDPOINTS),
        ("findings", FINDINGS),
    ]:
        col = db.collection(collection_name)
        for doc in docs:
            try:
                col.delete(doc["_key"])
            except Exception:
                pass

    for collection_name, edges in [
        ("ASSUMES_ROLE", ASSUMES_ROLE_EDGES),
        ("STS_ASSUMEROLE_ALLOW", STS_ASSUMEROLE_ALLOW_EDGES),
        ("STORES_SENSITIVE_DATA", STORES_SENSITIVE_DATA_EDGES),
    ]:
        col = db.collection(collection_name)
        for edge in edges:
            try:
                col.delete(edge["_key"])
            except Exception:
                pass
