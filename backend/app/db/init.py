"""
Tenant database schema initialization.
Idempotent — safe to run multiple times against the same database.
"""

from arango.database import StandardDatabase

VERTEX_COLLECTIONS = [
    "resources",
    "identities",
    "vulnerabilities",
    "network_endpoints",
    "data_assets",
    "attack_paths",
    "tenant_config",
    "findings",
    "scan_jobs",
    "audit_log",
    "saved_queries",  # Sprint 6: per-tenant AQL console saved queries
    "sboms",  # Sprint 2 (Epic 03): CycloneDX SBOMs generated per EC2 scan
]

ADMIN_VERTEX_COLLECTIONS = [
    "admin_audit_log",
    "mitre_techniques",
    "mitre_tactics",
    "mitre_groups",
]

ADMIN_EDGE_COLLECTIONS = [
    "APT_USES",
]

EDGE_COLLECTIONS = [
    "EXPOSED_TO",
    "ASSUMES_ROLE",
    "CONTAINS_BUG",
    "STORES_SENSITIVE_DATA",
    "ROUTES_TRAFFIC",
    "BELONGS_TO",
    "ATTACHED_TO",
    "MEMBER_OF",
    "HAS_FINDING",
    "MAPPED_TO",
    "IMPLEMENTS",
    # IAM deep model (Sprint 6)
    "STS_ASSUMEROLE_ALLOW",  # identity A can assume role B (derived from trust policy)
    "ASSUMES",  # identity A is actively assuming role B
    "ATTACHED_POLICY",  # identity has policy attached
    "HAS_ACTIVE_SESSION",  # identity has an active session credential
    "HAS_SBOM",  # resource → sbom (Sprint 2 Epic 03)
]

# (collection_name, fields, unique)
PERSISTENT_INDEXES: list[tuple[str, list[str], bool]] = [
    ("resources", ["tenant_id"], False),
    ("resources", ["tenant_id", "provider"], False),
    ("resources", ["tenant_id", "resource_type"], False),
    ("resources", ["resource_id"], False),
    ("resources", ["status"], False),
    ("identities", ["tenant_id"], False),
    ("identities", ["tenant_id", "provider"], False),
    ("identities", ["arn"], True),
    ("network_endpoints", ["tenant_id"], False),
    ("data_assets", ["tenant_id"], False),
    ("data_assets", ["arn"], False),
    ("vulnerabilities", ["tenant_id"], False),
    ("vulnerabilities", ["tenant_id", "check_id"], False),
    ("findings", ["tenant_id"], False),
    ("findings", ["tenant_id", "severity"], False),
    ("findings", ["tenant_id", "status"], False),
    ("findings", ["tenant_id", "provider"], False),
    ("findings", ["check_id"], False),
    ("scan_jobs", ["tenant_id"], False),
    ("scan_jobs", ["tenant_id", "status"], False),
    ("attack_paths", ["tenant_id"], False),
    ("attack_paths", ["tenant_id", "risk_score"], False),
    ("attack_paths", ["tenant_id", "is_toxic_combination"], False),
    ("attack_paths", ["tenant_id", "severity"], False),
    ("resources", ["tenant_id", "risk_score"], False),
    ("identities", ["tenant_id", "risk_score"], False),
    ("data_assets", ["tenant_id", "risk_score"], False),
    ("audit_log", ["tenant_id"], False),
    ("audit_log", ["tenant_id", "finding_key"], False),
    # Crown Jewels (Sprint 6)
    ("resources", ["tenant_id", "is_crown_jewel"], False),
    ("data_assets", ["tenant_id", "is_crown_jewel"], False),
    # Saved queries console (Sprint 6)
    ("saved_queries", ["tenant_id"], False),
    # SBOMs (Sprint 2 Epic 03)
    ("sboms", ["tenant_id"], False),
    ("sboms", ["tenant_id", "resource_id"], False),
]

ADMIN_PERSISTENT_INDEXES: list[tuple[str, list[str], bool]] = [
    ("admin_audit_log", ["tenant_id"], False),
    ("admin_audit_log", ["tenant_id", "timestamp"], False),
    ("admin_audit_log", ["actor_id"], False),
    ("mitre_techniques", ["technique_id"], True),
    ("mitre_techniques", ["tactic_ids"], False),
    ("mitre_groups", ["group_id"], True),
    ("mitre_tactics", ["tactic_id"], True),
]


def _ensure_indexes(db: StandardDatabase, indexes: list[tuple[str, list[str], bool]]) -> None:
    for collection_name, fields, unique in indexes:
        col = db.collection(collection_name)
        existing = col.indexes()
        already_exists = any(
            sorted(idx.get("fields", [])) == sorted(fields) and idx.get("type") == "persistent" for idx in existing
        )
        if not already_exists:
            col.add_index({"type": "persistent", "fields": fields, "unique": unique})


def init_tenant_schema(db: StandardDatabase) -> None:
    """Create all vertex collections, edge collections, and indexes for a tenant DB."""
    for name in VERTEX_COLLECTIONS:
        if not db.has_collection(name):
            db.create_collection(name)

    for name in EDGE_COLLECTIONS:
        if not db.has_collection(name):
            db.create_collection(name, edge=True)

    _ensure_indexes(db, PERSISTENT_INDEXES)


def init_admin_schema(db: StandardDatabase) -> None:
    """Create the admin database schema (ogum_admin). Idempotent."""
    for name in ADMIN_VERTEX_COLLECTIONS:
        if not db.has_collection(name):
            db.create_collection(name)

    for name in ADMIN_EDGE_COLLECTIONS:
        if not db.has_collection(name):
            db.create_collection(name, edge=True)

    _ensure_indexes(db, ADMIN_PERSISTENT_INDEXES)
