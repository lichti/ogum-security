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
]

EDGE_COLLECTIONS = [
    "EXPOSED_TO",
    "ASSUMES_ROLE",
    "CONTAINS_BUG",
    "STORES_SENSITIVE_DATA",
    "ROUTES_TRAFFIC",
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
]


def init_tenant_schema(db: StandardDatabase) -> None:
    """Create all vertex collections, edge collections, and indexes for a tenant DB."""
    for name in VERTEX_COLLECTIONS:
        if not db.has_collection(name):
            db.create_collection(name)

    for name in EDGE_COLLECTIONS:
        if not db.has_collection(name):
            db.create_collection(name, edge=True)

    for collection_name, fields, unique in PERSISTENT_INDEXES:
        col = db.collection(collection_name)
        existing = col.indexes()
        already_exists = any(
            sorted(idx.get("fields", [])) == sorted(fields) and idx.get("type") == "persistent"
            for idx in existing
        )
        if not already_exists:
            col.add_index({"type": "persistent", "fields": fields, "unique": unique})
