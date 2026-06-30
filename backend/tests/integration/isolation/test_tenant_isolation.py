"""
Tenant isolation tests — security-critical, always run in CI.

These tests verify that ArangoDB per-tenant database isolation prevents
any data leakage between tenants, even under buggy query conditions.
A failure here blocks the PR unconditionally.
"""
import pytest
from arango.database import StandardDatabase as ArangoDatabase

from app.db.init import init_tenant_schema
from tests.conftest import TEST_TENANT_A


@pytest.mark.integration
@pytest.mark.security
class TestTenantDatabaseIsolation:
    """Physical isolation: separate databases prevent cross-tenant data access."""

    def test_tenant_databases_are_distinct(
        self,
        db_tenant_a: ArangoDatabase,
        db_tenant_b: ArangoDatabase,
    ) -> None:
        db_tenant_a.create_collection("resources")
        db_tenant_a.collection("resources").insert({"_key": "ec2-001", "owner": TEST_TENANT_A})

        # Tenant B's database starts empty — a separate database, not a filtered view
        assert not db_tenant_b.has_collection("resources") or \
               db_tenant_b.collection("resources").count() == 0

    def test_cross_tenant_data_never_visible(
        self,
        db_tenant_a: ArangoDatabase,
        db_tenant_b: ArangoDatabase,
    ) -> None:
        db_tenant_a.create_collection("findings")
        db_tenant_a.collection("findings").insert({
            "_key": "finding-001",
            "severity": "CRITICAL",
            "resource_arn": "arn:aws:iam::111111111111:role/AdminRole",
        })

        db_tenant_b.create_collection("findings")
        assert db_tenant_b.collection("findings").count() == 0, \
            "Tenant B must never see Tenant A's findings"

    def test_write_to_tenant_b_does_not_affect_tenant_a(
        self,
        db_tenant_a: ArangoDatabase,
        db_tenant_b: ArangoDatabase,
    ) -> None:
        db_tenant_a.create_collection("identities")
        db_tenant_a.collection("identities").insert({"_key": "role-admin"})

        db_tenant_b.create_collection("identities")
        db_tenant_b.collection("identities").insert({"_key": "role-readonly"})

        # Tenant A's collection must still have exactly 1 document
        assert db_tenant_a.collection("identities").count() == 1

    def test_aql_traversal_confined_to_tenant_database(
        self,
        db_tenant_a: ArangoDatabase,
        db_tenant_b: ArangoDatabase,
    ) -> None:
        """An AQL query on Tenant B's DB must not reach Tenant A's graph."""
        db_tenant_a.create_collection("resources")
        db_tenant_a.create_collection("belongs_to", edge=True)
        db_tenant_a.collection("resources").insert({"_key": "s3-secret-bucket"})

        db_tenant_b.create_collection("resources")
        db_tenant_b.create_collection("belongs_to", edge=True)

        cursor = db_tenant_b.aql.execute(
            "FOR v IN resources RETURN v._key"
        )
        keys = list(cursor)
        assert "s3-secret-bucket" not in keys, \
            "AQL traversal on Tenant B's graph must not reach Tenant A's resources"


@pytest.mark.integration
@pytest.mark.security
class TestProviderConfigIsolation:
    """Provider configurations must never leak between tenants."""

    def test_provider_config_in_tenant_a_not_visible_in_tenant_b(
        self,
        db_tenant_a: ArangoDatabase,
        db_tenant_b: ArangoDatabase,
    ) -> None:
        init_tenant_schema(db_tenant_a)
        init_tenant_schema(db_tenant_b)

        db_tenant_a.collection("tenant_config").insert({
            "_key": "aws-111111111111",
            "provider": "aws",
            "account_id": "111111111111",
            "display_name": "Secret Account",
        })

        count = (
            db_tenant_b.collection("tenant_config").count()
            if db_tenant_b.has_collection("tenant_config")
            else 0
        )
        assert count == 0, "Tenant B must not see Tenant A's provider configs"

    def test_resource_data_does_not_cross_tenant_boundary(
        self,
        db_tenant_a: ArangoDatabase,
        db_tenant_b: ArangoDatabase,
    ) -> None:
        """AQL query on Tenant B's database must not return Tenant A's resources."""
        init_tenant_schema(db_tenant_a)
        init_tenant_schema(db_tenant_b)

        db_tenant_a.collection("resources").insert({
            "_key": "aws_ec2_instance_i-secret",
            "tenant_id": TEST_TENANT_A,
            "name": "secret-server",
            "provider": "aws",
            "resource_type": "ec2_instance",
            "status": "active",
        })

        result = list(db_tenant_b.aql.execute(
            "FOR r IN resources FILTER r.tenant_id == @tid RETURN r",
            bind_vars={"tid": TEST_TENANT_A},
        ))
        assert result == [], "Tenant B's AQL must return zero rows from Tenant A's namespace"


@pytest.mark.integration
@pytest.mark.security
class TestTenantProvisioningCleanup:
    """Verify that tenant database provisioning is idempotent and isolated."""

    def test_empty_database_on_first_provision(
        self,
        db_tenant_a: ArangoDatabase,
    ) -> None:
        collections = [c for c in db_tenant_a.collections() if not c["name"].startswith("_")]
        assert len(collections) == 0, \
            "Freshly provisioned tenant database must have no user collections"
