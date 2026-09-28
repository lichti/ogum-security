from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import (
    attack_paths,
    compliance,
    findings,
    graph,
    iac_scans,
    identities,
    inventory,
    providers,
    scans,
    side_scans,
    views,
)
from app.api.v1 import dev as dev_module
from app.api.v1 import (
    settings as settings_api,
)
from app.api.v1.admin import jobs as admin_jobs
from app.api.v1.admin import tenants as admin_tenants
from app.core.config import settings
from app.core.middleware import TenantIdentityMiddleware

app = FastAPI(
    title="Ogum Security API",
    description="Open CNAPP — Built for Everyone",
    version="0.2.0",
    docs_url="/docs" if settings.APP_ENV != "production" else None,
    redoc_url="/redoc" if settings.APP_ENV != "production" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# US-06.09 — pass-through quando AUTH_ENABLED=false (dev); com true, exige
# Bearer em toda rota (menos /health, docs e webhooks de scanner) e resolve
# X-Tenant-ID/X-User-Id a partir do token verificado.
app.add_middleware(TenantIdentityMiddleware)


@app.get("/health", tags=["system"])
async def health() -> dict:
    return {"status": "ok", "version": "0.2.0"}


app.include_router(inventory.router)
app.include_router(identities.router)
app.include_router(providers.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(compliance.router)
app.include_router(iac_scans.router)
app.include_router(attack_paths.router)
app.include_router(graph.router)
app.include_router(side_scans.router)
app.include_router(admin_jobs.router)
app.include_router(admin_tenants.router)
app.include_router(views.router)
app.include_router(settings_api.router)
app.include_router(dev_module.router)  # endpoints return 404 unless DEV_MODE=true
