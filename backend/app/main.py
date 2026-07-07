from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import attack_paths, compliance, findings, iac_scans, inventory, providers, scans
from app.api.v1 import dev as dev_module
from app.api.v1.admin import jobs as admin_jobs
from app.core.config import settings

app = FastAPI(
    title="Ogum Security API",
    description="Open CNAPP — Built for Everyone",
    version="0.1.0",
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


@app.get("/health", tags=["system"])
async def health() -> dict:
    return {"status": "ok", "version": "0.1.0"}


app.include_router(inventory.router)
app.include_router(providers.router)
app.include_router(scans.router)
app.include_router(findings.router)
app.include_router(compliance.router)
app.include_router(iac_scans.router)
app.include_router(attack_paths.router)
app.include_router(admin_jobs.router)
app.include_router(dev_module.router)  # endpoints return 404 unless DEV_MODE=true
