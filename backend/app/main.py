from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.api.v1 import inventory, providers

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

# Routers registered here as modules are built
# from app.api.v1 import scans, findings, graph, compliance, auth
# app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
# app.include_router(scans.router, prefix="/api/v1/scans", tags=["scans"])
# app.include_router(findings.router, prefix="/api/v1/findings", tags=["findings"])
# app.include_router(graph.router, prefix="/api/v1/graph", tags=["graph"])
# app.include_router(compliance.router, prefix="/api/v1/compliance", tags=["compliance"])
