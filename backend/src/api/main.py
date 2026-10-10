from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config.settings import FRONTEND_ORIGIN, API_VERSION
from src.api.routers import tickets, alerts, stats, dashboard, system, users, auth

app = FastAPI(
    title="SOC AI Platform API",
    description="API du pipeline d'enrichissement et de qualification des alertes SOC",
    version=API_VERSION
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[FRONTEND_ORIGIN, "http://localhost:8501"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(system.router, prefix="/api")
app.include_router(tickets.router, prefix="/api")
app.include_router(alerts.router, prefix="/api")
app.include_router(stats.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(users.router, prefix="/api")
app.include_router(auth.router, prefix="/api")


@app.get("/")
def root():
    return {"status": "ok", "service": "SOC AI Platform API"}