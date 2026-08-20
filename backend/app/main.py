from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.api.routes.alerts import router as alerts
from backend.app.api.routes.prediction import router as prediction_router
from backend.app.api.routes.statistics import router as statistics
from backend.app.db.init_db import init_db


app = FastAPI(
    title="Intelligent Intrusion Detection System",
    description="AI-powered network intrusion detection API",
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

@app.on_event("startup")
def startup():
    init_db()


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "IDS API",
    }


# ============================================================
# ROUTES
# ============================================================

app.include_router(prediction_router)
app.include_router(alerts)
app.include_router(statistics)
