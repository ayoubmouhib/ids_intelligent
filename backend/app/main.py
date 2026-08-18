from fastapi import FastAPI

from backend.app.api.routes.prediction import router as prediction_router
from backend.app.db.init_db import init_db

app = FastAPI(
    title="Intelligent Intrusion Detection System",
    description="AI-powered network intrusion detection API",
    version="1.0.0",
)

@app.on_event("startup")
def startup():

    init_db()


@app.get("/health")
def health_check():

    return {
        "status": "healthy",
        "service": "IDS API",
    }


app.include_router(prediction_router)