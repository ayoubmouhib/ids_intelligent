from fastapi import FastAPI

from backend.app.api.routes.prediction import router as prediction_router


app = FastAPI(
    title="Intelligent Intrusion Detection System",
    description="AI-powered network intrusion detection API",
    version="1.0.0",
)


@app.get("/health")
def health_check():

    return {
        "status": "healthy",
        "service": "IDS API",
    }


app.include_router(prediction_router)