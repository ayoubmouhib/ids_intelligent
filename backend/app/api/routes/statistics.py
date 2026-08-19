from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.app.db.database import get_db
from backend.app.services.statistics_service import get_statistics
from backend.app.schemas.statistics import StatisticsOut

router = APIRouter()

@router.get("/statistics", response_model=StatisticsOut)
def statistics(db: Session = Depends(get_db)):
    stats = get_statistics(db)
    return StatisticsOut(**stats)