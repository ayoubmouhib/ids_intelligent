from backend.app.db.database import Base, engine
from backend.app.models.alert import Alert


def init_db():

    Base.metadata.create_all(
        bind=engine
    )