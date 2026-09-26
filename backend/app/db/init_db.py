from backend.app.db.database import Base, engine
from backend.app.models.alert import Alert
from backend.app.models.network_event import NetworkEvent

def init_db():

    Base.metadata.create_all(
        bind=engine
    )
