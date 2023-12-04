from models.user_model import User
from database.oracle_db import OracleDb
from sqlalchemy.orm import Session
def add_user():
    """Add a new user."""
    with OracleDb("dummy", "dummy") as db:
        with Session(db.engine) as db_session:
            db_session.add(User(name="test", fullname="test fullname"))
            db_session.commit()
        print("Added a new user")


    