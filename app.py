from flask import Flask
from routes.blueprint import blueprint
from utils.globals import Base
from database.oracle_db import OracleDb
# import all model to create table (must be imported)
from models.user_model import User

def create_app():
    """
    Create and configure an instance of the Flask application. 
    Using app factory pattern. Will inintialize database tables
    """
    app = Flask(__name__)
    # will create all table registered in database
    with OracleDb("dummy", "dummy") as db:
        Base.metadata.create_all(db.engine)
        print(db) # print result of __repr__ method
    print("Created all table in database")
    return app

app = create_app()
app.register_blueprint(blueprint)
if __name__ == "__main__":
    app.run(port=5000, debug=True)
