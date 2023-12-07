from flask import Flask
from routes.blueprint import blueprint
from utils.globals import Base
from utils.queries import CREATE_ROLE_MANAGER_QUERY, CREATE_ROLE_EMPLOYEE_QUERY, \
    SET_RESOURCE_LIMIT_QUERY, SET_SESSION_CONTAINER_QUERY, \
    CREATE_PROFILE_MANAGER_QUERY, CREATE_PROFILE_EMPLOYEE_QUERY, \
    CREATE_TABLESPACE_QUERY, \
    DROP_PROFILE_MANAGER_QUERY, DROP_PROFILE_EMPLOYEE_QUERY, \
    DROP_ROLE_MANAGER_QUERY, DROP_ROLE_EMPLOYEE_QUERY, \
    DROP_TABLESPACE_MANAGER_QUERY, DROP_TABLESPACE_EMPLOYEE_QUERY

from database.oracle_db import OracleDb
# import all model to create table (must be imported)
from models.user_model import User
from sqlalchemy import text

def init_db():
    """
    Initialize the database tables, will create all table registered in database
    Create all oracle roles, profile, tablespaces
    """
    # 
    with OracleDb("sys", "123") as db:
        Base.metadata.create_all(db.engine)
        print(db) # print result of __repr__ method
        # check_role_manager_query = "SELECT * FROM dba_roles WHERE role = 'MANAGER'"
        # drop_role_admin_query = "DROP ROLE ADMIN"

        # TODO: always run drop role, profile, tablespace query
        # otherwise it will not set the container right, then the select dba tablespace return the wrong result
        db.conn.execute(text(SET_SESSION_CONTAINER_QUERY))
        # after we set container to FREEPDB1, the role name must not have C## prefixs, now we use freepdb, 
        # two try catch to make sure it run the later if the first fail, if there no role, profile, tablespace, we create them

        try:
            # drop all role, profile, tablespace then recreate
            db.conn.execute(text(DROP_TABLESPACE_MANAGER_QUERY))
            db.conn.execute(text(DROP_TABLESPACE_EMPLOYEE_QUERY))
            db.conn.execute(text(DROP_PROFILE_MANAGER_QUERY))
            db.conn.execute(text(DROP_PROFILE_EMPLOYEE_QUERY))
            db.conn.execute(text(DROP_ROLE_MANAGER_QUERY))
            db.conn.execute(text(DROP_ROLE_EMPLOYEE_QUERY))
            db.conn.commit()
        except Exception as e:
            print(e)
            
        try:
            db.conn.execute(text(SET_RESOURCE_LIMIT_QUERY))
            db.conn.execute(text(CREATE_PROFILE_MANAGER_QUERY))
            db.conn.execute(text(CREATE_PROFILE_EMPLOYEE_QUERY))
            db.conn.execute(text(CREATE_ROLE_MANAGER_QUERY))
            db.conn.execute(text(CREATE_ROLE_EMPLOYEE_QUERY))
            db.conn.execute(text(CREATE_TABLESPACE_QUERY.format(tablespace_name = "TBS_MANAGER")))
            db.conn.execute(text(CREATE_TABLESPACE_QUERY.format(tablespace_name = "TBS_EMPLOYEE")))
            db.conn.commit()
        except Exception as e:
            print(e)
            print("Error when create role, profile, tablespace, may be called the second time")
    print("Created all table in database")

def create_app():
    """
    Create and configure an instance of the Flask application. 
    Using app factory pattern. Will inintialize database tables
    """
    app = Flask(__name__)
    init_db()    
    return app

app = create_app()
app.secret_key = 'super secret key'
app.register_blueprint(blueprint)
if __name__ == "__main__":    
    app.run(port=5000, debug=True)
