from flask import Flask
from routes.blueprint import blueprint
from utils.globals import Base, singleton_auth_manager
from utils.queries import CREATE_ROLE_MANAGER_QUERY, CREATE_ROLE_EMPLOYEE_QUERY, \
    SET_RESOURCE_LIMIT_QUERY, SET_SESSION_CONTAINER_QUERY, \
    CREATE_PROFILE_MANAGER_QUERY, CREATE_PROFILE_EMPLOYEE_QUERY, \
    CREATE_TABLESPACE_QUERY, \
    DROP_PROFILE_MANAGER_QUERY, DROP_PROFILE_EMPLOYEE_QUERY, \
    DROP_ROLE_MANAGER_QUERY, DROP_ROLE_EMPLOYEE_QUERY, \
    DROP_TABLESPACE_MANAGER_QUERY, DROP_TABLESPACE_EMPLOYEE_QUERY

from utils.globals import IdleTimeEnum, ConnectTimeEnum, SessionPerUserEnum
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
        print(db) # print result of __repr__ method

        # TODO: always run drop role, profile, tablespace query
        # otherwise it will not set the container right, then the select dba tablespace return the wrong result
        db.conn.execute(text(SET_SESSION_CONTAINER_QUERY))
        # after we set container to FREEPDB1, the role name must not have C## prefixs, now we use freepdb, 
        # two try catch to make sure it run the later if the first fail, if there no role, profile, tablespace, we create them

        # try:
        #     # drop all role, profile, tablespace then recreate
        #     db.conn.execute(text(DROP_TABLESPACE_MANAGER_QUERY))
        #     db.conn.execute(text(DROP_TABLESPACE_EMPLOYEE_QUERY))
        #     db.conn.execute(text(DROP_PROFILE_MANAGER_QUERY))
        #     db.conn.execute(text(DROP_PROFILE_EMPLOYEE_QUERY))
        #     db.conn.execute(text(DROP_ROLE_MANAGER_QUERY))
        #     db.conn.execute(text(DROP_ROLE_EMPLOYEE_QUERY))
        #     db.conn.commit()
        # except Exception as e:
        #     print(e)
            
        try:
            db.conn.execute(text(SET_RESOURCE_LIMIT_QUERY))
            db.conn.execute(text(CREATE_PROFILE_MANAGER_QUERY.format(session_per_user = SessionPerUserEnum.CUSTOM.value,\
                                                                     connect_time = ConnectTimeEnum.CUSTOM.value, \
                                                                     idle_time = IdleTimeEnum.CUSTOM.value)))
            db.conn.execute(text(CREATE_PROFILE_EMPLOYEE_QUERY.format(session_per_user = SessionPerUserEnum.CUSTOM.value,\
                                                                     connect_time = ConnectTimeEnum.CUSTOM.value, \
                                                                     idle_time = IdleTimeEnum.CUSTOM.value)))
            db.conn.execute(text(CREATE_ROLE_MANAGER_QUERY))
            db.conn.execute(text(CREATE_ROLE_EMPLOYEE_QUERY))
            db.conn.execute(text(CREATE_TABLESPACE_QUERY.format(tablespace_name = "TBS_MANAGER")))
            db.conn.execute(text(CREATE_TABLESPACE_QUERY.format(tablespace_name = "TBS_EMPLOYEE")))            
            db.conn.commit()
        except Exception as e:
            print(e)
            print("Error when create role, profile, tablespace, may be called the second time")

        try:
            db.conn.execute(text("CREATE USER dummy IDENTIFIED BY dummy"))
            db.conn.execute(text("GRANT CREATE SESSION TO dummy"))
            db.conn.execute(text("ALTER USER dummy QUOTA 10M ON users"))
            db.conn.execute(text("GRANT CREATE TABLE TO dummy"))
            db.conn.execute(text("GRANT CREATE SEQUENCE TO dummy"))
            db.conn.commit()
        except Exception as e:
            print(e)
            print("Error when create dummy user, may be called the second time")

    with OracleDb("dummy", "dummy") as db:
        try:      
            db.conn.execute(text(SET_SESSION_CONTAINER_QUERY))      
            Base.metadata.create_all(db.engine)
        except Exception as e:
            print(e)
            print("Error when create all table, may be called the second time")
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

@app.context_processor
def inject_auth_manager_to_template_preprocessor():
    """sumary_line
    Decorator to inject auth manager to template for every request
    """
    return dict(auth_manager=singleton_auth_manager)

if __name__ == "__main__":    
    app.run(port=5000, debug=True)
