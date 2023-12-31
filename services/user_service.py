from models.user_model import User
from database.oracle_db import OracleDb
from sqlalchemy.orm import Session
from sqlalchemy import text
from utils.queries import SET_SESSION_CONTAINER_QUERY
def add_user(username: str, password: str, tablespace_name: str, quota: int, profile_name: str, role_name: str):
    """Add a new user."""
    with OracleDb("sys", "123") as db:
        db.conn.execute(text(SET_SESSION_CONTAINER_QUERY))
        # identified by values to store hashed password
        # wrap username in "" to avoid error ORA-65094: invalid local user or role name, and user in pdb cannot have c## prefix
        print("Reduced length of password:", password[:25])
        create_user_query = f"""
            CREATE USER "U_{username.upper()}" IDENTIFIED BY "{password}"
            DEFAULT TABLESPACE {tablespace_name} QUOTA {quota}M ON {tablespace_name}
            PROFILE {profile_name}
        """
        from utils.globals import TEST_TABLE_NAME
        from random import randint
        random_salary = randint(1000, 10000)
        insert_user_test_table_query = f"INSERT INTO {TEST_TABLE_NAME} (name, salary) VALUES ('{username}', {random_salary})"
        grant_selected_role = f"GRANT {role_name} TO U_{username.upper()}"
        grant_connect_query = f"GRANT CREATE SESSION TO U_{username.upper()}"
        db.conn.execute(text(create_user_query))
        db.conn.execute(text(insert_user_test_table_query))
        db.conn.execute(text(grant_selected_role))
        db.conn.execute(text(grant_connect_query))
        db.conn.commit()
        print(f"Added a user {username}")

def delete_user(username:str):
    """Delete a user."""
    with OracleDb("sys", "123") as db:
        try:
            drop_user_query = f"DROP USER U_{username.upper()} CASCADE"
            db.conn.execute(text(drop_user_query))
            db.conn.commit()
            print("Deleted a user")
        except Exception as e:
            print(e)
            print("User not found")

def check_user_valid(username:str):
    """Check if a user is valid."""
    with OracleDb("sys", "123") as db:
        check_user_query = f"SELECT * FROM dba_users WHERE username = 'U_{username.upper()}'"
        result = db.conn.execute(text(check_user_query))
        print(result.fetchone())
        return result.fetchone() == None
    
def check_user_not_exist(username:str):
    """Check if a user is not exist."""
    with OracleDb("sys", "123") as db:
        check_user_query = f"SELECT * FROM dba_users WHERE username = 'U_{username.upper()}'"
        result = db.conn.execute(text(check_user_query))
        print(result.fetchone())
        return result.fetchone() == None

    