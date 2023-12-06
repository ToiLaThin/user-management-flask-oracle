from models.user_model import User
from database.oracle_db import OracleDb
from sqlalchemy.orm import Session
from sqlalchemy import text
def add_user(username: str, password: str):
    """Add a new user."""
    with OracleDb("sys", "123") as db:
        create_user_query = f"CREATE USER C##{username.upper()} IDENTIFIED BY {password}"
        grant_connect_query = f"GRANT CREATE SESSION TO C##{username.upper()}"
        db.conn.execute(text(create_user_query))
        db.conn.execute(text(grant_connect_query))
        db.conn.commit()
        print(f"Added a user {username}")

def delete_user(username:str):
    """Delete a user."""
    with OracleDb("sys", "123") as db:
        try:
            drop_user_query = f"DROP USER C##{username.upper()} CASCADE"
            db.conn.execute(text(drop_user_query))
            db.conn.commit()
            print("Deleted a user")
        except Exception as e:
            print(e)
            print("User not found")

def check_user_valid(username:str):
    """Check if a user is valid."""
    with OracleDb("sys", "123") as db:
        check_user_query = f"SELECT * FROM dba_users WHERE username = 'C##{username.upper()}'"
        result = db.conn.execute(text(check_user_query))
        print(result.fetchone())
        return result.fetchone() == None
    
def check_user_not_exist(username:str):
    """Check if a user is not exist."""
    with OracleDb("sys", "123") as db:
        check_user_query = f"SELECT * FROM dba_users WHERE username = 'C##{username.upper()}'"
        result = db.conn.execute(text(check_user_query))
        print(result.fetchone())
        return result.fetchone() == None

    