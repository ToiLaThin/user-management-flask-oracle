from sqlalchemy.orm import DeclarativeBase
from database.oracle_db import OracleDb
class Base(DeclarativeBase):
    """sumary_line
    This is class represent a base class for all model. 
    And have singleton metadata holds all tables to create
    """
    pass

class AuthManager:
    db_instance = None
    is_logged_in = False
    def login(self, username, password):
        """sumary_line
        Login to an existing user account.
        """
        if self.is_logged_in == False:
            self.is_logged_in = True
            self.db_instance = OracleDb(username, password)
            print("User Logged in")
        else:
            print("User already logged in")

    def logout(self):
        """sumary_line
        Logout from an existing user account.
        """
        if self.is_logged_in == True:
            self.is_logged_in = False
            self.db_instance = None
            print("User Logged out")
        else:
            print("User already logged out")

# singleton in module python: https://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
singleton_auth_manager = AuthManager()