from enum import Enum
from flask import redirect, render_template, url_for, flash
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text
from database.oracle_db import OracleDb
from utils.queries import SELECT_USER_ROLE_QUERY
from functools import wraps
class Base(DeclarativeBase):
    """sumary_line
    This is class represent a base class for all model. 
    And have singleton metadata holds all tables to create
    """
    pass

class AuthManager:
    db_instance = None
    is_logged_in = False
    roles = []
    is_dba = False
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
            self.roles = []
            self.is_dba = False
            print("User Logged out")
        else:
            print("User already logged out")

# singleton in module python: https://stackoverflow.com/questions/6760685/creating-a-singleton-in-python
singleton_auth_manager = AuthManager()

class AccountStatusEnum(Enum):
    OPEN = "OPEN"
    LOCKED = "LOCKED"
    
class SessionPerUserEnum(Enum):
    UNLIMITED = "UNLIMITED"
    DEFAULT = "DEFAULT"
    CUSTOM = "5"

class ConnectTimeEnum(Enum):
    UNLIMITED = "UNLIMITED"
    DEFAULT = "DEFAULT"
    CUSTOM = "60"

class IdleTimeEnum(Enum):
    UNLIMITED = "UNLIMITED"
    DEFAULT = "DEFAULT"
    CUSTOM = "30"

# named tuple user info
from collections import namedtuple
UserInfoOracle = namedtuple('UserInfoOracle', ['username', \
                                   'account_status', \
                                   'lock_date', \
                                   'created', \
                                   'default_tablespace', \
                                   'temporary_tablespace', \
                                   'profile', \
                                   'granted_role', \
                                   'admin_option'])

def authentication_check_decorator(func):
    """sumary_line
    Decorator to check if user logged in or not
    """
    @wraps(func) # this to keep the original function name and doc
    def wrapper(*args, **kwargs):
        if singleton_auth_manager.is_logged_in == True:
            return func(*args, **kwargs)
        else:
            flash("User not logged in", "error")
            return redirect(url_for('blueprint.login'))
            
        
    return wrapper

def authorization_check_decorator(role_names:list):
    """sumary_line
    Decorator to check if user have enough role to access the function
    """
    def outer_wrapper(func):
        @wraps(func) # this to keep the original function name and doc
        def wrapper(*args, **kwargs):
            for role in singleton_auth_manager.roles:
                if role in role_names:
                    return func(*args, **kwargs)
            else:
                return render_template('/user/page_404.html'\
                                       , continue_url=url_for('blueprint.index')\
                                       , error="Access control failed, user does not have privileges to access this page"
                                    )
        return wrapper
            
        
    return outer_wrapper
            
DBA_ROLE_NAME = "DBA"
MANAGER_ROLE_NAME = "R_MANAGER"
EMPLOYEE_ROLE_NAME = "R_EMPLOYEE"
HASHED_METHOD = "pbkdf2:sha256"
TEST_TABLE_NAME = "DUMMY.USER_ACCOUNT"