from sqlalchemy import text
from flask import render_template
from flask import request
from database.oracle_db import OracleDb
from services.user_service import add_user as srv_add_user
from services.user_service import check_user_not_exist as srv_check_user_not_exist
from services.user_service import add_user as srv_add_user
from utils.globals import authentication_check_decorator, authorization_check_decorator,\
            singleton_auth_manager, \
            DBA_ROLE_NAME, MANAGER_ROLE_NAME, EMPLOYEE_ROLE_NAME, \
            HASHED_METHOD
from utils.queries import SET_SESSION_CONTAINER_QUERY, \
            SELECT_USER_ROLE_QUERY, \
            SELECT_DBA_TABLESPACES_QUERY, \
            SELECT_DBA_PROFILES_QUERY
from werkzeug.security import generate_password_hash
def login():
    """Login to an existing user account."""    
    if request.method == 'GET' and singleton_auth_manager.is_logged_in == False:        
        return render_template('auth/login.html')
    else:
        if singleton_auth_manager.is_logged_in == True:
            print(singleton_auth_manager.db_instance.engine)
            return "User already logged in with connection: " + singleton_auth_manager.db_instance.__repr__()
        username = request.form.get('username')
        password = request.form.get('password')
        password_hashed = generate_password_hash(password, method=HASHED_METHOD)
        print("password:", password)
        print("Hashed password:", password_hashed)
        if username == "sys":
            singleton_auth_manager.login(username, password)
        else:
            singleton_auth_manager.login(username, password_hashed)
        singleton_auth_manager.db_instance.connect()
        with singleton_auth_manager.db_instance.engine.connect() as conn:
            role_result = conn.execute(text(SELECT_USER_ROLE_QUERY))
            for row in role_result:
                print("From singleton:", row[0])
                if row[0] == "DBA":
                    singleton_auth_manager.is_dba = True
                singleton_auth_manager.roles.append(row[0])
        return singleton_auth_manager.db_instance.__repr__() + " " + str(singleton_auth_manager.is_logged_in)
    
@authentication_check_decorator
def logout():
    """Logout from an existing user account."""
    singleton_auth_manager.logout()
    return "User Logged out"

@authentication_check_decorator
def get_user_accounts():
    """Get all user accounts."""
    from sqlalchemy import text
    with singleton_auth_manager.db_instance.engine.connect() as conn:
        result = conn.execute(text("SELECT * FROM dummy.user_account"))
        user_list = []
        for row in result:
            print(row)
            user_list.append(row)
        return "User accounts: " + str(user_list)

@authentication_check_decorator
def get_account_infos():
    """Get all account infos."""
    from sqlalchemy import text
    with singleton_auth_manager.db_instance.engine.connect() as conn:
        roles_result = conn.execute(text(SELECT_USER_ROLE_QUERY))
        role_privs_result = conn.execute(text("SELECT * FROM ROLE_ROLE_PRIVS WHERE ROLE = '{role}'"))
        account_sys_privs_without_role_result = conn.execute(text("SELECT PRIVILEGE FROM USER_SYS_PRIVS"))
        account_tab_privs_without_role_result = conn.execute(text("SELECT PRIVILEGE FROM USER_TAB_PRIVS"))
        account_role_list = []
        account_role_privs_list = []
        account_privs_without_role_list = []
        #can be made as functions and asynchronous
        for row in roles_result:
            print(row[0]) #type la str
            account_role_list.append(row[0])
        for row in role_privs_result:
            print(row)
            account_role_privs_list.append(row)

        for row in account_sys_privs_without_role_result:
            print(row[0])
            account_privs_without_role_list.append(row[0])
        for row in account_tab_privs_without_role_result:
            print(row[0])
            account_privs_without_role_list.append(row[0])
    return f"""
        Account role: " + {account_role_list}
        Account role privs: " + {account_role_privs_list}     
        Account privs without role: " + {account_privs_without_role_list}       
    """
