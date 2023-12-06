from flask import render_template
from flask import request
from services.user_service import add_user as srv_add_user
from services.user_service import check_user_valid as srv_check_user_valid
from services.user_service import check_user_not_exist as srv_check_user_not_exist
from services.user_service import delete_user as srv_delete_user
from services.user_service import add_user as srv_add_user
from utils.globals import singleton_auth_manager

def create_account():
    """Create a new user account."""
    if request.method == 'GET':
        return render_template('auth/create_account.html')
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        if srv_check_user_not_exist(username) == True:
            srv_add_user(username, password)
            return "created_account, please check database"
        else:
            return f"user {username} is already exist"

def delete_account():    
    """Delete an existing user account."""
    if request.method == 'GET':
        return render_template('auth/delete_account.html')
    else:
        username = request.form.get('username')
        if srv_check_user_valid(username) == True:
            print(f"user {username} is valid")
            srv_delete_user(username)
        return "account deleted"

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
        singleton_auth_manager.login(username, password)
        singleton_auth_manager.db_instance.connect()
        return singleton_auth_manager.db_instance.__repr__() + " " + str(singleton_auth_manager.is_logged_in)
    
def logout():
    """Logout from an existing user account."""
    if singleton_auth_manager.is_logged_in == True:
        singleton_auth_manager.logout()
        return "User Logged out"
    else:
        return "User not logged in"

def get_user_accounts():
    """Get all user accounts."""
    if singleton_auth_manager.is_logged_in == False:
        return "Not logged in"
    else:
        from sqlalchemy import text
        with singleton_auth_manager.db_instance.engine.connect() as conn:
            result = conn.execute(text("SELECT * FROM dummy.user_account"))
            user_list = []
            for row in result:
                print(row)
                user_list.append(row)
            return "User accounts: " + str(user_list)


def get_account_infos():
    """Get all account infos."""
    if singleton_auth_manager.is_logged_in == False:
        return "Not logged in"
    else:
        from sqlalchemy import text
        with singleton_auth_manager.db_instance.engine.connect() as conn:

            roles_result = conn.execute(text("SELECT GRANTED_ROLE FROM USER_ROLE_PRIVS"))
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
