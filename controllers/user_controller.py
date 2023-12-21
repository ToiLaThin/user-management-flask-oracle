from sqlalchemy import text
from flask import flash, render_template, url_for
from flask import request
from database.oracle_db import OracleDb
from services.user_service import add_user as srv_add_user
from services.user_service import check_user_not_exist as srv_check_user_not_exist
from services.user_service import add_user as srv_add_user
from utils.globals import authentication_check_decorator, authorization_check_decorator,\
            singleton_auth_manager, \
            MANAGER_ROLE_NAME, EMPLOYEE_ROLE_NAME, \
            HASHED_METHOD
from utils.queries import SELECT_USER_ROLE_QUERY
from werkzeug.security import generate_password_hash

def index():
    """Entry point to the app depend on the auth manager state"""
    if singleton_auth_manager.is_logged_in == True:
        if singleton_auth_manager.is_dba == True:
            return redirect(url_for('blueprint.list_users'))
        else:
            return redirect(url_for('blueprint.user_account_list'))
    else:
        return redirect(url_for('blueprint.login'))    

def login():
    """Login to an existing user account."""    
    if request.method == 'GET' and singleton_auth_manager.is_logged_in == False:        
        return render_template('auth/login.html')
    else:
        if singleton_auth_manager.is_logged_in == True:
            print(singleton_auth_manager.db_instance.engine)
            flash("User already logged in with connection: " + singleton_auth_manager.db_instance.__repr__())
            return redirect(url_for('blueprint.index'))
        username = request.form.get('username')
        password = request.form.get('password')
        password_hashed = generate_password_hash(password, method=HASHED_METHOD)
        print("Password:", password)
        print("Hashed password:", password_hashed)

        
        if username == "sys":
            singleton_auth_manager.login(username, password)
        else:
            #can be changed to password_hashed to see it fail
            singleton_auth_manager.login(username, password)
        
                
        try: #if login failed , do not set the db_instance
            singleton_auth_manager.db_instance.connect() 
        except Exception as e:
            singleton_auth_manager.logout()
            return render_template('/user/page_404.html', error=str(e), continue_url=url_for('blueprint.index'))
        
        with singleton_auth_manager.db_instance.engine.connect(): #login success
            role_result = singleton_auth_manager.db_instance.conn.execute(text(SELECT_USER_ROLE_QUERY))
            for row in role_result:
                print("From singleton:", row[0])
                if row[0] == "DBA":
                    singleton_auth_manager.is_dba = True
                singleton_auth_manager.roles.append(row[0])
        flash(f"Logged in successfully with conn: {singleton_auth_manager.db_instance.__repr__() + str(singleton_auth_manager.is_logged_in)}", "success")
        return redirect(url_for('blueprint.index'), code=301) # 301 is for redirect permanently, 302 is for redirect temporarily, 301 we can redirect from get to post method
    
@authentication_check_decorator
def logout():
    """Logout from an existing user account."""
    singleton_auth_manager.logout()
    flash("Logged out successfully.", "success")
    return redirect(url_for('blueprint.index'))

@authentication_check_decorator
def get_account_infos():
    """Get all account infos."""
    from sqlalchemy import text

    username = singleton_auth_manager.db_instance.username
    username = 'U_' + username.upper()

    userrole = singleton_auth_manager.roles[0]
    print("From get account info:", userrole)
    query_user_privs_sys = f"SELECT PRIVILEGE FROM USER_SYS_PRIVS"
    # select from user_tab_privs return not wanted priv, so use dba_tab_privs instead
    query_user_privs_tab = f"SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE = '{username}'"
    query_role_privs_sys = f"SELECT PRIVILEGE FROM DBA_SYS_PRIVS WHERE GRANTEE = '{userrole}'"
    query_role_privs_tab = f"SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE = '{userrole}'"    
    query_session_roles = f"SELECT ROLE FROM SESSION_ROLES"
    query_session_privs = f"SELECT PRIVILEGE FROM SESSION_PRIVS"
    query_tbs_quota = f"SELECT TABLESPACE_NAME, BYTES FROM USER_TS_QUOTAS"
    query_profile_name = f"SELECT PROFILE FROM DBA_USERS WHERE USERNAME = '{username}'"
    query_profile_info = """SELECT * FROM DBA_PROFILES WHERE PROFILE = '{profile_name}'"""
    query_check_role_have_password = f"SELECT PASSWORD_REQUIRED FROM DBA_ROLES WHERE ROLE = '{userrole}'"
    role_is_enabled = False
    role_have_password = False

    session_privs_list = []
    account_role_list = []  
    account_role_privs_list = []
    account_privs_without_role_list = []
    profile_info_dict = {}

    

    with OracleDb('sys', '123') as db:
        #must use sys to get all privs
        account_tab_privs_without_role_result = db.conn.execute(text(query_user_privs_tab))
        role_sys_privs_result = db.conn.execute(text(query_role_privs_sys))
        role_tab_privs_result = db.conn.execute(text(query_role_privs_tab))        
        profile_name_result = db.conn.execute(text(query_profile_name)).fetchone()
        profile_name = profile_name_result[0]
        profile_info_result = db.conn.execute(text(query_profile_info.format(profile_name=profile_name)))
                
        for row in profile_info_result:
            resource_name = row[1]
            limit_value = row[2]
            profile_info_dict[resource_name] = limit_value

        role_have_password_result = db.conn.execute(text(query_check_role_have_password)).fetchone()
        if role_have_password_result[0] == 'YES':
            role_have_password = True
        else:
            role_have_password = False

        
        # if connection close (out of with), the result(cursor) will be gone, 
        # so these must be done inside with
        for row in role_sys_privs_result:
            # print("From get account info:", row)
            privilege = row[0]
            account_role_privs_list.append(privilege)

        for row in role_tab_privs_result:
            # print("From get account info:", row)
            privilege = row[0]
            account_role_privs_list.append(privilege)

        for row in account_tab_privs_without_role_result:
            # print("From get account info:", row[0])
            privilege_without_role = row[0]
            account_privs_without_role_list.append(privilege_without_role)

        

    with singleton_auth_manager.db_instance.engine.connect() as conn:
        roles_result = conn.execute(text(SELECT_USER_ROLE_QUERY))
        account_sys_privs_without_role_result = conn.execute(text(query_user_privs_sys))
        account_session_roles_result = conn.execute(text(query_session_roles))
        account_session_privs_result = conn.execute(text(query_session_privs))

        #can be made as functions and asynchronous
        for row in roles_result:
            # print("From get account info:", row[0]) #type la str
            account_role_list.append(row[0])

        for row in account_sys_privs_without_role_result:
            # print("From get account info:", row[0])
            privilege_without_role = row[0]
            account_privs_without_role_list.append(privilege_without_role)

        for row in account_session_roles_result:
            if row[0] == userrole:
                role_is_enabled = True
                break
        
        for row in account_session_privs_result:
            session_priv = row[0]
            print("From get account info:", session_priv)
            session_privs_list.append(session_priv)

        # when fetch one, result is a iterable object, so we can use iterator to get value
        # each iter is a col, not a row
        tbs_quota_result = conn.execute(text(query_tbs_quota)).fetchone()
        iterator = tbs_quota_result.__iter__()
        tbs_name = iterator.__next__()
        tbs_quota = iterator.__next__()


    return render_template('user/user_account_infos.html', \
                            account_role_list=account_role_list, \
                            account_role_privs_list=account_role_privs_list, \
                            account_privs_without_role_list=account_privs_without_role_list, \
                            session_privs_list=session_privs_list, \
                            role_is_enabled=role_is_enabled, \
                            role_have_password=role_have_password, \
                            profile_info_dict=profile_info_dict, \
                            profile_name=profile_name, \
                            tbs_name=tbs_name, tbs_quota=tbs_quota)

from utils.globals import TEST_TABLE_NAME
@authentication_check_decorator
@authorization_check_decorator([EMPLOYEE_ROLE_NAME, MANAGER_ROLE_NAME])
def user_account_list():
    """Get all user accounts."""
    with singleton_auth_manager.db_instance.engine.connect() as conn:
        try:
            result = conn.execute(text(f"SELECT * FROM {TEST_TABLE_NAME}"))
            user_account_tuple_list = []
            for row in result:
                print(row)
                user_account_tuple_list.append(row)
        except Exception as e:
            return render_template('/user/page_404.html', error=str(e), continue_url=url_for('blueprint.index'))
        return render_template('user/user_account_list.html', user_account_tuple_list=user_account_tuple_list)
    
from flask import redirect, url_for
@authentication_check_decorator
# sys have both of these roles so sys can also create user or delete user
@authorization_check_decorator([EMPLOYEE_ROLE_NAME, MANAGER_ROLE_NAME])
def user_account_create():
    """Add a new user account."""
    if request.method == 'GET':
        return render_template('user/user_account_create.html')
    else:
        from random import randint
        username = request.form.get('username')
        random_salary = randint(1000, 10000)
        insert_user_test_table_query = f"INSERT INTO {TEST_TABLE_NAME} (name, salary) VALUES ('{username}', {random_salary})"
        with singleton_auth_manager.db_instance.engine.connect() as conn:
            try:
                conn.execute(text(insert_user_test_table_query))
                conn.commit()
            except Exception as e:
                return render_template('/user/page_404.html', error=str(e), continue_url=url_for('blueprint.index'))
        return redirect(url_for('blueprint.user_account_list'))
    
@authentication_check_decorator
@authorization_check_decorator([EMPLOYEE_ROLE_NAME, MANAGER_ROLE_NAME])
def user_account_delete(userid):
    """Delete an existing user account."""
    delete_user_test_table_query = f"DELETE FROM {TEST_TABLE_NAME} WHERE id = {userid}"
    with singleton_auth_manager.db_instance.engine.connect() as conn:
        try:
            conn.execute(text(delete_user_test_table_query))
            conn.commit()
        except Exception as e:
            return render_template('/user/page_404.html', error=str(e), continue_url=url_for('blueprint.index'))
    return redirect(url_for('blueprint.user_account_list'))

@authentication_check_decorator
@authorization_check_decorator([EMPLOYEE_ROLE_NAME, MANAGER_ROLE_NAME])
def grant_privs_user_list():
    """Get all user accounts."""
    with OracleDb('sys', '123') as db:
        try:
            # have username since we have authen checked
            transformed_logged_in_username = "U_" + singleton_auth_manager.db_instance.username.upper()
            username_result = db.conn.execute(text(f"SELECT USERNAME FROM DBA_USERS WHERE REGEXP_LIKE (USERNAME ,'^U_.*$') AND USERNAME != '{transformed_logged_in_username}'"))
            sys_privs_current_logged_in_user_can_grant_result = db.conn.execute(text(f"SELECT * FROM DBA_SYS_PRIVS WHERE GRANTEE = '{transformed_logged_in_username}' AND ADMIN_OPTION = 'YES'"))
            tab_privs_current_logged_in_user_can_grant_result = db.conn.execute(text(f"SELECT * FROM DBA_TAB_PRIVS WHERE GRANTEE = '{transformed_logged_in_username}' AND GRANTABLE = 'YES'"))

            sys_privs_current_logged_in_user_can_grant_list = []
            tab_privs_current_logged_in_user_can_grant_list = []

            for row in sys_privs_current_logged_in_user_can_grant_result:
                spriv = row[1]
                sys_privs_current_logged_in_user_can_grant_list.append(spriv)
            for row in tab_privs_current_logged_in_user_can_grant_result:
                # ALL ARE UPPER CASE ALREADY
                tpriv = row[4]
                owner = row[1]
                table_name = row[2]
                full_tab_priv_name = tpriv + " ON " + owner + "." + table_name
                tab_privs_current_logged_in_user_can_grant_list.append(full_tab_priv_name)

            username_list = []
            for row in username_result:
                uname = row[0]
                print(uname)
                username_list.append(uname)

        except Exception as e:
            return render_template('/user/page_404.html', error=str(e), continue_url=url_for('blueprint.index'))
        print(sys_privs_current_logged_in_user_can_grant_list)
        print(tab_privs_current_logged_in_user_can_grant_list)
        return render_template('user/grant_privs_user_list.html', username_list=username_list, \
                               sys_privs_current_logged_in_user_can_grant_list=sys_privs_current_logged_in_user_can_grant_list, \
                               tab_privs_current_logged_in_user_can_grant_list=tab_privs_current_logged_in_user_can_grant_list,
                               grantor=transformed_logged_in_username)
    
@authentication_check_decorator
@authorization_check_decorator([EMPLOYEE_ROLE_NAME, MANAGER_ROLE_NAME])
def grant_priv_user_detail(grantor:str, grantee:str):
    with OracleDb('sys', '123') as db:
        try:
            # it 's a little weird that grantee = grantor, but 's the curr logged in user is the grantor, in the db it's still the grantee column
            sys_privs_current_logged_in_user_can_grant_result = db.conn.execute(text(f"SELECT * FROM DBA_SYS_PRIVS WHERE GRANTEE = '{grantor}' AND ADMIN_OPTION = 'YES'"))
            tab_privs_current_logged_in_user_can_grant_result = db.conn.execute(text(f"SELECT * FROM DBA_TAB_PRIVS WHERE GRANTEE = '{grantor}' AND GRANTABLE = 'YES'"))
            grantee_sys_privs_granted_result = db.conn.execute(text(f"SELECT * FROM DBA_SYS_PRIVS WHERE GRANTEE = '{grantee}'"))
            grantee_tab_privs_granted_result = db.conn.execute(text(f"SELECT * FROM DBA_TAB_PRIVS WHERE GRANTEE = '{grantee}'"))

            sys_privs_current_logged_in_user_can_grant_list = []
            tab_privs_current_logged_in_user_can_grant_list = []
            grantee_sys_privs_granted_list = []
            grantee_tab_privs_granted_list = []
            grantee_tab_privs_not_granted_list = []
            grantee_sys_privs_not_granted_list = []

            priv_with_grant_option_lookup_dict = {}
            for row in grantee_sys_privs_granted_result:
                spriv = row[1]
                admin_option = row[2]
                grantee_sys_privs_granted_list.append(spriv)
                priv_with_grant_option_lookup_dict[spriv] = admin_option
                
            for row in grantee_tab_privs_granted_result:
                # ALL ARE UPPER CASE ALREADY
                tpriv = row[4]
                owner = row[1]
                table_name = row[2]
                full_tab_priv_name = tpriv + " ON " + owner + "." + table_name
                grantable = row[5]
                grantee_tab_privs_granted_list.append(full_tab_priv_name)
                priv_with_grant_option_lookup_dict[full_tab_priv_name] = grantable

            for row in sys_privs_current_logged_in_user_can_grant_result:
                spriv = row[1]
                sys_privs_current_logged_in_user_can_grant_list.append(spriv)

            for row in tab_privs_current_logged_in_user_can_grant_result:
                # ALL ARE UPPER CASE ALREADY
                tpriv = row[4]
                owner = row[1]
                table_name = row[2]
                full_tab_priv_name = tpriv + " ON " + owner + "." + table_name
                tab_privs_current_logged_in_user_can_grant_list.append(full_tab_priv_name)

        except Exception as e:
            return render_template('/user/page_404.html', error=str(e), continue_url=url_for('blueprint.index'))
        
        grantee_sys_privs_not_granted_list = [spriv for spriv in sys_privs_current_logged_in_user_can_grant_list \
                                                if spriv not in priv_with_grant_option_lookup_dict]
        grantee_tab_privs_not_granted_list = [tpriv for tpriv in tab_privs_current_logged_in_user_can_grant_list \
                                                if tpriv not in priv_with_grant_option_lookup_dict]
        print(sys_privs_current_logged_in_user_can_grant_list)
        print(tab_privs_current_logged_in_user_can_grant_list)
        print(grantee_sys_privs_granted_list)
        print(grantee_tab_privs_granted_list)
        print(grantee_sys_privs_not_granted_list)
        print(grantee_tab_privs_not_granted_list)
        return render_template('user/grant_priv_user_detail.html', \
                               grantee_sys_privs_granted_list=grantee_sys_privs_granted_list, \
                               grantee_tab_privs_granted_list=grantee_tab_privs_granted_list, \
                               grantee_sys_privs_not_granted_list=grantee_sys_privs_not_granted_list, \
                               grantee_tab_privs_not_granted_list=grantee_tab_privs_not_granted_list, \
                               priv_with_grant_option_lookup_dict=priv_with_grant_option_lookup_dict, \
                               grantor=grantor, grantee=grantee)
    
@authentication_check_decorator
@authorization_check_decorator([EMPLOYEE_ROLE_NAME, MANAGER_ROLE_NAME])
def grant_priv_user_update():
    """
    Revoke all privs of a user account, both tab and sys privs. 
    Then grant all checked privs via AJAX (for grantor to be current logged in user
    we must use the conn in singleton_auth_manager.db_instance.conn)
    """
    username = request.json['username'] # this username already has U_ prefix
    username:str = username[2:]
    all_checked_privs = request.json['all_checked_privs']
    all_checked_privs_with_grant_option = request.json['all_checked_privs_with_grant_option']
    print(all_checked_privs)
    print(all_checked_privs_with_grant_option)

    from utils.queries import GRANT_ALL_PRIVS_TO_USER_QUERY, REVOKE_ALL_PRIVS_FR_USER_QUERY, GRANT_PRIV_TO_USER_QUERY
    from utils.globals import ALL_SYS_PRIVS
    with OracleDb('sys', '123') as db: # This to avoid current logged in user not have enough privs to grant all privs
        db.conn.execute(text(GRANT_ALL_PRIVS_TO_USER_QUERY.format(username=username.upper()))) # to avoid err: ORA-01952: system privileges not granted to 'U_THINH'
        db.conn.execute(text(REVOKE_ALL_PRIVS_FR_USER_QUERY.format(
            username=username.upper()
        )))
        db.conn.commit()   
    for priv in all_checked_privs:
        if priv in all_checked_privs_with_grant_option:
            if priv in ALL_SYS_PRIVS:
                # to remove admin option from sys privs, we need to revoke it first, then grant it again
                grant_query = GRANT_PRIV_TO_USER_QUERY.format(priv=priv, username=username.upper()) + " WITH ADMIN OPTION"
            else:
                grant_query = GRANT_PRIV_TO_USER_QUERY.format(priv=priv, username=username.upper()) + " WITH GRANT OPTION"
        else:
            grant_query = GRANT_PRIV_TO_USER_QUERY.format(priv=priv, username=username.upper())
        print(grant_query)
        singleton_auth_manager.db_instance.conn.execute(text(grant_query))
        singleton_auth_manager.db_instance.conn.commit()
    flash(f"Grant privs to user {username} successfully.", "success")
    return redirect(url_for('blueprint.index'), code=301) # 301 is for redirect permanently'))

from utils.queries import DISABLE_ROLE_QUERY, ENABLE_ROLE_QUERY, ENABLE_ROLE_WITH_PASSWORD_QUERY
@authentication_check_decorator
def disable_session_role():
    """Disable a session role."""
    with singleton_auth_manager.db_instance.engine.connect() as conn:
        conn.execute(text(DISABLE_ROLE_QUERY))
        conn.commit()
    print("Role set None")
    return redirect(url_for('blueprint.get_account_infos'), code=301)

@authentication_check_decorator
def enable_session_role():
    """Enable a session role."""
    role = request.form.get('role')    
    print("Role:", role)
    with singleton_auth_manager.db_instance.engine.connect() as conn:
        conn.execute(text(ENABLE_ROLE_QUERY.format(
            role=role
        )))
        conn.commit()
    return redirect(url_for('blueprint.get_account_infos'), code=301)

@authentication_check_decorator
def enable_session_role_with_password():
    """Enable a session role with password."""
    role = request.form.get('role')
    password = request.form.get('password')
    with singleton_auth_manager.db_instance.engine.connect() as conn:
        try:
            conn.execute(text(ENABLE_ROLE_WITH_PASSWORD_QUERY.format(
                role=role, 
                password=password
            )))
            conn.commit()
        except Exception as e:
            return render_template('/user/page_404.html', error=str(e), continue_url=url_for('blueprint.index'))
    return redirect(url_for('blueprint.get_account_infos'), code=301)