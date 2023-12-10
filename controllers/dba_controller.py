from flask import redirect, request, render_template, url_for
import pandas as pd
from prompt_toolkit import HTML
from sqlalchemy import text
from database.oracle_db import OracleDb
from utils.globals import authentication_check_decorator, authorization_check_decorator, \
            DBA_ROLE_NAME, HASHED_METHOD, \
            singleton_auth_manager
from utils.queries import SELECT_DBA_PROFILES_QUERY, SELECT_DBA_TABLESPACES_QUERY, SELECT_DBA_ROLES_QUERY, SET_SESSION_CONTAINER_QUERY

from services.user_service import add_user as srv_add_user
from services.user_service import check_user_not_exist as srv_check_user_not_exist
from services.user_service import delete_user as srv_delete_user
from services.user_service import check_user_valid as srv_check_user_valid
from werkzeug.security import generate_password_hash
@authentication_check_decorator
@authorization_check_decorator(DBA_ROLE_NAME)
def create_account():
    # TODO this is only valid for dba user
    """Create a new user account."""
    if request.method == 'GET':
        with OracleDb('sys', '123') as db:
            db.conn.execute(text(SET_SESSION_CONTAINER_QUERY))
            # must have to select the right tablespace
            tbs_list = []
            profile_list = []
            role_list = []
            tbs_result = db.conn.execute(text(SELECT_DBA_TABLESPACES_QUERY))
            profiles_result = db.conn.execute(text(SELECT_DBA_PROFILES_QUERY))
            roles_result = db.conn.execute(text(SELECT_DBA_ROLES_QUERY))
            for row in tbs_result:
                print("Tablespace:", row[0])
                tbs_list.append(row[0])
            for row in profiles_result:
                print("Profile:", row[0])
                profile_list.append(row[0])
            for row in roles_result:
                print("Role:", row[0])
                role_list.append(row[0])
        return render_template('auth/create_account.html', tbs_list=tbs_list, profile_list=profile_list, role_list=role_list)
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method=HASHED_METHOD)
        tbs_name = request.form.get('tbs_name')
        pf_name = request.form.get('pf_name')
        quota = int(request.form.get('quota'))
        r_name = request.form.get('r_name')
        print(username, hashed_password, tbs_name,pf_name, quota) #oracle hash password already, so we don't need to hash it again
        if srv_check_user_not_exist(username) == True:
            srv_add_user(username, password,tbs_name, quota, pf_name, r_name)
            return "created_account, please check database"
        else:
            return f"user {username} is already exist"
    
@authentication_check_decorator
@authorization_check_decorator(DBA_ROLE_NAME)
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
    

@authentication_check_decorator
@authorization_check_decorator(DBA_ROLE_NAME)
def list_users():
    """List all user accounts."""
    with singleton_auth_manager.db_instance.engine.connect():
        query = """
            SELECT USERNAME, ACCOUNT_STATUS, LOCK_DATE, CREATED, DEFAULT_TABLESPACE, TEMPORARY_TABLESPACE, PROFILE
                , GRANTED_ROLE, ADMIN_OPTION
            FROM DBA_USERS dba_u 
            JOIN DBA_ROLE_PRIVS dba_r 
            ON dba_u.USERNAME = dba_r.GRANTEE
            WHERE REGEXP_LIKE (USERNAME ,'^U_.*$')
        """
        df_users = pd.read_sql_query(text(query), singleton_auth_manager.db_instance.engine)
        print(df_users)
        df_users['granted_role'] = df_users['granted_role'].groupby(df_users['username']).transform(lambda x: ','.join(x))
        df_users.drop_duplicates(subset=['username'], inplace=True) # 2 row is the same, since the above query modify the granted_role column
        html = df_users.to_html(classes='data', header="true")
        return render_template('admin/user_list.html', table=html)
    
@authentication_check_decorator
@authorization_check_decorator(DBA_ROLE_NAME)
def detail_user():
    """Detail a user account."""    
    if request.method == 'GET' or request.method == 'POST':
        username = request.args.get('username')
        userpf = request.args.get('userpf')
        userrole = request.args.get('userrole')


        with singleton_auth_manager.db_instance.engine.connect():
            singleton_auth_manager.db_instance.conn.execute(text(SET_SESSION_CONTAINER_QUERY))
            query_roles = f"SELECT * FROM DBA_ROLE_PRIVS WHERE GRANTEE = '{username}'"
            query_pf = f"SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE = '{userpf}'"
            query_user_privs_sys = f"SELECT * FROM DBA_SYS_PRIVS WHERE GRANTEE = '{username}'"
            query_user_privs_tab = f"SELECT * FROM DBA_TAB_PRIVS WHERE GRANTEE = '{username}'"
            query_role_privs_sys = f"SELECT * FROM DBA_SYS_PRIVS WHERE GRANTEE = '{userrole}'"
            query_role_privs_tab = f"SELECT * FROM DBA_TAB_PRIVS WHERE GRANTEE = '{userrole}'"
            df_user_roles = pd.read_sql_query(text(query_roles), singleton_auth_manager.db_instance.engine)
            print(df_user_roles)

            # can use async to run all query parallel
            df_user_pf = pd.read_sql_query(text(query_pf), singleton_auth_manager.db_instance.engine)
            df_privs_sys_to_user = pd.read_sql_query(text(query_user_privs_sys), singleton_auth_manager.db_instance.engine)
            df_privs_tab_to_user = pd.read_sql_query(text(query_user_privs_tab), singleton_auth_manager.db_instance.engine)
            df_privs_sys_to_userrole = pd.read_sql_query(text(query_role_privs_sys), singleton_auth_manager.db_instance.engine)
            df_privs_tab_to_userrole = pd.read_sql_query(text(query_role_privs_tab), singleton_auth_manager.db_instance.engine)

            user_sys_privs_arr = df_privs_sys_to_user['privilege'].array
            user_tab_privs_arr = df_privs_tab_to_user['privilege'].array
            user_role_sys_privs_arr = df_privs_sys_to_userrole['privilege'].array
            user_role_tab_privs_arr = df_privs_tab_to_userrole['privilege'].array
            print(user_sys_privs_arr)
            print(user_tab_privs_arr)
            print("User profile: ", df_user_pf)
            print("User sys privs: ", df_privs_sys_to_user)
            print("User tab privs: ", df_privs_tab_to_user)
            print("Role sys privs: ", df_privs_sys_to_userrole)
            print("Role tab privs: ", df_privs_tab_to_userrole)

            pf_resource_dict = {}
            resource_to_take_dict = {
                'CONNECT_TIME': 1, 
                'IDLE_TIME': 1,
                'SESSIONS_PER_USER': 1
            }
            for _, row in df_user_pf.iterrows():
                if resource_to_take_dict.get(row['resource_name']) != None:
                    pf_resource_dict[row['resource_name']] = row['limit']
            print(pf_resource_dict)

            all_sys_privs = [
                'CREATE PROFILE', 'ALTER PROFILE', 'DROP PROFILE',\
                'CREATE USER', 'ALTER USER', 'DROP USER',\
                'CREATE SESSION',\
                'CREATE ROLE', 'ALTER ANY ROLE', 'DROP ANY ROLE', 'GRANT ANY ROLE'\
                'CREATE ANY TABLE', 'ALTER ANY TABLE', 'DROP ANY TABLE', 'CREATE TABLE'\
                'SELECT ANY TABLE', 'DELETE ANY TABLE', 'INSERT ANY TABLE', 'UPDATE ANY TABLE'
            ]
            from utils.globals import TEST_TABLE_NAME
            all_tab_privs = [
                f'SELECT ON {TEST_TABLE_NAME}', f'DELETE ON {TEST_TABLE_NAME}',\
                f'INSERT ON {TEST_TABLE_NAME}', f'UPDATE ON {TEST_TABLE_NAME}'
            ]

            user_sys_privs_arr_not_applied = list(set(all_sys_privs) - set(user_sys_privs_arr))
            user_tab_privs_arr_not_applied = list(set(all_tab_privs) - set(user_tab_privs_arr))
            user_role_sys_privs_arr_not_applied = list(set(all_sys_privs) - set(user_role_sys_privs_arr))
            user_role_tab_privs_arr_not_applied = list(set(all_tab_privs) - set(user_role_tab_privs_arr))
            #convert profiles resoures to dict to make it easier to render in html
        return render_template('admin/user_detail.html'\
                               , username=username\
                               , userpf=userpf\
                               , userrole=userrole\
                               
                               , user_sys_privs_arr=user_sys_privs_arr\
                               , user_tab_privs_arr=user_tab_privs_arr\
                               , user_role_sys_privs_arr=user_role_sys_privs_arr\
                               , user_role_tab_privs_arr=user_role_tab_privs_arr\
                               , pf_resource_dict=pf_resource_dict\
                               
                               , user_sys_privs_arr_not_applied=user_sys_privs_arr_not_applied\
                               , user_tab_privs_arr_not_applied=user_tab_privs_arr_not_applied\
                               , user_role_sys_privs_arr_not_applied=user_role_sys_privs_arr_not_applied\
                               , user_role_tab_privs_arr_not_applied=user_role_tab_privs_arr_not_applied\
                            )
    

@authentication_check_decorator
@authorization_check_decorator(DBA_ROLE_NAME)
def update_privs_user():
    """
    Revoke all privs of a user account, both tab and sys privs. 
    Then grant all checked privs via AJAX
    """
    username = request.json['username'] # this username already has U_ prefix
    username = username[2:]
    all_checked_privs = request.json['all_checked_privs']
    print(all_checked_privs)
    userpf = request.json['userpf']
    userrole = request.json['userrole']

    grant_all_privs_query = f"GRANT ALL PRIVILEGES TO U_{username.upper()}"
    revoke_all_privs_query = f"REVOKE ALL PRIVILEGES FROM U_{username.upper()}"
    grant_priv_query = """GRANT {priv} TO U_{username}"""

    print(singleton_auth_manager.db_instance)
    singleton_auth_manager.db_instance.conn.execute(text(grant_all_privs_query)) # to avoid err: ORA-01952: system privileges not granted to 'U_THINH'
    singleton_auth_manager.db_instance.conn.execute(text(revoke_all_privs_query))
    for priv in all_checked_privs:
        grant_query = grant_priv_query.format(priv=priv, username=username.upper())
        print(grant_query)
        singleton_auth_manager.db_instance.conn.execute(text(grant_query))
    return redirect(
        url_for('blueprint.detail_user', 
                username=username, 
                userpf=userpf, 
                userrole=userrole)
    )

