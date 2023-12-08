from flask import request, render_template
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
            srv_add_user(username, hashed_password,tbs_name, quota, pf_name, r_name)
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