from flask import request, render_template
from sqlalchemy import text
from database.oracle_db import OracleDb
from utils.globals import authentication_check_decorator, authorization_check_decorator, \
            DBA_ROLE_NAME, HASHED_METHOD
from utils.queries import SELECT_DBA_PROFILES_QUERY, SELECT_DBA_TABLESPACES_QUERY, SET_SESSION_CONTAINER_QUERY

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
            tbs_result = db.conn.execute(text(SELECT_DBA_TABLESPACES_QUERY))
            profiles_result = db.conn.execute(text(SELECT_DBA_PROFILES_QUERY))
            for row in tbs_result:
                print("Tablespace:", row[0])
                tbs_list.append(row[0])
            for row in profiles_result:
                print("Profile:", row[0])
                profile_list.append(row[0])
        return render_template('auth/create_account.html', tbs_list=tbs_list, profile_list=profile_list)
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        hashed_password = generate_password_hash(password, method=HASHED_METHOD)
        tbs_name = request.form.get('tbs_name')
        pf_name = request.form.get('pf_name')
        quota = int(request.form.get('quota'))
        print(username, hashed_password, tbs_name,pf_name, quota) #oracle hash password already, so we don't need to hash it again
        if srv_check_user_not_exist(username) == True:
            srv_add_user(username, hashed_password,tbs_name, quota, pf_name)
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