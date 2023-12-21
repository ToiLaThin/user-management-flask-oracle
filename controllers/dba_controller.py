from flask import flash, redirect, request, render_template, url_for
import pandas as pd
from prompt_toolkit import HTML
from sqlalchemy import text
from database.oracle_db import OracleDb
from utils.globals import AccountStatusEnum, ConnectTimeEnum, IdleTimeEnum, SessionPerUserEnum, \
            authentication_check_decorator, authorization_check_decorator, \
            DBA_ROLE_NAME, HASHED_METHOD, \
            singleton_auth_manager
from utils.queries import SELECT_DBA_PROFILES_QUERY, SELECT_DBA_TABLESPACES_QUERY, SELECT_DBA_ROLES_QUERY, SET_SESSION_CONTAINER_QUERY

from services.user_service import add_user as srv_add_user
from services.user_service import check_user_not_exist as srv_check_user_not_exist
from services.user_service import delete_user as srv_delete_user
from services.user_service import check_user_valid as srv_check_user_valid
from werkzeug.security import generate_password_hash
@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
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
            try:
                srv_add_user(username, password,tbs_name, quota, pf_name, r_name)
            except Exception as e:
                flash(f"Error: {e}")
                return redirect(url_for('blueprint.create_account'), code=301)
            flash(f"Created user {username}. Please check database", "success")
            return redirect(url_for('blueprint.index'), code=301)
        else:
            flash(f"user {username} is already exist")
            return redirect(url_for('blueprint.create_account'), code=301)
    
@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def delete_account(username: str):    
    """Delete an existing user account."""
    if srv_check_user_valid(username) == True:
        print(f"user {username} is valid")
        username = username[2:] # remove U_ prefix
        try:
            srv_delete_user(username)
        except Exception as e:
            print("Exception:", e)
            flash(f"Error: {e}")
            return redirect(url_for('blueprint.index'), code=301)
    flash(f"Account deleted", "success")
    return redirect(url_for('blueprint.index'), code=301)
    

@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def list_users():
    """List all user accounts."""
    with singleton_auth_manager.db_instance.engine.connect():
        # every time we reload the app, 
        # the user lost the role granted by admin, 
        # so next time this won't show any users, find how to fix this
        query = """
            SELECT USERNAME, ACCOUNT_STATUS, LOCK_DATE, CREATED, DEFAULT_TABLESPACE, TEMPORARY_TABLESPACE, PROFILE
                , GRANTED_ROLE, ADMIN_OPTION
            FROM DBA_USERS dba_u 
            JOIN DBA_ROLE_PRIVS dba_r 
            ON dba_u.USERNAME = dba_r.GRANTEE
            WHERE REGEXP_LIKE (USERNAME ,'^U_.*$')
        """
        df_users = pd.read_sql_query(text(query), singleton_auth_manager.db_instance.engine)
        # print(df_users)
        df_users['granted_role'] = df_users['granted_role'].groupby(df_users['username']).transform(lambda x: ','.join(x))
        df_users.drop_duplicates(subset=['username'], inplace=True) # 2 row is the same, since the above query modify the granted_role column
        
        user_info_orcl_list = []
        from utils.globals import UserInfoOracle
        for _, row in df_users.iterrows():
            username = row['username']
            account_status = row['account_status']
            lock_date = row['lock_date']
            created = row['created']
            default_tablespace = row['default_tablespace']
            temporary_tablespace = row['temporary_tablespace']
            profile = row['profile']
            granted_role = row['granted_role']
            admin_option = row['admin_option']

            user_info_orcl = UserInfoOracle(username, account_status, lock_date, created, default_tablespace, temporary_tablespace, profile, granted_role, admin_option)
            user_info_orcl_list.append(user_info_orcl)
        print(user_info_orcl_list)
        return render_template('admin/user_list.html', user_info_orcl_list=user_info_orcl_list)
    
@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def detail_user():
    """Detail a user account."""    
    if request.method == 'GET' or request.method == 'POST':
        username = request.args.get('username')
        userpf = request.args.get('userpf')
        userrole = request.args.get('userrole')
        account_status = request.args.get('account_status')
        if account_status == AccountStatusEnum.LOCKED:
            print("User account is locked")
        else:
            print("User account is open")

        with singleton_auth_manager.db_instance.engine.connect():
            singleton_auth_manager.db_instance.conn.execute(text(SET_SESSION_CONTAINER_QUERY))
            query_pf = f"SELECT PROFILE, RESOURCE_NAME, LIMIT FROM DBA_PROFILES WHERE PROFILE = '{userpf}'"
            query_user_privs_sys = f"SELECT * FROM DBA_SYS_PRIVS WHERE GRANTEE = '{username}'"
            query_user_privs_tab = f"SELECT * FROM DBA_TAB_PRIVS WHERE GRANTEE = '{username}'"
            query_role_privs_sys = f"SELECT * FROM DBA_SYS_PRIVS WHERE GRANTEE = '{userrole}'"
            query_role_privs_tab = f"SELECT * FROM DBA_TAB_PRIVS WHERE GRANTEE = '{userrole}'"

            # can use async to run all query parallel
            df_user_pf = pd.read_sql_query(text(query_pf), singleton_auth_manager.db_instance.engine)
            df_privs_sys_to_user = pd.read_sql_query(text(query_user_privs_sys), singleton_auth_manager.db_instance.engine)
            df_privs_tab_to_user = pd.read_sql_query(text(query_user_privs_tab), singleton_auth_manager.db_instance.engine)
            df_privs_sys_to_userrole = pd.read_sql_query(text(query_role_privs_sys), singleton_auth_manager.db_instance.engine)
            df_privs_tab_to_userrole = pd.read_sql_query(text(query_role_privs_tab), singleton_auth_manager.db_instance.engine)            

            user_sys_privs_arr = df_privs_sys_to_user['privilege'].array
            # TODO transform this tab privs to format: "PRIVILEGES ON OWNER.TABLE"
            df_privs_tab_to_user['privilege'] = df_privs_tab_to_user['privilege'].transform(
                lambda x: x + " ON " + df_privs_tab_to_user['owner'] + "." + df_privs_tab_to_user['table_name'])
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

            # create dictionary key: privilege, value: is admin option/ grantable or not
            priv_with_grant_option__lookup_dict = {}
            for _, row in df_privs_sys_to_user.iterrows():
                sys_priv = row['privilege']
                have_admin_option = row['admin_option']
                priv_with_grant_option__lookup_dict[sys_priv] = have_admin_option
            for _, row in df_privs_tab_to_user.iterrows():
                tab_priv = row['privilege']
                have_admin_option = row['grantable']
                priv_with_grant_option__lookup_dict[tab_priv] = have_admin_option
            print(priv_with_grant_option__lookup_dict)

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

            from utils.globals import ALL_SYS_PRIVS, ALL_TAB_PRIVS  
            user_sys_privs_arr_not_applied = list(set(ALL_SYS_PRIVS) - set(user_sys_privs_arr))
            user_tab_privs_arr_not_applied = list(set(ALL_TAB_PRIVS) - set(user_tab_privs_arr))
            user_role_sys_privs_arr_not_applied = list(set(ALL_SYS_PRIVS) - set(user_role_sys_privs_arr))
            user_role_tab_privs_arr_not_applied = list(set(ALL_TAB_PRIVS) - set(user_role_tab_privs_arr))
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
                               
                               , account_status=account_status\
                               , priv_with_grant_option__lookup_dict=priv_with_grant_option__lookup_dict\
                            )
    

@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def update_privs_user():
    """
    Revoke all privs of a user account, both tab and sys privs. 
    Then grant all checked privs via AJAX
    """
    username = request.json['username'] # this username already has U_ prefix
    username = username[2:]
    all_checked_privs = request.json['all_checked_privs']
    all_checked_privs_with_grant_option = request.json['all_checked_privs_with_grant_option']
    print(all_checked_privs)
    print(all_checked_privs_with_grant_option)
    userpf = request.json['userpf']
    userrole = request.json['userrole']
    account_status = request.json['account_status']

    from utils.queries import GRANT_ALL_PRIVS_TO_USER_QUERY, REVOKE_ALL_PRIVS_FR_USER_QUERY, GRANT_PRIV_TO_USER_QUERY
    singleton_auth_manager.db_instance.conn.execute(text(GRANT_ALL_PRIVS_TO_USER_QUERY.format(
        username=username.upper()
    ))) # to avoid err: ORA-01952: system privileges not granted to 'U_THINH'
    singleton_auth_manager.db_instance.conn.execute(text(REVOKE_ALL_PRIVS_FR_USER_QUERY.format(
        username=username.upper()
    )))

    from utils.globals import ALL_SYS_PRIVS
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
    return redirect(
        url_for('blueprint.detail_user', 
                username=username, 
                userpf=userpf, 
                userrole=userrole,
                account_status=account_status)
    )

@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def lock_unlock_user(astatus: str, username: str):
    """Lock or unlock a user account."""
    from utils.queries import LOCK_USER_QUERY, UNLOCK_USER_QUERY
    username = username[2:] # remove U_ prefix
    if astatus == AccountStatusEnum.LOCKED.value:
        print("Locked. Unlocking user account")
        query = UNLOCK_USER_QUERY.format(username=username)
    else:
        print("UnLocked. Locking user account")
        query = LOCK_USER_QUERY.format(username=username)
    with singleton_auth_manager.db_instance.engine.connect():
        singleton_auth_manager.db_instance.conn.execute(text(SET_SESSION_CONTAINER_QUERY))
        singleton_auth_manager.db_instance.conn.execute(text(query))
    return redirect(url_for('blueprint.list_users'))


@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def list_profiles():
    """List all profiles."""
    with singleton_auth_manager.db_instance.engine.connect():
        query = """
            SELECT PROFILE, RESOURCE_NAME, LIMIT
            FROM DBA_PROFILES WHERE REGEXP_LIKE (PROFILE, '^PF_.*$')
        """
        profile_result = singleton_auth_manager.db_instance.conn.execute(text(query))
        profile_tuple_list = []
        profile_dict = {} 
        # value is list of tuples: (resource_name, limit)
        resource_to_take_dict = {
                'CONNECT_TIME': 1, 
                'IDLE_TIME': 1,
                'SESSIONS_PER_USER': 1
        }
        for row in profile_result:
            pf_name = row[0]
            if pf_name not in profile_dict.keys():
                profile_dict[pf_name] = []
        
        # profile_dict = profile_dict.fromkeys(profile_set, [])
        # https://stackoverflow.com/a/34010458 why append to one key will append to all keys
        
        # must query again to get the resource_name and limit, iterate over the result above cleared this 
        profile_result = singleton_auth_manager.db_instance.conn.execute(text(query))
        for row in profile_result:
            pf_name = row[0]
            resource_name = row[1]
            limit = row[2]
            if resource_to_take_dict.get(resource_name) != None: 
                # only take the resource we want, row is (pf_name, resource_name, limit)
                profile_tuple_list.append(row)
                profile_dict[pf_name].append((resource_name, limit))

        print(profile_dict)
        return render_template('admin/profile_list.html', \
                               profile_tuple_list=profile_tuple_list, \
                               profile_dict=profile_dict)
    
@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def detail_profile(pf_name:str):
    """Detail a profile."""
    pf_name = pf_name[3:] # remove PF_ prefix
    with singleton_auth_manager.db_instance.engine.connect():
        singleton_auth_manager.db_instance.conn.execute(text(SET_SESSION_CONTAINER_QUERY))
        query = f"""
            SELECT PROFILE, RESOURCE_NAME, LIMIT
            FROM DBA_PROFILES WHERE PROFILE = 'PF_{pf_name}'
        """
        resource_to_take_dict = {
                'CONNECT_TIME': 1, 
                'IDLE_TIME': 1,
                'SESSIONS_PER_USER': 1
        }
        profile_result = singleton_auth_manager.db_instance.conn.execute(text(query))
        session_per_user_options_list = [ss.value for ss in SessionPerUserEnum]
        connect_time_options_list = [ct.value for ct in ConnectTimeEnum]
        idle_time_options_list = [it.value for it in IdleTimeEnum]
        resource_limit_of_profile_dict = {}
        for row in profile_result:
            resource_name = row[1]
            limit = row[2]
            print(resource_name, limit)
            if resource_to_take_dict.get(resource_name) != None: 
                # only take the resource we want, row is (pf_name, resource_name, limit)
                resource_limit_of_profile_dict[resource_name] = limit
        print(resource_limit_of_profile_dict)
        return render_template('admin/profile_detail.html', \
                               resource_limit_of_profile_dict=resource_limit_of_profile_dict, \
                               session_per_user_options_list=session_per_user_options_list, \
                               connect_time_options_list=connect_time_options_list, \
                               idle_time_options_list=idle_time_options_list, \
                               pf_name=pf_name)


@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def update_profile():
    """Update a profile with select options."""
    pf_name = request.form.get('pf_name') # does not have PF_ prefix
    session_per_user = request.form.get('session_per_user')
    connect_time = request.form.get('connect_time')
    idle_time = request.form.get('idle_time')

    print(pf_name, session_per_user, connect_time, idle_time)
    with singleton_auth_manager.db_instance.engine.connect():
        singleton_auth_manager.db_instance.conn.execute(text(SET_SESSION_CONTAINER_QUERY))
        query = f"""
            ALTER PROFILE PF_{pf_name} LIMIT
            SESSIONS_PER_USER {session_per_user}
            CONNECT_TIME {connect_time}
            IDLE_TIME {idle_time}
        """
        singleton_auth_manager.db_instance.conn.execute(text(query))
    return redirect(url_for('blueprint.list_profiles'))


@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def get_all_roles():
    from utils.queries import SELECT_USER_ROLE_QUERY
    """Get a list of all roles on the system."""
    with singleton_auth_manager.db_instance.engine.connect():
        roles_result = singleton_auth_manager.db_instance.conn.execute(text(SELECT_DBA_ROLES_QUERY))
        roles_list = [row[0] for row in roles_result if row[0].lower().startswith('r')]
    return render_template('/admin/roles.html', roles_list = roles_list )

@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def get_role_info(selected_role):    
    """Get information about a specific role, its privileges, and users with that role."""
    query_check_role_have_password = f"SELECT PASSWORD_REQUIRED FROM DBA_ROLES WHERE ROLE = '{selected_role}'"
    role_have_password = False

    with singleton_auth_manager.db_instance.engine.connect() :
        role_sys_privs_result = singleton_auth_manager.db_instance.conn.execute(
            text(f"SELECT PRIVILEGE FROM DBA_SYS_PRIVS WHERE GRANTEE = '{selected_role}'")
        )
        role_tab_privs_result = singleton_auth_manager.db_instance.conn.execute(
            text(f"SELECT PRIVILEGE FROM DBA_TAB_PRIVS WHERE GRANTEE = '{selected_role}'")
        )
        users_with_role_result = singleton_auth_manager.db_instance.conn.execute(
            text(f"SELECT GRANTEE FROM DBA_ROLE_PRIVS WHERE GRANTED_ROLE = '{selected_role}' AND GRANTEE LIKE 'U_%'")
        )
        role_have_password_result = singleton_auth_manager.db_instance.conn.execute(text(query_check_role_have_password)).fetchone()
        if role_have_password_result[0] == 'YES':
            role_have_password = True
        else:
            role_have_password = False
        print(role_have_password)        

        role_sys_privs_granted_list = []
        role_tab_privs_granted_list = []
        users_with_role_list = []

        for row in role_sys_privs_result:
            role_sys_privs_granted_list.append(row[0])
        for row in role_tab_privs_result:
            role_tab_privs_granted_list.append(row[0])            
        for row in users_with_role_result:
            users_with_role_list.append(row[0])

    from utils.globals import ALL_SYS_PRIVS, ALL_TAB_PRIVS
    return render_template('/admin/role_info.html', 
                           role = selected_role, 
                           role_have_password = role_have_password,
                           role_sys_privs_granted_list= role_sys_privs_granted_list, 
                           role_tab_privs_granted_list = role_tab_privs_granted_list, 
                           all_sys_privs = ALL_SYS_PRIVS, 
                           all_tab_privs = ALL_TAB_PRIVS, 
                           users_with_role_list = users_with_role_list)

@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def update_privs_role():
    """
    Revoke all privs of a role, both tab and sys privs. 
    Then grant all checked privs via AJAX
    """
    role = request.json['role'] # this username already has U_ prefix
    role = role[2:]
    privileges_to_grant = request.json['privileges']
    print(privileges_to_grant)

    from utils.queries import GRANT_ALL_PRIVS_TO_ROLE_QUERY, REVOKE_ALL_PRIVS_FR_ROLE_QUERY, GRANT_PRIV_TO_ROLE_QUERY
    singleton_auth_manager.db_instance.conn.execute(text(GRANT_ALL_PRIVS_TO_ROLE_QUERY.format(
        role=role.upper()
    ))) # to avoid err: ORA-01952: system privileges not granted to 'U_THINH'
    singleton_auth_manager.db_instance.conn.execute(text(REVOKE_ALL_PRIVS_FR_ROLE_QUERY.format(
        role=role.upper()
    )))

    for priv in privileges_to_grant:
        singleton_auth_manager.db_instance.conn.execute(text(GRANT_PRIV_TO_ROLE_QUERY.format(
            priv=priv,
            role=role.upper()
        )))

    return redirect(
        url_for('blueprint.get_role_info', 
                selected_role=role)
    )


@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def update_user_role():
    if request.method == 'GET':
        username = request.args.get('username')
        role = request.args.get('role')
        all_roles_list = []
        with singleton_auth_manager.db_instance.engine.connect():
            roles_result = singleton_auth_manager.db_instance.conn.execute(text(SELECT_DBA_ROLES_QUERY))
            all_roles_list = [row[0] for row in roles_result if row[0].lower().startswith('r')]
        current_role = role
        return render_template('admin/update_user_role.html'\
                               , username=username\
                               , current_role=current_role\
                               , all_roles_list=all_roles_list)
    else:
        username = request.form.get('username')
        username = username[2:] # remove U_ prefix
        current_role = request.form.get('current_role')
        selected_role = request.form.get('selected_role')
        print(username, selected_role)
        from utils.queries import REVOKE_ROLE_FROM_USER_QUERY, GRANT_ROLE_TO_USER_QUERY
        with singleton_auth_manager.db_instance.engine.connect():
            singleton_auth_manager.db_instance.conn.execute(text(SET_SESSION_CONTAINER_QUERY))
            # revoke old role first
            singleton_auth_manager.db_instance.conn.execute(text(REVOKE_ROLE_FROM_USER_QUERY.format(
                role=current_role, 
                username=username
            )))
            singleton_auth_manager.db_instance.conn.execute(text(GRANT_ROLE_TO_USER_QUERY.format(
                role=selected_role, 
                username=username
            )))
        return redirect(url_for('blueprint.get_role_info', selected_role=selected_role), code=301)
    
from utils.queries import ENABLE_OR_UPDATE_ROLE_PWD_QUERY, DISABLE_ROLE_PWD_QUERY
@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def enable_role_pwd():
    """Enable role password."""
    role = request.form.get('role')
    password = request.form.get('password')
    with singleton_auth_manager.db_instance.engine.connect():
        singleton_auth_manager.db_instance.conn.execute(text(ENABLE_OR_UPDATE_ROLE_PWD_QUERY.format(
            role=role,
            password=password
        )))
        singleton_auth_manager.db_instance.conn.commit()
        flash(f"Enabled role password for {role}", "success")
    return redirect(url_for('blueprint.get_role_info', selected_role=role), code=301)

@authentication_check_decorator
@authorization_check_decorator([DBA_ROLE_NAME])
def disable_or_update_role_pwd():
    """Disable or update role password."""
    role = request.form.get('role')
    password = request.form.get('password')
    if password == "" or password == None:
        with singleton_auth_manager.db_instance.engine.connect():
            singleton_auth_manager.db_instance.conn.execute(text(DISABLE_ROLE_PWD_QUERY.format(
                role=role
            )))
            singleton_auth_manager.db_instance.conn.commit()
            flash(f"Disabled role password for {role}", "success")
    else:
        with singleton_auth_manager.db_instance.engine.connect():
            singleton_auth_manager.db_instance.conn.execute(text(ENABLE_OR_UPDATE_ROLE_PWD_QUERY.format(
                role=role,
                password=password
            )))
            singleton_auth_manager.db_instance.conn.commit()
            flash(f"Updated role password for {role}", "success")
    return redirect(url_for('blueprint.get_role_info', selected_role=role), code=301)