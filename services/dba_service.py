import pandas as pd
from sqlalchemy import text
from utils.globals import singleton_auth_manager
def list_users() -> list:
    """sumary_line
    List all users in the database
    """
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
        return user_info_orcl_list
    
# why i do not do def detail_user: because it 's too complex, it have too many params to return
# instead the better way is to make multiple list service, call all of those list service and get all the result
# if post method, we have not problem, get method is the problem
    

def update_privs_user(username: str, all_checked_privs: list, all_checked_privs_with_grant_option: list):
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
            # to remove admin option from sys privs, we need to revoke it first, then grant it again
            # using tenary operator in python to avoid deep nested if else
            grant_query = GRANT_PRIV_TO_USER_QUERY.format(priv=priv, username=username.upper()) + " WITH ADMIN OPTION" if priv in ALL_SYS_PRIVS \
                else GRANT_PRIV_TO_USER_QUERY.format(priv=priv, username=username.upper()) + " WITH GRANT OPTION"
        else:
            grant_query = GRANT_PRIV_TO_USER_QUERY.format(priv=priv, username=username.upper())
        print(grant_query)
        singleton_auth_manager.db_instance.conn.execute(text(grant_query))



def lock_unlock_user(astatus: str, username: str):
    from utils.globals import AccountStatusEnum
    from utils.queries import LOCK_ACCOUNT_QUERY, UNLOCK_ACCOUNT_QUERY, SET_SESSION_CONTAINER_QUERY
    if astatus == AccountStatusEnum.LOCKED.value:
        print("Locked. Unlocking user account")
        query = UNLOCK_ACCOUNT_QUERY.format(username=username)
    else:
        print("UnLocked. Locking user account")
        query = LOCK_ACCOUNT_QUERY.format(username=username)
    with singleton_auth_manager.db_instance.engine.connect():
        singleton_auth_manager.db_instance.conn.execute(text(SET_SESSION_CONTAINER_QUERY))
        singleton_auth_manager.db_instance.conn.execute(text(query))
        singleton_auth_manager.db_instance.conn.commit()


def update_privs_role(role: str, privileges_to_grant: list):
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