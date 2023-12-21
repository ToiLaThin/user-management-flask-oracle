SET_RESOURCE_LIMIT_QUERY = "ALTER SYSTEM SET RESOURCE_LIMIT = TRUE"
SET_SESSION_CONTAINER_QUERY = "ALTER SESSION SET CONTAINER = FREEPDB1"
CREATE_ROLE_MANAGER_QUERY = "CREATE ROLE R_MANAGER"
CREATE_ROLE_EMPLOYEE_QUERY = "CREATE ROLE R_EMPLOYEE"

# change logical reads per session and call to 10000
# to avoid ORA-02394: The current session exceeds IO usage limits; this session is being logged off.
# "exceeded session limit on IO usage, you are being logged off"
CREATE_PROFILE_MANAGER_QUERY = """
    CREATE PROFILE PF_MANAGER LIMIT 
        SESSIONS_PER_USER {session_per_user} 
        CPU_PER_SESSION 2000 
        CPU_PER_CALL 2000 
        CONNECT_TIME {connect_time} 
        IDLE_TIME {idle_time}
        LOGICAL_READS_PER_SESSION 10000
        LOGICAL_READS_PER_CALL 10000 
        PRIVATE_SGA 20K 
        COMPOSITE_LIMIT 1000 
        PASSWORD_LIFE_TIME 180 
        PASSWORD_REUSE_TIME 180 
        PASSWORD_REUSE_MAX 5 
        PASSWORD_LOCK_TIME 1 
        PASSWORD_GRACE_TIME 7 
        FAILED_LOGIN_ATTEMPTS 3 
        PASSWORD_VERIFY_FUNCTION NULL
    """
CREATE_PROFILE_EMPLOYEE_QUERY = """
    CREATE PROFILE PF_EMPLOYEE LIMIT
        SESSIONS_PER_USER {session_per_user} 
        CPU_PER_SESSION 2000 
        CPU_PER_CALL 2000 
        CONNECT_TIME {connect_time} 
        IDLE_TIME {idle_time} 
        LOGICAL_READS_PER_SESSION 10000 
        LOGICAL_READS_PER_CALL 10000 
        PRIVATE_SGA 20K 
        COMPOSITE_LIMIT 1000 
        PASSWORD_LIFE_TIME 180 
        PASSWORD_REUSE_TIME 180 
        PASSWORD_REUSE_MAX 5 
        PASSWORD_LOCK_TIME 1 
        PASSWORD_GRACE_TIME 7 
        FAILED_LOGIN_ATTEMPTS 3 
        PASSWORD_VERIFY_FUNCTION NULL
    """

CREATE_TABLESPACE_QUERY = """
    CREATE TABLESPACE {tablespace_name}
    DATAFILE '{tablespace_name}.DBF'
    SIZE 10M
    AUTOEXTEND ON
    NEXT 10M
    MAXSIZE 100M
    EXTENT MANAGEMENT LOCAL
    SEGMENT SPACE MANAGEMENT AUTO
"""
DROP_TABLESPACE_EMPLOYEE_QUERY = """DROP TABLESPACE TBS_EMPLOYEE DROP QUOTA INCLUDING CONTENTS AND DATAFILES CASCADE CONSTRAINTS"""
DROP_PROFILE_EMPLOYEE_QUERY = """DROP PROFILE PF_EMPLOYEE CASCADE"""
DROP_ROLE_EMPLOYEE_QUERY = """DROP ROLE R_EMPLOYEE"""
DROP_TABLESPACE_MANAGER_QUERY = """DROP TABLESPACE TBS_MANAGER DROP QUOTA INCLUDING CONTENTS AND DATAFILES CASCADE CONSTRAINTS"""
DROP_PROFILE_MANAGER_QUERY = """DROP PROFILE PF_MANAGER CASCADE"""
DROP_ROLE_MANAGER_QUERY = """DROP ROLE R_MANAGER"""

# IF HAVE ERROR WITH THIS QUERY, REMOVE THE WHERE CLAUSE AND CHECK THE RESULT
SELECT_USER_ROLE_QUERY = "SELECT GRANTED_ROLE FROM USER_ROLE_PRIVS WHERE REGEXP_LIKE (GRANTED_ROLE, '^R_.*$') OR GRANTED_ROLE = 'DBA'"
SELECT_USER_TABLESPACE_QUERY = "SELECT TABLESPACE_NAME FROM USER_TABLESPACES"
# ANY TABLESPACE START WITH TBS
SELECT_DBA_TABLESPACES_QUERY = "SELECT TABLESPACE_NAME FROM DBA_TABLESPACES WHERE REGEXP_LIKE (TABLESPACE_NAME, '^TBS.*$')"
SELECT_DBA_PROFILES_QUERY = "SELECT DISTINCT PROFILE FROM DBA_PROFILES WHERE REGEXP_LIKE (PROFILE, '^PF_.*$')"
SELECT_DBA_ROLES_QUERY = "SELECT DISTINCT ROLE FROM DBA_ROLES WHERE REGEXP_LIKE (ROLE, '^R_.*$')"


GRANT_ALL_PRIVS_TO_USER_QUERY = """GRANT ALL PRIVILEGES TO U_{username}"""
REVOKE_ALL_PRIVS_FR_USER_QUERY = """REVOKE ALL PRIVILEGES FROM U_{username}"""
GRANT_PRIV_TO_USER_QUERY = """GRANT {priv} TO U_{username}"""
GRANT_ALL_PRIVS_TO_ROLE_QUERY = """GRANT ALL PRIVILEGES TO R_{role}"""
REVOKE_ALL_PRIVS_FR_ROLE_QUERY = """REVOKE ALL PRIVILEGES FROM R_{role}"""
GRANT_PRIV_TO_ROLE_QUERY = """GRANT {priv} TO {role}"""

REVOKE_ROLE_FROM_USER_QUERY = """REVOKE {role} FROM U_{username}"""
GRANT_ROLE_TO_USER_QUERY = """GRANT {role} TO U_{username}"""

DISABLE_ROLE_QUERY = """SET ROLE NONE"""
ENABLE_ROLE_QUERY = """SET ROLE {role}"""
ENABLE_ROLE_WITH_PASSWORD_QUERY = """SET ROLE {role} IDENTIFIED BY {password}"""
DISABLE_ROLE_PWD_QUERY = """ALTER ROLE {role} NOT IDENTIFIED"""
ENABLE_OR_UPDATE_ROLE_PWD_QUERY = """ALTER ROLE {role} IDENTIFIED BY {password}"""

LOCK_ACCOUNT_QUERY = """ALTER USER U_{username} ACCOUNT LOCK"""
UNLOCK_ACCOUNT_QUERY = """ALTER USER U_{username} ACCOUNT UNLOCK"""