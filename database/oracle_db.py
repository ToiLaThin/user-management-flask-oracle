import config
import oracledb as dbapi
from sqlalchemy import create_engine

class OracleDb:
    """sumary_line
    This is class represent a engine connect to oracle database
    With specific username, password, host, port, database name
    Since this is a database security level
    Keyword arguments:
    argument -- description
    username -- username of user auth with database
    password -- password of user

    Return: instance which hold the engine connect to database
    """

    def __init__(self, username:str, password):
        self.username = username.upper()
        self.password = password
        self.host = config.DATABASE_HOST
        self.port = config.DATABASE_PORT
        self.sid = config.DATABASE_SID
        self.service_name = config.DATABASE_SERVICE_NAME
        self.engine = None
        self.conn = None
        if username == "sys":
            self.conn_string = (
                'oracle+oracledb://{username}:{password}@' + self.host +
                ':' + str(self.port) + '/' + self.sid + '?mode=sysdba'
            )
        else:
            self.conn_string = (
                'oracle+oracledb://U_{username}:{password}@' + self.host + ':' + \
                str(self.port) + '/?service_name=' + self.service_name
            )
    def connect(self):
        """sumary_line
        This is method connect to database, will set the conn and the engine
        """
        try:
            self.engine = create_engine(
                self.conn_string.format(
                    username=self.username,
                    password=self.password
                ),
                pool_size=config.DATABASE_POOL_SIZE,
                pool_recycle=config.DATABASE_POOL_RECYCLE,
                echo=True
            )
            self.conn = self.engine.connect()
            print(self.conn_string.format(username=self.username,password=self.password))
            print('Connected to Oracle DB!')
        except Exception as e:
            self.conn = None
            self.engine = None
            print('Error: ', e)
            exit(1)
    
    def close(self):
        """sumary_line
        This is method close the connection to database
        """
        try:
            self.conn.close()
            self.engine.dispose()
            self = None
            print('Connection closed!')
            print("To make sure we cleaned the oracle db, now it 's:", self)
        except Exception as e:
            print('Error: ', e)
            exit(1)

    def __repr__(self) -> str:
        return self.conn_string.format(
            username=self.username,
            password=self.password
        )
    
    def __enter__(self):
        """This method call when use with statement"""
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """This method call when exit with statement"""
        self.close()
    
            