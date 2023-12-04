from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import create_engine
import config
class Base(DeclarativeBase):
    """sumary_line
    This is class represent a base class for all model. 
    And have singleton metadata holds all tables to create
    """
    pass