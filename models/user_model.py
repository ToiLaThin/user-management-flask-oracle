from sqlalchemy.orm import Mapped
from sqlalchemy.orm import mapped_column
from sqlalchemy.orm import relationship
from sqlalchemy import Table, Column, Integer, String, ForeignKey, Identity

from typing import Optional, List
from utils.globals import Base

class User(Base):
    """Will be register in Base.metadata, when call Base.metadata.create_all() in app.py,
      this class will create a table in oracle database"""
    __tablename__ = "user_account"
    id: Mapped[int] = mapped_column(Identity(start=1, increment=1), primary_key=True)
    name: Mapped[str] = mapped_column(String(30))
    fullname: Mapped[Optional[str]] = mapped_column(String(50))

    def __repr__(self) -> str:
        return f"User(id={self.id!r}, name={self.name!r}, fullname={self.fullname!r})"