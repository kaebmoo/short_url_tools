from sqlalchemy import Column, Integer, String, DateTime, Enum, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

Base = declarative_base()

class ScanRecord(Base):
    __tablename__ = 'scan_records'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    url = Column(String, nullable=False)
    status = Column(Enum('0', 'Dangerous', 'Safe', 'In queue for scanning', '-1', '1', 'No conclusive information', 'No classification'), default='0')
    scan_type = Column(String, nullable=False)
    result = Column(String, nullable=True)
    submission_type = Column(String, nullable=True)
    scan_id = Column(String, nullable=True)
    sha256 = Column(String, nullable=True)

def create_db_engine(database_path):
    return create_engine(f'sqlite:///{database_path}', echo=True)

def create_db_session(database_path):
    engine = create_db_engine(database_path)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    return Session(), engine

# Creating sessions for both databases
urls_database_path = os.getenv("DATABASE_PATH")
scan_records_database_path = os.getenv("SCAN_RECORDS_DATABASE_PATH")

urls_session, urls_engine = create_db_session(urls_database_path)
scan_records_session, scan_records_engine = create_db_session(scan_records_database_path)
