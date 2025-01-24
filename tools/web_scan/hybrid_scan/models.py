from dotenv import load_dotenv
from sqlalchemy import Column, Integer, String, DateTime, Enum, create_engine
from sqlalchemy.dialects.postgresql import ENUM
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime, timezone
import os

# Load environment variables
load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), 'config.env'))

Base = declarative_base()

# Define PostgreSQL-native ENUM type
status_enum = ENUM(
    '0', 'Dangerous', 'Safe', 'In queue for scanning', '-1', '1',
    'No conclusive information', 'No classification',
    name='status_enum',  # PostgreSQL enum type name
    create_type=True  # Ensure the type is created in the database
)

class ScanRecord(Base):
    __tablename__ = 'scan_records'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, nullable=False)
    url = Column(String, nullable=False)
    status = Column(status_enum, default='0')
    scan_type = Column(String, nullable=False)
    result = Column(String, nullable=True)
    submission_type = Column(String, nullable=True)
    scan_id = Column(String, nullable=True)
    sha256 = Column(String, nullable=True)
    threat_score = Column(Integer, nullable=True)  # New field for threat score
    verdict = Column(String, nullable=True)  # New field for verdict

def create_db_engine(database_path):
    if database_path.startswith("postgresql"):
        return create_engine(database_path)        
    
    return create_engine(f'sqlite:///{database_path}', connect_args={"check_same_thread": False}, echo=True)

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
