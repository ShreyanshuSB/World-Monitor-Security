"""
World Monitor Lab - Database Models and Initialization (SQLite)
Target replica database containing realistic intelligence dashboard datasets.
"""

import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime, Float
from sqlalchemy.orm import declarative_base, sessionmaker

LAB_DB_PATH = os.path.join(os.path.dirname(__file__), "lab.db")
DATABASE_URL = f"sqlite:///{LAB_DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(200), nullable=False)
    salt = Column(String(50), nullable=False)
    role = Column(String(20), nullable=False)  # admin, analyst, viewer
    api_token = Column(String(100), unique=True, nullable=False)
    recovery_codes = Column(String(200), nullable=True)  # Seeded sensitive PII
    internal_ip = Column(String(50), nullable=True)      # Seeded sensitive infrastructure data
    created_at = Column(DateTime, default=datetime.utcnow)

class Report(Base):
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(200), nullable=False)
    classification = Column(String(50), nullable=False)  # PUBLIC, RESTRICTED, TOP_SECRET
    summary = Column(Text, nullable=False)
    content = Column(Text, nullable=False)
    notes = Column(Text, default="")
    author_id = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Telemetry(Base):
    __tablename__ = "telemetry"

    id = Column(Integer, primary_key=True, index=True)
    station_code = Column(String(50), nullable=False)
    satellite_id = Column(String(50), nullable=False)
    signal_strength = Column(Float, nullable=False)
    coordinates = Column(String(100), nullable=False)
    recorded_at = Column(DateTime, default=datetime.utcnow)

class SystemLog(Base):
    __tablename__ = "system_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    level = Column(String(20), default="INFO")
    message = Column(Text, nullable=False)
    context = Column(Text, nullable=True)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
