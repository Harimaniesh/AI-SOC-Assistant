import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from backend.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), default="Analyst", nullable=False)  # Admin or Analyst
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    uploaded_files = relationship("LogFile", back_populates="uploader")
    reports = relationship("IncidentReport", back_populates="creator")

class LogFile(Base):
    __tablename__ = "log_files"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String(255), unique=True, nullable=False)  # Unique secure UUID filename
    original_filename = Column(String(255), nullable=False)
    file_path = Column(String(512), nullable=False)
    file_size = Column(Integer, nullable=False)
    status = Column(String(50), default="Pending", nullable=False)  # Pending, Parsed, Failed
    uploaded_by = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    uploaded_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    uploader = relationship("User", back_populates="uploaded_files")
    alerts = relationship("Alert", back_populates="log_file", cascade="all, delete-orphan")

class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    log_file_id = Column(Integer, ForeignKey("log_files.id", ondelete="SET NULL"), nullable=True)
    timestamp = Column(DateTime, index=True, nullable=False)
    source_ip = Column(String(50), index=True, nullable=False)
    destination_ip = Column(String(50), index=True, nullable=False)
    threat_type = Column(String(100), index=True, nullable=False)  # Brute Force, Port Scanning, Malware Execution, Privilege Escalation, Suspicious IP
    severity = Column(Integer, index=True, nullable=False)  # Risk score (1-10)
    mitre_id = Column(String(50), index=True, nullable=True)   # T1110, T1046, T1068, T1204
    status = Column(String(50), default="New", nullable=False)  # New, In Progress, Resolved, Dismissed
    description = Column(Text, nullable=True)
    target_system = Column(String(255), nullable=True)
    raw_log_payload = Column(Text, nullable=True)

    log_file = relationship("LogFile", back_populates="alerts")
    incident_report = relationship("IncidentReport", uselist=False, back_populates="alert", cascade="all, delete-orphan")

class IncidentReport(Base):
    __tablename__ = "incident_reports"

    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), unique=True, nullable=False)
    summary = Column(Text, nullable=False)
    recommended_remediation = Column(Text, nullable=False)
    pdf_path = Column(String(512), nullable=True)
    created_by = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, nullable=False)

    alert = relationship("Alert", back_populates="incident_report")
    creator = relationship("User", back_populates="reports")
