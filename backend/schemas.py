from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

# Auth Schemas
class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)

class UserCreate(UserBase):
    password: str = Field(..., min_length=8, max_length=128)
    role: Optional[str] = "Analyst"  # Admin or Analyst

class UserResponse(UserBase):
    id: int
    role: str
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str
    username: str

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None

# LogFile Schemas
class LogFileResponse(BaseModel):
    id: int
    original_filename: str
    file_size: int
    status: str
    uploaded_at: datetime
    uploaded_by: int

    class Config:
        from_attributes = True

# Alert Schemas
class AlertBase(BaseModel):
    timestamp: datetime
    source_ip: str
    destination_ip: str
    threat_type: str
    severity: int
    mitre_id: Optional[str] = None
    status: str
    target_system: Optional[str] = None

class AlertResponse(AlertBase):
    id: int
    log_file_id: Optional[int] = None
    description: Optional[str] = None
    raw_log_payload: Optional[str] = None

    class Config:
        from_attributes = True

class AlertStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(New|In Progress|Resolved|Dismissed)$")

# Incident Report Schemas
class IncidentReportCreate(BaseModel):
    alert_id: int
    summary: str
    recommended_remediation: str

class IncidentReportResponse(BaseModel):
    id: int
    alert_id: int
    summary: str
    recommended_remediation: str
    pdf_path: Optional[str] = None
    created_by: int
    created_at: datetime

    class Config:
        from_attributes = True

# Chatbot Schemas
class ChatMessage(BaseModel):
    message: str
    alert_id: Optional[int] = None

class ChatResponse(BaseModel):
    response: str
    alert_id: Optional[int] = None
