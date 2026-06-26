import os
import uuid
import datetime
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from backend.config import settings, logger
from backend.database import engine, Base, get_db
from backend.models import User, LogFile, Alert, IncidentReport
from backend import schemas
from backend import auth
from backend.parser import parse_log_file, process_parsed_events
from backend.ai_analyzer import analyze_threat_ai, ask_chatbot_ai
from backend.reporter import generate_pdf_report

# Initialize DB tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="AI SOC Assistant API", version="1.0.0")

# CORS Configurations - strictly configure allowed origin for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Initialize a default admin user if none exists
@app.on_event("startup")
def startup_event():
    db = next(get_db())
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            hashed_pwd = auth.get_password_hash("AdminSocPass123!")
            admin_user = User(
                username="admin",
                password_hash=hashed_pwd,
                role="Admin"
            )
            db.add(admin_user)
            db.commit()
            logger.info("Default administrator 'admin' initialized successfully.")
    except Exception as e:
        logger.error(f"Startup DB initialization failed: {e}")
    finally:
        db.close()


# ----------------------------------------------------
# AUTHENTICATION ROUTERS
# ----------------------------------------------------
@app.post("/api/auth/register", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
def register(user_in: schemas.UserCreate, db: Session = Depends(get_db)):
    # Check if username exists
    existing = db.query(User).filter(User.username == user_in.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username is already taken")
    
    try:
        hashed_password = auth.get_password_hash(user_in.password)
    except ValueError as val_err:
        raise HTTPException(status_code=400, detail=str(val_err))
        
    new_user = User(
        username=user_in.username,
        password_hash=hashed_password,
        role=user_in.role if user_in.role in ["Admin", "Analyst"] else "Analyst"
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/api/auth/login", response_model=schemas.Token)
def login(form_data: schemas.UserCreate, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not auth.verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token = auth.create_access_token(data={"sub": user.username, "role": user.role})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username
    }


# ----------------------------------------------------
# LOG FILES MODULE
# ----------------------------------------------------
@app.post("/api/logs/upload", response_model=schemas.LogFileResponse)
def upload_log(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.require_analyst)
):
    # 1. Check file size (e.g. limit to 5MB)
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    content = file.file.read(MAX_FILE_SIZE + 1)
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File exceeds maximum allowed size (5MB)")
    file.file.seek(0)  # Reset pointer

    # 2. Check file extension (allow-list validation)
    orig_filename = os.path.basename(file.filename)
    _, ext = os.path.splitext(orig_filename.lower())
    if ext not in [".csv", ".json", ".txt"]:
        raise HTTPException(status_code=400, detail="Unsupported file format. Only .csv, .json, and .txt are allowed.")

    # 3. Generate unique random storage filename
    secure_filename = f"{uuid.uuid4().hex}{ext}"
    target_path = os.path.join(settings.UPLOAD_DIR, secure_filename)

    # 4. Resolve absolute paths and check boundary limits
    resolved_path = os.path.abspath(target_path)
    resolved_dir = os.path.abspath(settings.UPLOAD_DIR)
    if not resolved_path.startswith(resolved_dir + os.sep) and resolved_path != resolved_dir:
        raise HTTPException(status_code=400, detail="Invalid target upload path.")

    # 5. Write to disk outside the web root
    try:
        with open(resolved_path, "wb") as f:
            f.write(file.file.read())
    except Exception as e:
        logger.error(f"Failed to write uploaded file to disk: {e}")
        raise HTTPException(status_code=500, detail="Server failed to save log file.")

    # 6. Save LogFile record in DB
    log_record = LogFile(
        filename=secure_filename,
        original_filename=orig_filename,
        file_path=resolved_path,
        file_size=len(content),
        status="Pending",
        uploaded_by=current_user.id
    )
    db.add(log_record)
    db.commit()
    db.refresh(log_record)

    # 7. Parse and detect threat alerts
    try:
        events = parse_log_file(resolved_path, ext)
        alerts_found = process_parsed_events(events, log_record.id, db)
        
        log_record.status = "Parsed"
        db.commit()
        logger.info(f"Log file {orig_filename} parsed successfully. Created {alerts_found} threat alerts.")
    except Exception as parse_err:
        logger.error(f"Error parsing log file {orig_filename}: {parse_err}")
        log_record.status = "Failed"
        db.commit()
        raise HTTPException(status_code=400, detail=f"Log parsing failure: {str(parse_err)}")

    return log_record

@app.get("/api/logs/history", response_model=List[schemas.LogFileResponse])
def get_log_history(db: Session = Depends(get_db), current_user: User = Depends(auth.require_analyst)):
    return db.query(LogFile).order_by(LogFile.uploaded_at.desc()).all()


# ----------------------------------------------------
# ALERTS MODULE
# ----------------------------------------------------
@app.get("/api/alerts", response_model=List[schemas.AlertResponse])
def get_alerts(
    source_ip: Optional[str] = None,
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.require_analyst)
):
    query = db.query(Alert)

    # Apply filters
    if source_ip:
        query = query.filter(Alert.source_ip.contains(source_ip))
    if threat_type:
        query = query.filter(Alert.threat_type == threat_type)
    if status:
        query = query.filter(Alert.status == status)
    if severity:
        try:
            # Handle severity range or single value
            if severity.lower() == "critical":
                query = query.filter(Alert.severity >= 9)
            elif severity.lower() == "high":
                query = query.filter(Alert.severity.between(7, 8))
            elif severity.lower() == "medium":
                query = query.filter(Alert.severity.between(4, 6))
            elif severity.lower() == "low":
                query = query.filter(Alert.severity.between(1, 3))
            else:
                query = query.filter(Alert.severity == int(severity))
        except ValueError:
            pass

    if date_from:
        try:
            dt_from = datetime.datetime.strptime(date_from, "%Y-%m-%d")
            query = query.filter(Alert.timestamp >= dt_from)
        except ValueError:
            pass
    if date_to:
        try:
            # include entire end day
            dt_to = datetime.datetime.strptime(date_to, "%Y-%m-%d") + datetime.timedelta(days=1)
            query = query.filter(Alert.timestamp < dt_to)
        except ValueError:
            pass

    return query.order_by(Alert.timestamp.desc()).all()

@app.put("/api/alerts/{id}/status", response_model=schemas.AlertResponse)
def update_alert_status(
    id: int,
    status_update: schemas.AlertStatusUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.require_analyst)
):
    alert = db.query(Alert).filter(Alert.id == id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    
    alert.status = status_update.status
    db.commit()
    db.refresh(alert)
    return alert

@app.get("/api/alerts/{id}/ai-explain")
def explain_alert(id: int, db: Session = Depends(get_db), current_user: User = Depends(auth.require_analyst)):
    alert = db.query(Alert).filter(Alert.id == id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    explanation = analyze_threat_ai(
        alert_type=alert.threat_type,
        mitre_id=alert.mitre_id or "N/A",
        source_ip=alert.source_ip,
        target=alert.target_system or "System Boundary",
        payload=alert.raw_log_payload or alert.description or "No raw context available"
    )
    return {"explanation": explanation}


# ----------------------------------------------------
# CHATBOT FEATURE
# ----------------------------------------------------
@app.post("/api/chat", response_model=schemas.ChatResponse)
def chat_with_assistant(
    chat_msg: schemas.ChatMessage,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.require_analyst)
):
    context_alert = None
    if chat_msg.alert_id:
        alert = db.query(Alert).filter(Alert.id == chat_msg.alert_id).first()
        if alert:
            context_alert = {
                "id": alert.id,
                "threat_type": alert.threat_type,
                "mitre_id": alert.mitre_id,
                "source_ip": alert.source_ip,
                "target_system": alert.target_system,
                "severity": alert.severity,
                "description": alert.description
            }

    response_text = ask_chatbot_ai(chat_msg.message, context_alert)
    return {"response": response_text, "alert_id": chat_msg.alert_id}


# ----------------------------------------------------
# INCIDENT REPORT GENERATOR
# ----------------------------------------------------
@app.post("/api/reports/generate", response_model=schemas.IncidentReportResponse)
def create_report(
    report_in: schemas.IncidentReportCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.require_analyst)
):
    # Verify alert exists
    alert = db.query(Alert).filter(Alert.id == report_in.alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Trigger alert not found")

    # Check if a report already exists for this alert
    existing_report = db.query(IncidentReport).filter(IncidentReport.alert_id == report_in.alert_id).first()
    if existing_report:
        # Update the existing report with the new user input details
        existing_report.summary = report_in.summary
        existing_report.recommended_remediation = report_in.recommended_remediation
        existing_report.created_by = current_user.id
        db.commit()
        report = existing_report
    else:
        # Create a new report
        report = IncidentReport(
            alert_id=report_in.alert_id,
            summary=report_in.summary,
            recommended_remediation=report_in.recommended_remediation,
            created_by=current_user.id
        )
        db.add(report)
        db.commit()
        db.refresh(report)

    # Generate the PDF report on disk
    alert_dict = {
        "id": alert.id,
        "threat_type": alert.threat_type,
        "mitre_id": alert.mitre_id,
        "source_ip": alert.source_ip,
        "destination_ip": alert.destination_ip,
        "target_system": alert.target_system,
        "timestamp": alert.timestamp,
        "severity": alert.severity,
        "raw_log_payload": alert.raw_log_payload
    }
    
    try:
        pdf_path = generate_pdf_report(
            alert_data=alert_dict,
            summary=report.summary,
            remediation=report.recommended_remediation,
            analyst_name=current_user.username
        )
        report.pdf_path = pdf_path
        db.commit()
        db.refresh(report)
    except Exception as e:
        logger.error(f"Could not generate PDF: {e}")
        # Return DB record even if PDF fails
        pass

    return report

@app.get("/api/reports/history", response_model=List[schemas.IncidentReportResponse])
def get_reports_history(db: Session = Depends(get_db), current_user: User = Depends(auth.require_analyst)):
    return db.query(IncidentReport).order_by(IncidentReport.created_at.desc()).all()

@app.get("/api/reports/{id}/download")
def download_pdf_report(
    id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(auth.require_analyst)
):
    report = db.query(IncidentReport).filter(IncidentReport.id == id).first()
    if not report or not report.pdf_path:
        raise HTTPException(status_code=404, detail="Incident report or PDF file not found")
        
    resolved_path = os.path.abspath(report.pdf_path)
    resolved_dir = os.path.abspath(settings.REPORTS_DIR)
    if not resolved_path.startswith(resolved_dir + os.sep) and resolved_path != resolved_dir:
        raise HTTPException(status_code=400, detail="Invalid file download path request.")

    if not os.path.exists(resolved_path):
        raise HTTPException(status_code=404, detail="Report PDF file does not exist on disk")

    return FileResponse(
        resolved_path,
        media_type="application/pdf",
        filename=os.path.basename(resolved_path),
        headers={
            "Content-Disposition": f"attachment; filename={os.path.basename(resolved_path)}",
            "X-Content-Type-Options": "nosniff"
        }
    )


# ----------------------------------------------------
# DASHBOARD STATS
# ----------------------------------------------------
@app.get("/api/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db), current_user: User = Depends(auth.require_analyst)):
    # Total alerts count
    total_alerts = db.query(Alert).count()
    
    # Severity breakdown
    critical_alerts = db.query(Alert).filter(Alert.severity >= 9).count()
    high_alerts = db.query(Alert).filter(Alert.severity.between(7, 8)).count()
    medium_alerts = db.query(Alert).filter(Alert.severity.between(4, 6)).count()
    low_alerts = db.query(Alert).filter(Alert.severity.between(1, 3)).count()

    # Top attacker IPs (Group by source_ip and count)
    top_attackers_query = db.query(
        Alert.source_ip,
        func.count(Alert.id).label("count")
    ).group_by(Alert.source_ip).order_by(func.count(Alert.id).desc()).limit(5).all()
    
    top_attackers = [{"ip": ip, "count": count} for ip, count in top_attackers_query]

    # Threat Type Pie Chart
    threat_types_query = db.query(
        Alert.threat_type,
        func.count(Alert.id).label("count")
    ).group_by(Alert.threat_type).all()
    
    threat_types = {t_type: count for t_type, count in threat_types_query}

    # Recent Attack Timeline (last 10 alerts)
    recent_timeline_query = db.query(Alert).order_by(Alert.timestamp.desc()).limit(15).all()
    recent_timeline = [
        {
            "id": a.id,
            "timestamp": a.timestamp,
            "threat_type": a.threat_type,
            "source_ip": a.source_ip,
            "severity": a.severity,
            "status": a.status
        }
        for a in recent_timeline_query
    ]

    return {
        "total_alerts": total_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "top_attackers": top_attackers,
        "threat_types": threat_types,
        "recent_timeline": recent_timeline
    }
