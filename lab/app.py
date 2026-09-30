"""
World Monitor Lab - Intentionally Vulnerable Target Application
Simulates an intelligence monitoring and telemetry dashboard with labeled security flaws.
Controlled environment: localhost only.
"""

import time
import html
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, Header, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import text

from lab.database import get_db, init_db, User, Report, Telemetry, SystemLog
from lab.seed import seed_lab, hash_pw
from lab.vuln_config import vuln_config

app = FastAPI(
    title="World Monitor Lab (Target Replica)",
    description="INTENTIONALLY VULNERABLE LAB TARGET - controlled environment for SIH26163 security assessment",
    version="1.0.0-lab"
)

# CORS configuration for lab
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Rate limiting tracking (in-memory for lab)
login_attempts = {}

@app.on_event("startup")
def startup_event():
    init_db()
    seed_lab()

# Middleware for Secure Communication flaw
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response: Response = await call_next(request)
    
    if vuln_config.is_fixed("COMM_MISSING_HEADERS"):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    else:
        # Intentionally remove or omit security headers
        for h in ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Strict-Transport-Security"]:
            if h in response.headers:
                del response.headers[h]
                
    # Always include label header for clear identification
    response.headers["X-Target-Type"] = "INTENTIONALLY VULNERABLE LAB TARGET - controlled environment"
    return response

# Schemas
class LoginRequest(BaseModel):
    username: str
    password: str

class NoteRequest(BaseModel):
    notes: str

# Auth Dependency
def get_current_user(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)) -> Optional[User]:
    if not authorization:
        return None
    token = authorization.replace("Bearer ", "").strip()
    
    # Flaw 1: Weak JWT/Static Token check
    # If not fixed, predictable token formats and weak token validation allow arbitrary forged tokens
    user = db.query(User).filter(User.api_token == token).first()
    if not user:
        if not vuln_config.is_fixed("AUTH_WEAK_SECRET"):
            # Vulnerable: Accepts backdoor test token if signed with weak secret key "secret123"
            if token.startswith("wm_forged_admin_"):
                return db.query(User).filter(User.role == "admin").first()
    return user

# ==================== LAB CONTROL & STATUS ====================
@app.get("/api/health")
def health_check():
    return {
        "status": "healthy",
        "service": "World Monitor Lab Target",
        "mode": "INTENTIONALLY VULNERABLE LAB TARGET - controlled environment",
        "timestamp": time.time()
    }

@app.get("/api/lab/status")
def lab_status():
    return {
        "target": "World Monitor Lab",
        "environment": "INTENTIONALLY VULNERABLE LAB TARGET - controlled environment",
        "patches": vuln_config.get_status()
    }

@app.post("/api/lab/patch/{vuln_key}")
def toggle_patch(vuln_key: str, enable: bool = Query(True)):
    if vuln_key not in vuln_config.patches:
        raise HTTPException(status_code=404, detail=f"Vulnerability key {vuln_key} not recognized.")
    if enable:
        vuln_config.apply_fix(vuln_key)
    else:
        vuln_config.reset_fix(vuln_key)
    return {
        "vuln_key": vuln_key,
        "is_fixed": vuln_config.is_fixed(vuln_key),
        "status": vuln_config.get_status()
    }

# ==================== AUTHENTICATION & SESSION ====================
@app.post("/api/auth/login")
def login(creds: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "127.0.0.1"

    # Flaw 7: API Security - Lack of rate limiting on sensitive login endpoint
    if vuln_config.is_fixed("API_NO_RATE_LIMIT"):
        now = time.time()
        attempts = login_attempts.get(ip, [])
        # Filter attempts in last 60 seconds
        attempts = [t for t in attempts if now - t < 60]
        login_attempts[ip] = attempts
        if len(attempts) >= 5:
            raise HTTPException(
                status_code=429,
                detail="Rate limit exceeded: 5 failed attempts allowed per minute. IP throttled."
            )

    user = db.query(User).filter(User.username == creds.username).first()
    if not user or user.password_hash != hash_pw(creds.password, user.salt):
        if vuln_config.is_fixed("API_NO_RATE_LIMIT"):
            login_attempts.setdefault(ip, []).append(time.time())
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Flaw 1: Weak JWT Secret / Predictable token emission
    return {
        "access_token": user.api_token,
        "token_type": "bearer",
        "user_id": user.id,
        "username": user.username,
        "role": user.role,
        "warning": "Lab dummy token"
    }

# ==================== USER PROFILE (EXCESSIVE DATA EXPOSURE) ====================
@app.get("/api/users/profile")
def get_user_profile(user: Optional[User] = Depends(get_current_user)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Flaw 6: API Security - Excessive Data Exposure
    if vuln_config.is_fixed("API_EXCESSIVE_DATA"):
        # Sanitized response: only necessary public profile fields
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "created_at": user.created_at.isoformat()
        }
    else:
        # VULNERABLE: Leaks full database record including password hash, salt, recovery codes, and internal IP!
        return {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "password_hash": user.password_hash,
            "salt": user.salt,
            "recovery_codes": user.recovery_codes,
            "internal_ip": user.internal_ip,
            "created_at": user.created_at.isoformat()
        }

# ==================== REPORTS (IDOR, SQLi, STORED XSS) ====================
@app.get("/api/reports")
def list_reports(search: Optional[str] = None, user: Optional[User] = Depends(get_current_user), db: Session = Depends(get_db)):
    # Flaw 4: Input Validation - SQL Injection in search parameter
    if search:
        if vuln_config.is_fixed("INPUT_SQLI_SEARCH"):
            # SAFE: Parameterized ORM filter
            results = db.query(Report).filter(Report.title.ilike(f"%{search}%")).all()
        else:
            # VULNERABLE: Raw SQL string concatenation allows SQL Injection
            raw_query = f"SELECT id, title, classification, summary, content, notes, author_id FROM reports WHERE title LIKE '%{search}%'"
            try:
                cursor = db.execute(text(raw_query))
                rows = cursor.fetchall()
                results = []
                for r in rows:
                    results.append({
                        "id": r[0],
                        "title": r[1],
                        "classification": r[2],
                        "summary": r[3],
                        "content": r[4],
                        "notes": r[5],
                        "author_id": r[6]
                    })
                return results
            except Exception as e:
                # Exposes SQL syntax error in response
                raise HTTPException(status_code=500, detail=f"Database query error: {str(e)}")
    else:
        results = db.query(Report).all()

    return [
        {
            "id": r.id,
            "title": r.title,
            "classification": r.classification,
            "summary": r.summary,
            "content": r.content,
            "notes": r.notes,
            "author_id": r.author_id
        }
        for r in results
    ]

@app.get("/api/reports/{report_id}")
def get_report_detail(report_id: int, user: Optional[User] = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Flaw 2: Authorization - Broken Object Level Authorization (IDOR)
    if vuln_config.is_fixed("AUTHZ_IDOR_REPORT"):
        # SAFE: Role and ownership checks enforced
        if report.classification == "RESTRICTED_TOP_SECRET" and user.role not in ["admin"]:
            raise HTTPException(status_code=403, detail="Access denied: Report requires TOP_SECRET clearance")
        if report.classification == "INTERNAL" and user.role not in ["admin", "analyst"]:
            raise HTTPException(status_code=403, detail="Access denied: Report requires INTERNAL clearance")
    else:
        # VULNERABLE: Viewer can access RESTRICTED_TOP_SECRET report 3 and 4 directly by ID!
        pass

    return {
        "id": report.id,
        "title": report.title,
        "classification": report.classification,
        "summary": report.summary,
        "content": report.content,
        "notes": report.notes,
        "author_id": report.author_id
    }

@app.post("/api/reports/{report_id}/notes")
def update_report_notes(report_id: int, note_data: NoteRequest, user: Optional[User] = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Flaw 5: Input Validation - Stored Cross-Site Scripting (XSS)
    if vuln_config.is_fixed("INPUT_STORED_XSS"):
        # SAFE: Input sanitized and HTML-encoded
        sanitized_note = html.escape(note_data.notes)
        report.notes = sanitized_note
    else:
        # VULNERABLE: Stores raw unsanitized HTML / JavaScript payload
        report.notes = note_data.notes

    db.commit()
    return {
        "id": report.id,
        "notes": report.notes,
        "status": "updated"
    }

# ==================== TELEMETRY & BFLA ====================
@app.get("/api/telemetry/live")
def get_live_telemetry(db: Session = Depends(get_db)):
    telemetries = db.query(Telemetry).all()
    return [
        {
            "id": t.id,
            "station_code": t.station_code,
            "satellite_id": t.satellite_id,
            "signal_strength": t.signal_strength,
            "coordinates": t.coordinates,
            "recorded_at": t.recorded_at.isoformat()
        }
        for t in telemetries
    ]

@app.get("/api/admin/telemetry-export")
def export_bulk_telemetry(user: Optional[User] = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    # Flaw 3: Authorization - Broken Function Level Authorization (BFLA)
    if vuln_config.is_fixed("AUTHZ_BFLA_EXPORT"):
        # SAFE: Restrict function strictly to admin role
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="Forbidden: Administrative privilege required for bulk telemetry export")
    else:
        # VULNERABLE: Viewer/Analyst tokens can invoke admin export endpoint without error
        pass

    telemetry_data = db.query(Telemetry).all()
    return {
        "export_status": "SUCCESS",
        "exported_by": user.username,
        "user_role": user.role,
        "total_records": len(telemetry_data),
        "data": [
            {
                "station": t.station_code,
                "satellite": t.satellite_id,
                "signal": t.signal_strength,
                "coords": t.coordinates
            }
            for t in telemetry_data
        ]
    }

# ==================== CLIENT CONFIG (SECRET LEAK) ====================
@app.get("/api/config/client")
def get_client_config():
    # Flaw 8: Client-Side Controls - Leaked sensitive API credentials and gateway
    if vuln_config.is_fixed("CLIENT_KEY_LEAK"):
        return {
            "appName": "World Monitor System",
            "environment": "production",
            "telemetryRefreshMs": 5000,
            "version": "2.4.1"
        }
    else:
        return {
            "appName": "World Monitor System",
            "environment": "staging-restricted",
            "telemetryRefreshMs": 5000,
            "version": "2.4.1",
            "SATELLITE_UPLINK_KEY": "sk_live_ntro_9921_classified",
            "INTERNAL_GATEWAY_URL": "http://gateway.internal.ntro.local:9000/uplink",
            "DEBUG_SECRET_TOKEN": "wm_debug_master_bypass_9812"
        }

# ==================== SYSTEM LOGS (DATA PRIVACY / CLEARTEXT TOKENS) ====================
@app.get("/api/admin/system-logs")
def get_system_logs(user: Optional[User] = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")

    logs = db.query(SystemLog).order_by(SystemLog.id.desc()).limit(20).all()

    # Flaw 10: Data Storage & Privacy - Cleartext sensitive credentials in logs
    if vuln_config.is_fixed("DATA_CLEARTEXT_LOGS"):
        masked = []
        for l in logs:
            safe_msg = l.message.replace("wm_sec_token_adm_9941", "wm_sec_token_***")
            safe_ctx = (l.context or "").replace("wm_sec_token_adm_9941", "wm_sec_token_***")
            masked.append({
                "id": l.id,
                "level": l.level,
                "message": safe_msg,
                "context": safe_ctx,
                "timestamp": l.timestamp.isoformat()
            })
        return masked
    else:
        return [
            {
                "id": l.id,
                "level": l.level,
                "message": l.message,
                "context": l.context,
                "timestamp": l.timestamp.isoformat()
            }
            for l in logs
        ]
