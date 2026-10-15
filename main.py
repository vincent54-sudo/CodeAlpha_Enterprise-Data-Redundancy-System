from fastapi import FastAPI, UploadFile, File, HTTPException, Header, Depends, Form
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional
from pathlib import Path
import pandas as pd
import io
import datetime
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from rapidfuzz import fuzz
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

app = FastAPI(title="Data Redundancy Removal System - Commercial Edition")

STATIC_DIR = Path(__file__).resolve().parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def serve_homepage():
    return FileResponse(STATIC_DIR / "login.html")


@app.get("/client", include_in_schema=False)
async def serve_client_page():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/admin", include_in_schema=False)
async def serve_admin_page():
    return FileResponse(STATIC_DIR / "admin.html")


DB_FILE = os.getenv(
    "DB_FILE",
    str(Path(__file__).resolve().parent / "redundancy_history.db"),
)
PASSWORD_ROUNDS = 310_000
ACCESS_TOKEN_HOURS = 12


class RegisterRequest(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=10, max_length=128)


class LoginRequest(BaseModel):
    email: str
    password: str


def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    salt = salt or secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ROUNDS)
    return salt.hex(), password_hash.hex()


def verify_password(password: str, salt_hex: str, expected_hash: str) -> bool:
    _, password_hash = hash_password(password, bytes.fromhex(salt_hex))
    return hmac.compare_digest(password_hash, expected_hash)


def hash_access_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def init_db():
    Path(DB_FILE).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS job_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            filename TEXT,
            timestamp TEXT,
            original_rows INTEGER,
            cleaned_rows INTEGER,
            duplicates_removed INTEGER,
            redundancy_percentage REAL,
            health_score REAL
        )
    ''')
    columns = {row[1] for row in cursor.execute("PRAGMA table_info(job_logs)")}
    if "health_score" not in columns:
        cursor.execute("ALTER TABLE job_logs ADD COLUMN health_score REAL")
    if "user_id" not in columns:
        cursor.execute("ALTER TABLE job_logs ADD COLUMN user_id INTEGER")
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('client', 'admin')),
            created_at TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS auth_tokens (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL
        )
    ''')
    admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    if admin_email and admin_password:
        salt, password_hash = hash_password(admin_password)
        cursor.execute('''
            INSERT INTO users (full_name, email, password_salt, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, 'admin', ?)
            ON CONFLICT(email) DO UPDATE SET
                full_name = excluded.full_name,
                password_salt = excluded.password_salt,
                password_hash = excluded.password_hash,
                role = 'admin'
        ''', (
            os.getenv("ADMIN_NAME", "System Administrator"),
            admin_email,
            salt,
            password_hash,
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        ))
    conn.commit()
    conn.close()

init_db()


@app.get("/health", include_in_schema=False)
async def health_check():
    return {"status": "ok"}


def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Sign in is required")
    token = authorization[7:].strip()
    if not token:
        raise HTTPException(status_code=401, detail="Invalid access token")

    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT users.id, users.full_name, users.email, users.role
        FROM auth_tokens
        JOIN users ON users.id = auth_tokens.user_id
        WHERE auth_tokens.token_hash = ? AND auth_tokens.expires_at > ?
    ''', (hash_access_token(token), datetime.datetime.now(datetime.timezone.utc).isoformat()))
    user = cursor.fetchone()
    conn.close()
    if user is None:
        raise HTTPException(status_code=401, detail="Access token is invalid or expired")
    return dict(user)


def require_admin(current_user: dict = Depends(get_current_user)) -> dict:
    if current_user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Administrator access is required")
    return current_user


@app.post("/auth/register", status_code=201)
async def register_account(request: RegisterRequest):
    full_name = request.full_name.strip()
    email = request.email.strip().lower()
    if len(full_name) < 2 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        raise HTTPException(status_code=400, detail="Enter a valid name and email address")

    salt, password_hash = hash_password(request.password)
    conn = sqlite3.connect(DB_FILE)
    try:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO users (full_name, email, password_salt, password_hash, role, created_at)
            VALUES (?, ?, ?, ?, 'client', ?)
        ''', (
            full_name,
            email,
            salt,
            password_hash,
            datetime.datetime.now(datetime.timezone.utc).isoformat(),
        ))
        conn.commit()
        return {"status": "created", "role": "client"}
    except sqlite3.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="An account with this email already exists") from exc
    finally:
        conn.close()


@app.post("/auth/login")
async def login(request: LoginRequest):
    email = request.email.strip().lower()
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()
    if user is None or not verify_password(request.password, user["password_salt"], user["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Email or password is incorrect")

    token = secrets.token_urlsafe(32)
    expires_at = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=ACCESS_TOKEN_HOURS)
    cursor.execute(
        "INSERT INTO auth_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
        (hash_access_token(token), user["id"], expires_at.isoformat()),
    )
    conn.commit()
    user_data = {"id": user["id"], "full_name": user["full_name"], "email": user["email"], "role": user["role"]}
    conn.close()
    return {"access_token": token, "token_type": "bearer", "user": user_data}


@app.get("/auth/me")
async def get_account(current_user: dict = Depends(get_current_user)):
    return current_user


@app.post("/auth/logout")
async def logout(
    current_user: dict = Depends(get_current_user),
    authorization: str = Header(...),
):
    token = authorization[7:].strip()
    conn = sqlite3.connect(DB_FILE)
    conn.execute("DELETE FROM auth_tokens WHERE token_hash = ?", (hash_access_token(token),))
    conn.commit()
    conn.close()
    return {"status": "signed out"}


@app.get("/admin/overview")
async def admin_overview(current_user: dict = Depends(require_admin)):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, full_name, email, role, created_at FROM users ORDER BY id")
    users = [dict(row) for row in cursor.fetchall()]
    cursor.execute('''
        SELECT job_logs.*, users.email AS user_email
        FROM job_logs LEFT JOIN users ON users.id = job_logs.user_id
        ORDER BY job_logs.id DESC LIMIT 100
    ''')
    jobs = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"users": users, "jobs": jobs}

def load_dataframe_from_upload(contents: bytes, filename: str) -> pd.DataFrame:
    lower_name = filename.lower()
    try:
        if lower_name.endswith('.csv'):
            return pd.read_csv(io.BytesIO(contents))
        elif lower_name.endswith(('.xlsx', '.xls')):
            return pd.read_excel(io.BytesIO(contents))
        elif lower_name.endswith('.json'):
            return pd.read_json(io.BytesIO(contents))
        else:
            return pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Could not parse file format. Error: {str(e)}")

@app.post("/redundancy/analyze", dependencies=[Depends(get_current_user)])
async def analyze_dataset(file: UploadFile = File(...)):
    try:
        contents = await file.read()
        df = load_dataframe_from_upload(contents, file.filename)
        df = df.fillna("")
        return {
            "filename": file.filename,
            "columns": list(df.columns),
            "total_rows": len(df),
            "sample_data": df.head(5).values.tolist()
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid file format: {str(e)}")

@app.post("/redundancy/process", dependencies=[Depends(get_current_user)])
async def process_redundancy_removal(
    file: UploadFile = File(...),
    subset_cols: Optional[str] = Form(None),
    keep_policy: str = Form("first"),
    ignore_case: bool = Form(False),
    enable_fuzzy: bool = Form(False),
    fuzzy_col: Optional[str] = Form(None),
    fuzzy_threshold: int = Form(85),
    current_user: dict = Depends(get_current_user),
):
    try:
        contents = await file.read()
        df = load_dataframe_from_upload(contents, file.filename)
        df = df.fillna("")

        original_row_count = len(df)

        subset_list = [col.strip() for col in subset_cols.split(",")] if subset_cols else None
        if subset_list:
            subset_list = [col for col in subset_list if col in df.columns]
            if not subset_list:
                subset_list = None

        if enable_fuzzy and fuzzy_col and fuzzy_col in df.columns:
            kept_indices = []
            duplicate_indices = []
            values = df[fuzzy_col].astype(str).tolist()

            for i, val in enumerate(values):
                is_dup = False
                val_clean = val.lower().strip()
                if not val_clean:
                    kept_indices.append(i)
                    continue

                for kept_idx in kept_indices:
                    kept_val = values[kept_idx].lower().strip()
                    similarity = fuzz.ratio(val_clean, kept_val)
                    if similarity >= fuzzy_threshold:
                        is_dup = True
                        break

                if is_dup:
                    duplicate_indices.append(i)
                else:
                    kept_indices.append(i)

            df_cleaned = df.iloc[kept_indices].copy()
            df_duplicates = df.iloc[duplicate_indices].copy()
        else:
            df_comp = df.copy()
            if ignore_case:
                for col in df_comp.columns:
                    if df_comp[col].dtype == object or pd.api.types.is_string_dtype(df_comp[col]):
                        df_comp[col] = df_comp[col].astype(str).str.lower().str.strip()

            duplicates_mask = df_comp.duplicated(subset=subset_list, keep=keep_policy)
            df_duplicates = df[duplicates_mask]
            df_cleaned = df[~duplicates_mask].copy()

        cleaned_row_count = len(df_cleaned)
        duplicates_removed = len(df_duplicates)
        redundancy_percentage = round((duplicates_removed / original_row_count * 100), 2) if original_row_count > 0 else 0.0

        # Calculate Enterprise Data Health Score (100 minus penalty for redundancy and empty fields)
        missing_values_count = (df == "").sum().sum()
        missing_penalty = min(20, (missing_values_count / (original_row_count * max(1, len(df.columns)))) * 20)
        health_score = round(max(0.0, min(100.0, 100.0 - redundancy_percentage - missing_penalty)), 1)

        timestamp_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO job_logs (user_id, filename, timestamp, original_rows, cleaned_rows, duplicates_removed, redundancy_percentage, health_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (current_user["id"], file.filename, timestamp_str, original_row_count, cleaned_row_count, duplicates_removed, redundancy_percentage, health_score))
        conn.commit()
        conn.close()

        return {
            "status": "Success",
            "filename": file.filename,
            "timestamp": timestamp_str,
            "metrics": {
                "original_rows": original_row_count,
                "cleaned_rows": cleaned_row_count,
                "duplicates_removed": duplicates_removed,
                "redundancy_percentage": redundancy_percentage,
                "health_score": health_score
            },
            "preview_columns": list(df_cleaned.columns),
            "preview_rows": df_cleaned.head(15).values.tolist(),
            "cleaned_csv_content": df_cleaned.to_csv(index=False),
            "cleaned_json_content": df_cleaned.to_json(orient="records", indent=4),
            "removed_csv_content": df_duplicates.to_csv(index=False),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to process dataset: {str(e)}")

@app.post("/redundancy/pdf-report", dependencies=[Depends(get_current_user)])
async def generate_pdf_report(
    filename: str = Form(...),
    original_rows: int = Form(...),
    cleaned_rows: int = Form(...),
    duplicates_removed: int = Form(...),
    redundancy_percentage: float = Form(...),
    health_score: float = Form(...)
):
    """Generates an official Executive PDF Compliance & Health Certificate."""
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    elements = []

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('DocTitle', parent=styles['Heading1'], fontSize=20, textColor=colors.HexColor('#2563eb'), spaceAfter=6)
    subtitle_style = ParagraphStyle('DocSub', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#6b7280'), spaceAfter=20)
    heading_style = ParagraphStyle('Heading', parent=styles['Heading2'], fontSize=14, textColor=colors.HexColor('#1f2937'), spaceBefore=12, spaceAfter=6)
    normal_style = ParagraphStyle('NormalText', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#374151'), spaceAfter=6)

    elements.append(Paragraph("Enterprise Data Redundancy Audit Certificate", title_style))
    elements.append(Paragraph(f"Generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | SaaS Pro Engine v7.0", subtitle_style))

    elements.append(Paragraph("1. Executive Summary", heading_style))
    summary_text = f"This document certifies that dataset <b>{filename}</b> was processed through the Enterprise Data Cleansing Engine. Below are the finalized data hygiene and redundancy metrics verified during the audit."
    elements.append(Paragraph(summary_text, normal_style))

    data_table = [
        ["Audit Metric Parameter", "Recorded Value"],
        ["Source Filename", filename],
        ["Original Dataset Rows", str(original_rows)],
        ["Optimized Cleaned Rows", str(cleaned_rows)],
        ["Redundant Duplicates Purged", str(duplicates_removed)],
        ["Redundancy Ratio (%)", f"{redundancy_percentage}%"],
        ["Data Quality Health Score", f"{health_score} / 100"]
    ]

    t = Table(data_table, colWidths=[260, 260])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.HexColor('#1e3a8a')),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f3f4f6')]),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#d1d5db'))
    ]))

    elements.append(Spacer(1, 10))
    elements.append(t)
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("2. Compliance & Verification Statement", heading_style))
    elements.append(Paragraph("The optimized dataset complies with standard data hygiene protocols, removing exact duplicates and fuzzy variations according to configured retention policies. This audit log is permanently secured in the enterprise history database.", normal_style))

    doc.build(elements)
    buffer.seek(0)

    return Response(content=buffer.getvalue(), media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename=Audit_Certificate_{filename}.pdf"})

@app.get("/redundancy/history")
async def get_job_history(current_user: dict = Depends(get_current_user)):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    if current_user["role"] == "admin":
        cursor.execute("SELECT * FROM job_logs ORDER BY id DESC LIMIT 25")
    else:
        cursor.execute("SELECT * FROM job_logs WHERE user_id = ? ORDER BY id DESC LIMIT 25", (current_user["id"],))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]