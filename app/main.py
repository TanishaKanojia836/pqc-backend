import sqlite3
from pathlib import Path
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Header, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    title="PQC Risk Assessor API",
    version="1.0.0",
    description="Defensive Post-Quantum Cryptography Risk Assessment Engine"
)

# --- 1. CORS Middleware Setup ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits requests from React frontend
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
)

# --- 2. Shared Team API Key Authentication ---
TEAM_API_KEY = "pqc_secret_team_key_2026"

def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")):
    if x_api_key != TEAM_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header"
        )
    return x_api_key


# --- 3. SQLite Database Helpers ---
DB_FILE = Path(__file__).parent.parent / "pqc-database.db"

def get_db_connection():
    # Fallback to local DB filename if main directory path differs
    db_path = DB_FILE if DB_FILE.exists() else "pqc-database.db"
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


# --- 4. Data Models (Pydantic) ---
class AssetCreate(BaseModel):
    asset_name: str
    asset_type: str
    current_algorithm: str
    data_sensitivity: str
    internet_facing: str
    data_retention_years: int
    owner: str
    status: Optional[str] = "Active"

class AssetUpdate(BaseModel):
    asset_name: Optional[str] = None
    asset_type: Optional[str] = None
    current_algorithm: Optional[str] = None
    data_sensitivity: Optional[str] = None
    internet_facing: Optional[str] = None
    data_retention_years: Optional[int] = None
    owner: Optional[str] = None
    status: Optional[str] = None

class RiskAssessmentRequest(BaseModel):
    algorithm: str
    key_size: Optional[int] = None


# --- 5. Root & Health Endpoints (Public) ---

@app.get("/", tags=["Public"])
def read_root():
    return {"message": "PQC Risk Assessor API is online"}

@app.get("/health", tags=["Public"])
def health_check():
    return {"status": "healthy", "service": "pqc-backend"}


# --- 6. Authentication Check ---

@app.get("/status", tags=["Auth Check"])
def get_status(api_key: str = Depends(verify_api_key)):
    return {"status": "authenticated", "message": "API key valid"}


# --- 7. PQC Risk Assessment Engine ---

@app.post("/assess", tags=["Risk Engine"])
def assess_risk(payload: RiskAssessmentRequest, api_key: str = Depends(verify_api_key)):
    algo = payload.algorithm.upper()
    
    if "RSA" in algo or "ECDSA" in algo or "DH" in algo or "ECDH" in algo or "ECC" in algo:
        risk_score = 9.5
        status_label = "Vulnerable to Quantum Attack (CRITICAL)"
        recommendation = "Migrate immediately to ML-KEM (Kyber) or ML-DSA (Dilithium)."
    elif "ML-KEM" in algo or "KYBER" in algo or "ML-DSA" in algo or "DILITHIUM" in algo or "SPHINCS" in algo:
        risk_score = 1.2
        status_label = "PQC-Ready (SAFE)"
        recommendation = "Maintain current quantum-safe configuration."
    elif "AES" in algo:
        if payload.key_size and payload.key_size >= 256:
            risk_score = 2.0
            status_label = "Quantum Resilient (SAFE)"
            recommendation = "AES-256 provides adequate resistance against Grover's algorithm."
        else:
            risk_score = 6.0
            status_label = "Moderate Risk"
            recommendation = "Upgrade key size to AES-256 to counter quantum search speedups."
    else:
        risk_score = 5.0
        status_label = "Unknown Algorithm"
        recommendation = "Review algorithm specification against NIST PQC standards."

    return {
        "algorithm": payload.algorithm,
        "key_size": payload.key_size,
        "risk_score": risk_score,
        "status": status_label,
        "recommendation": recommendation
    }


# --- 8. Database-Backed Asset Management (Full CRUD) ---

@app.get("/assets", tags=["Assets"])
def get_assets(api_key: str = Depends(verify_api_key)):
    conn = get_db_connection()
    cursor = conn.cursor()
    assets = cursor.execute("SELECT * FROM assets").fetchall()
    conn.close()
    return {"assets": [dict(asset) for asset in assets]}

@app.get("/assets/{asset_id}", tags=["Assets"])
def get_asset_by_id(asset_id: int, api_key: str = Depends(verify_api_key)):
    conn = get_db_connection()
    cursor = conn.cursor()
    asset = cursor.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    conn.close()
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found")
    return {"asset": dict(asset)}

@app.post("/assets", tags=["Assets"], status_code=status.HTTP_201_CREATED)
def create_asset(asset: AssetCreate, api_key: str = Depends(verify_api_key)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            INSERT INTO assets (
                asset_name, asset_type, current_algorithm, 
                data_sensitivity, internet_facing, data_retention_years, 
                owner, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                asset.asset_name, asset.asset_type, asset.current_algorithm,
                asset.data_sensitivity, asset.internet_facing, asset.data_retention_years,
                asset.owner, asset.status
            )
        )
        conn.commit()
        new_id = cursor.lastrowid
        new_asset = cursor.execute("SELECT * FROM assets WHERE asset_id = ?", (new_id,)).fetchone()
        conn.close()
        return {"message": "Asset created successfully", "asset": dict(new_asset)}
    except sqlite3.IntegrityError as e:
        conn.close()
        raise HTTPException(status_code=400, detail=f"Asset name already exists: {str(e)}")

@app.put("/assets/{asset_id}", tags=["Assets"])
def update_asset(asset_id: int, updated_data: AssetUpdate, api_key: str = Depends(verify_api_key)):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    existing = cursor.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found")
    
    update_fields = {k: v for k, v in updated_data.dict().items() if v is not None}
    if update_fields:
        set_clause = ", ".join([f"{k} = ?" for k in update_fields.keys()])
        values = list(update_fields.values()) + [asset_id]
        cursor.execute(f"UPDATE assets SET {set_clause} WHERE asset_id = ?", values)
        conn.commit()

    updated_asset = cursor.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    conn.close()
    return {"message": "Asset updated successfully", "asset": dict(updated_asset)}

@app.delete("/assets/{asset_id}", tags=["Assets"])
def delete_asset(asset_id: int, api_key: str = Depends(verify_api_key)):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    existing = cursor.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found")
        
    cursor.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
    conn.commit()
    conn.close()
    return {"message": "Asset deleted successfully", "asset": dict(existing)}


# --- 9. Database-Backed Risk Assessments & User Endpoints ---

@app.get("/risk-assessments", tags=["Risk Engine"])
def get_risk_assessments(api_key: str = Depends(verify_api_key)):
    conn = get_db_connection()
    cursor = conn.cursor()
    assessments = cursor.execute("SELECT * FROM risk_assessments").fetchall()
    conn.close()
    return {"risk_assessments": [dict(r) for r in assessments]}

@app.get("/users", tags=["Users"])
def get_users(api_key: str = Depends(verify_api_key)):
    conn = get_db_connection()
    cursor = conn.cursor()
    users = cursor.execute("SELECT user_id, username, email, role, created_at FROM users").fetchall()
    conn.close()
    return {"users": [dict(u) for u in users]}
