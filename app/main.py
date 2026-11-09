from fastapi import FastAPI, HTTPException, Header, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

app = FastAPI(
    title="PQC Risk Assessor API",
    version="1.0.0",
    description="Defensive Post-Quantum Cryptography Risk Assessment Engine"
)

# Configure CORS Middleware for Frontend Access
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "https://pqc-ready-frontend.onrender.com",
    "*"  # Allows all origins for development smooth testing
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permits requests from React frontend
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key", "Authorization"],
)

# Shared Team API Key authentication
TEAM_API_KEY = "pqc_secret_team_key_2026"

def verify_api_key(x_api_key: str = Header(..., alias="X-API-Key")):
    if x_api_key != TEAM_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header"
        )
    return x_api_key


# In-Memory Database for Session Assets
assets_db: List[Dict[str, Any]] = [
    {
        "id": 1,
        "name": "Legacy RSA Keypair",
        "algorithm": "RSA-2048",
        "category": "Asymmetric",
        "system": "Auth Gateway"
    },
    {
        "id": 2,
        "name": "TLS Certificate Key",
        "algorithm": "ECDSA P-256",
        "category": "Digital Signature",
        "system": "Web Proxy"
    }
]


# Data Models
class AssetCreate(BaseModel):
    name: str
    algorithm: str
    category: str
    system: str

class AssetUpdate(BaseModel):
    name: Optional[str] = None
    algorithm: Optional[str] = None
    category: Optional[str] = None
    system: Optional[str] = None

class RiskAssessmentRequest(BaseModel):
    algorithm: str
    key_size: Optional[int] = None


# --- 1. Root & Health Endpoints (Public) ---

@app.get("/", tags=["Public"])
def read_root():
    return {"message": "PQC Risk Assessor API is online"}

@app.get("/health", tags=["Public"])
def health_check():
    return {"status": "healthy", "service": "pqc-backend"}


# --- 2. Authentication Verification ---

@app.get("/status", tags=["Auth Check"])
def get_status(api_key: str = Depends(verify_api_key)):
    return {"status": "authenticated", "message": "API key valid"}


# --- 3. PQC Risk Assessment Engine ---

@app.post("/assess", tags=["Risk Engine"])
def assess_risk(payload: RiskAssessmentRequest, api_key: str = Depends(verify_api_key)):
    algo = payload.algorithm.upper()
    
    # Quantum-vulnerable algorithms
    if "RSA" in algo or "ECDSA" in algo or "DH" in algo or "ECDH" in algo:
        risk_score = 9.5
        status_label = "Vulnerable to Quantum Attack (CRITICAL)"
        recommendation = "Migrate immediately to ML-KEM (Kyber) or ML-DSA (Dilithium)."
    # Post-Quantum Cryptography standards
    elif "ML-KEM" in algo or "KYBER" in algo or "ML-DSA" in algo or "DILITHIUM" in algo or "SPHINCS" in algo:
        risk_score = 1.2
        status_label = "PQC-Ready (SAFE)"
        recommendation = "Maintain current quantum-safe configuration."
    # Symmetric encryption (AES-256 vs AES-128 under Grover's algorithm)
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


# --- 4. Asset Management Endpoints (Full CRUD for Member 2) ---

@app.get("/assets", tags=["Assets"])
def get_assets(api_key: str = Depends(verify_api_key)):
    return {"assets": assets_db}

@app.post("/assets", tags=["Assets"], status_code=status.HTTP_201_CREATED)
def create_asset(asset: AssetCreate, api_key: str = Depends(verify_api_key)):
    new_id = max([a["id"] for a in assets_db], default=0) + 1
    new_asset = {"id": new_id, **asset.dict()}
    assets_db.append(new_asset)
    return {"message": "Asset added successfully", "asset": new_asset}

@app.put("/assets/{asset_id}", tags=["Assets"])
def update_asset(asset_id: int, updated_data: AssetUpdate, api_key: str = Depends(verify_api_key)):
    for index, asset in enumerate(assets_db):
        if asset["id"] == asset_id:
            update_dict = {k: v for k, v in updated_data.dict().items() if v is not None}
            assets_db[index].update(update_dict)
            return {"message": "Asset updated successfully", "asset": assets_db[index]}
    raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found")

@app.delete("/assets/{asset_id}", tags=["Assets"])
def delete_asset(asset_id: int, api_key: str = Depends(verify_api_key)):
    for index, asset in enumerate(assets_db):
        if asset["id"] == asset_id:
            deleted_asset = assets_db.pop(index)
            return {"message": "Asset deleted successfully", "asset": deleted_asset}
    raise HTTPException(status_code=404, detail=f"Asset with ID {asset_id} not found")
