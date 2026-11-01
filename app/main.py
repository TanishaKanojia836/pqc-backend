from fastapi import FastAPI, Depends, HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader

app = FastAPI(
    title="PQC Risk Assessor API",
    description="Defensive Post-Quantum Cryptography Risk Assessment Engine",
    version="1.0.0"
)

# 1. Define header name and secret key
API_KEY_NAME = "X-API-Key"
SECRET_API_KEY = "pqc_secret_team_key_2026"  # Change this to your preferred secret key

api_key_header = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

# 2. Key validation logic
async def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key == SECRET_API_KEY:
        return api_key
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Access Denied: Invalid or missing API Key"
    )

# 3. Public Root Endpoint
@app.get("/")
def read_root():
    return {"status": "online", "message": "PQC-Ready FastAPI Backend is running!"}

# 4. Protected Endpoints
@app.get("/status", dependencies=[Depends(verify_api_key)])
def get_status():
    return {
        "status": "authenticated",
        "system": "PQC-Ready Risk Assessor Engine",
        "access": "Granted"
    }

@app.post("/assess", dependencies=[Depends(verify_api_key)])
def assess_risk(data: dict):
    return {
        "status": "success",
        "input_received": data,
        "pqc_risk_score": 85
    }
