
import os

from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    Security,
    status
)

from fastapi.security.api_key import APIKeyHeader
from fastapi.middleware.cors import CORSMiddleware


# --------------------------------------------------
# 1. FASTAPI APPLICATION
# --------------------------------------------------

app = FastAPI(
    title="PQC Risk Assessor API",
    description="Defensive Post-Quantum Cryptography Risk Assessment Engine",
    version="1.0.0"
)


# --------------------------------------------------
# 2. CORS CONFIGURATION
# --------------------------------------------------

origins = [
    "http://localhost:5173",
    "http://localhost:5174",
    "http://localhost:3000",
]

# Add deployed frontend URL through Render environment variable.
frontend_url = os.getenv("FRONTEND_URL")

if frontend_url:
    origins.append(frontend_url.rstrip("/"))

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-API-Key"],
)


# --------------------------------------------------
# 3. API KEY CONFIGURATION
# --------------------------------------------------

API_KEY_NAME = "X-API-Key"

SECRET_API_KEY = os.getenv("PQC_API_KEY")

api_key_header = APIKeyHeader(
    name=API_KEY_NAME,
    auto_error=False
)


# --------------------------------------------------
# 4. API KEY VALIDATION
# --------------------------------------------------

async def verify_api_key(
    api_key: str = Security(api_key_header)
):
    if not SECRET_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="API authentication is not configured."
        )

    if not api_key or api_key != SECRET_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Invalid or missing API Key"
        )

    return api_key


# --------------------------------------------------
# 5. PUBLIC ROOT ENDPOINT
# --------------------------------------------------

@app.get("/")
def read_root():
    return {
        "status": "online",
        "message": "PQC-Ready FastAPI Backend is running!"
    }


# --------------------------------------------------
# 6. PUBLIC HEALTH CHECK
# --------------------------------------------------

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "PQC Risk Assessor API"
    }


# --------------------------------------------------
# 7. PROTECTED STATUS ENDPOINT
# --------------------------------------------------

@app.get(
    "/status",
    dependencies=[Depends(verify_api_key)]
)
def get_status():
    return {
        "status": "authenticated",
        "system": "PQC-Ready Risk Assessor Engine",
        "access": "Granted"
    }


# --------------------------------------------------
# 8. PROTECTED RISK ASSESSMENT ENDPOINT
# --------------------------------------------------

@app.post(
    "/assess",
    dependencies=[Depends(verify_api_key)]
)
def assess_risk(data: dict):
    return {
        "status": "success",
        "input_received": data,
        "pqc_risk_score": 85
    }


# --------------------------------------------------
# 9. APPLICATION ENTRY POINT
# --------------------------------------------------

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=int(os.getenv("PORT", 8000))
    )
