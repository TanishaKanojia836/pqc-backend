from typing import Optional, List
from enum import Enum
from datetime import datetime, timezone
from sqlmodel import SQLModel, Field

class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    ENGINEER = "engineer"

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(index=True, unique=True)
    email: str = Field(unique=True)
    hashed_password: str
    role: UserRole = Field(default=UserRole.ANALYST)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserCreate(SQLModel):
    username: str
    email: str
    password: str
    role: Optional[UserRole] = UserRole.ANALYST

class UserResponse(SQLModel):
    id: int
    username: str
    email: str
    role: UserRole

class Token(SQLModel):
    access_token: str
    token_type: str

# --- Cryptographic Asset & Risk Assessment Models ---

class EncryptionAlgorithm(str, Enum):
    RSA = "RSA"
    ECC = "ECC"
    AES_128 = "AES-128"
    AES_256 = "AES-256"
    KYBER_768 = "Kyber-768"
    DILITHIUM = "Dilithium"

class RiskLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class AssetBase(SQLModel):
    name: str
    system_type: str
    algorithm: EncryptionAlgorithm
    key_size: int
    is_public_facing: bool = False

class Asset(AssetBase, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    owner_id: int = Field(foreign_key="user.id")
    
    risk_score: Optional[float] = None
    risk_level: Optional[RiskLevel] = None

class AssetCreate(AssetBase):
    pass

class AssetResponse(AssetBase):
    id: int
    created_at: datetime
    owner_id: int
    risk_score: Optional[float]
    risk_level: Optional[RiskLevel]
