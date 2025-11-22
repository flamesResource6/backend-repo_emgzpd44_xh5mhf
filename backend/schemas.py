from pydantic import BaseModel, Field, EmailStr
from typing import Optional, List, Dict, Any
from datetime import datetime

# Core shared models
class User(BaseModel):
    email: EmailStr
    name: str
    role: str = Field(..., regex=r"^(admin|user)$")
    systems: List[str] = []
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class UserCreate(BaseModel):
    email: EmailStr
    name: str
    password: str
    role: str = Field(..., regex=r"^(admin|user)$")
    systems: List[str] = []

class UserUpdate(BaseModel):
    name: Optional[str]
    role: Optional[str]
    systems: Optional[List[str]]

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

class ActivityLog(BaseModel):
    user_id: str
    action: str
    metadata: Dict[str, Any] = {}
    created_at: Optional[datetime] = None

# Generic resource schema for dynamic systems
class Resource(BaseModel):
    system: str
    type: str  # e.g., "student", "teacher", etc.
    data: Dict[str, Any]
    owner_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class ResourceUpdate(BaseModel):
    data: Dict[str, Any]

class QueryParams(BaseModel):
    filter: Dict[str, Any] = {}
    limit: int = 50
    skip: int = 0
    sort: Optional[List[str]] = None
