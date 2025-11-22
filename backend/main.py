from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

from schemas import User, UserCreate, UserUpdate, Token, LoginRequest, ActivityLog, Resource, ResourceUpdate, QueryParams
from database import db, create_document, get_documents

SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title="Multi-Management Platform", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility auth functions
class TokenData(BaseModel):
    user_id: Optional[str] = None
    role: Optional[str] = None


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(authorization: Optional[str] = Header(None)) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        role: str = payload.get("role")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": ObjectId(user_id)})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["id"] = str(user["_id"])
        user["role"] = role
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Token expired or invalid")


async def require_admin(user=Depends(get_current_user)):
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


# Auth endpoints
@app.post("/auth/register", response_model=Token)
async def register(payload: UserCreate):
    existing = db["user"].find_one({"email": payload.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_doc = {
        "email": payload.email,
        "name": payload.name,
        "password": get_password_hash(payload.password),
        "role": payload.role,
        "systems": payload.systems,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    inserted = db["user"].insert_one(user_doc)
    token = create_access_token({"sub": str(inserted.inserted_id), "role": payload.role})
    return Token(access_token=token)


@app.post("/auth/login", response_model=Token)
async def login(payload: LoginRequest):
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": str(user["_id"]), "role": user.get("role", "user")})
    return Token(access_token=token)


# Admin: users CRUD
@app.get("/admin/users", dependencies=[Depends(require_admin)])
async def list_users():
    users = list(db["user"].find())
    for u in users:
        u["id"] = str(u["_id"])
        u.pop("password", None)
    return users


@app.post("/admin/users", dependencies=[Depends(require_admin)])
async def create_user(payload: UserCreate):
    if db["user"].find_one({"email": payload.email}):
        raise HTTPException(status_code=400, detail="Email already exists")
    doc = payload.dict()
    doc["password"] = get_password_hash(doc.pop("password"))
    doc["created_at"] = datetime.utcnow()
    doc["updated_at"] = datetime.utcnow()
    inserted = db["user"].insert_one(doc)
    return {"id": str(inserted.inserted_id)}


@app.patch("/admin/users/{user_id}", dependencies=[Depends(require_admin)])
async def update_user(user_id: str, payload: UserUpdate):
    updates = {k: v for k, v in payload.dict(exclude_unset=True).items() if v is not None}
    updates["updated_at"] = datetime.utcnow()
    res = db["user"].update_one({"_id": ObjectId(user_id)}, {"$set": updates})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"updated": True}


@app.delete("/admin/users/{user_id}", dependencies=[Depends(require_admin)])
async def delete_user(user_id: str):
    res = db["user"].delete_one({"_id": ObjectId(user_id)})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"deleted": True}


@app.post("/admin/users/{user_id}/assign", dependencies=[Depends(require_admin)])
async def assign_systems(user_id: str, systems: List[str]):
    db["user"].update_one({"_id": ObjectId(user_id)}, {"$addToSet": {"systems": {"$each": systems}}})
    return {"assigned": True}

# Activity tracking
@app.post("/activity")
async def log_activity(payload: ActivityLog, user=Depends(get_current_user)):
    doc = payload.dict()
    doc["user_id"] = str(user["_id"]) if isinstance(user.get("_id"), ObjectId) else user.get("id")
    doc["created_at"] = datetime.utcnow()
    db["activity"].insert_one(doc)
    return {"logged": True}

@app.get("/admin/activity", dependencies=[Depends(require_admin)])
async def get_activity(limit: int = 100):
    items = list(db["activity"].find().sort("created_at", -1).limit(limit))
    for i in items:
        i["id"] = str(i["_id"])
    return items

# Systems registry
DEFAULT_SYSTEMS = [
    "school", "college", "university", "library", "hostel", "transport", "hospital", "clinic", "pharmacy",
    "patient-record", "doctor-appointment", "inventory", "payroll", "project", "crm", "erp", "accounting",
    "budget", "loan", "banking", "ecommerce-order", "warehouse", "hotel", "restaurant", "tourism", "hr",
    "attendance", "performance", "exam", "finance", "insurance", "gov-records", "public-transport-ticket",
    "electric-bill", "water-supply", "citizen-complaint", "police-case", "court-scheduling", "disaster-response",
    "construction", "real-estate", "manufacturing", "quality-control", "factory-maintenance", "supply-chain",
    "logistics", "shipping"
]

@app.get("/systems")
async def list_systems(user=Depends(get_current_user)):
    if user.get("role") == "admin":
        return DEFAULT_SYSTEMS
    return [s for s in user.get("systems", []) if s in DEFAULT_SYSTEMS]


# Generic CRUD for resources under each system
@app.post("/systems/{system}/{rtype}")
async def create_resource(system: str, rtype: str, payload: Resource, user=Depends(get_current_user)):
    if user.get("role") != "admin" and system not in user.get("systems", []):
        raise HTTPException(status_code=403, detail="Access denied to this system")
    doc = {
        "system": system,
        "type": rtype,
        "data": payload.data,
        "owner_id": str(user.get("_id")) if isinstance(user.get("_id"), ObjectId) else user.get("id"),
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    inserted = db["resource"].insert_one(doc)
    return {"id": str(inserted.inserted_id)}


@app.post("/systems/{system}/{rtype}/query")
async def query_resources(system: str, rtype: str, params: QueryParams, user=Depends(get_current_user)):
    if user.get("role") != "admin" and system not in user.get("systems", []):
        raise HTTPException(status_code=403, detail="Access denied to this system")
    q = {"system": system, "type": rtype}
    q.update(params.filter or {})
    cursor = db["resource"].find(q).skip(params.skip).limit(params.limit)
    items = list(cursor)
    for it in items:
        it["id"] = str(it["_id"])
    return items


@app.get("/systems/{system}/{rtype}/{rid}")
async def get_resource(system: str, rtype: str, rid: str, user=Depends(get_current_user)):
    if user.get("role") != "admin" and system not in user.get("systems", []):
        raise HTTPException(status_code=403, detail="Access denied to this system")
    doc = db["resource"].find_one({"_id": ObjectId(rid), "system": system, "type": rtype})
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    doc["id"] = str(doc["_id"])
    return doc


@app.patch("/systems/{system}/{rtype}/{rid}")
async def update_resource(system: str, rtype: str, rid: str, payload: ResourceUpdate, user=Depends(get_current_user)):
    if user.get("role") != "admin" and system not in user.get("systems", []):
        raise HTTPException(status_code=403, detail="Access denied to this system")
    res = db["resource"].update_one({"_id": ObjectId(rid), "system": system, "type": rtype}, {"$set": {"data": payload.data, "updated_at": datetime.utcnow()}})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"updated": True}


@app.delete("/systems/{system}/{rtype}/{rid}")
async def delete_resource(system: str, rtype: str, rid: str, user=Depends(get_current_user)):
    if user.get("role") != "admin" and system not in user.get("systems", []):
        raise HTTPException(status_code=403, detail="Access denied to this system")
    res = db["resource"].delete_one({"_id": ObjectId(rid), "system": system, "type": rtype})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Not found")
    return {"deleted": True}


# Simple analytics endpoint per system (aggregations by month and counts)
@app.get("/analytics/{system}")
async def system_analytics(system: str, user=Depends(get_current_user)):
    if user.get("role") != "admin" and system not in user.get("systems", []):
        raise HTTPException(status_code=403, detail="Access denied to this system")
    now = datetime.utcnow()
    since = datetime(now.year, 1, 1)
    pipeline = [
        {"$match": {"system": system, "created_at": {"$gte": since}}},
        {"$group": {
            "_id": {"month": {"$month": "$created_at"}, "type": "$type"},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id.month": 1}}
    ]
    agg = list(db["resource"].aggregate(pipeline))
    totals = db["resource"].count_documents({"system": system})
    return {"series": agg, "total": totals}


@app.get("/health")
async def health():
    return {"ok": True}
