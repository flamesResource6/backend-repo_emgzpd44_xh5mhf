import os
from typing import Any, Dict, Optional, List
from datetime import datetime
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "mongodb://localhost:27017")
DATABASE_NAME = os.getenv("DATABASE_NAME", "multimanagement")

_client = MongoClient(DATABASE_URL)
db = _client[DATABASE_NAME]


def create_document(collection_name: str, data: Dict[str, Any]) -> str:
    data["created_at"] = data.get("created_at") or datetime.utcnow()
    data["updated_at"] = data.get("updated_at") or datetime.utcnow()
    inserted = db[collection_name].insert_one(data)
    return str(inserted.inserted_id)


def get_documents(collection_name: str, filter_dict: Dict[str, Any], limit: int = 50) -> List[Dict[str, Any]]:
    cursor = db[collection_name].find(filter_dict).limit(limit)
    items = list(cursor)
    for it in items:
        it["id"] = str(it["_id"])  # type: ignore
    return items
