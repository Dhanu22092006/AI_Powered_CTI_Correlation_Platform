from pydantic import BaseModel, EmailStr, Field
from typing import Optional

class LoginIn(BaseModel):
    email: str
    password: str

class UserCreate(BaseModel):
    email: str
    password: str = Field(min_length=12, max_length=128)
    role: str = "analyst"

class AlertUpdate(BaseModel):
    status: str
    note: Optional[str] = None

class FeedbackIn(BaseModel):
    verdict: str
    comment: str = ""

class IngestText(BaseModel):
    text: str = Field(min_length=1, max_length=200000)
    source: str = "manual-upload"
    title: str = "Manual intelligence"
