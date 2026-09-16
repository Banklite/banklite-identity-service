import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator



class UserCreate(BaseModel):
    email: EmailStr
    phone: str = Field(min_length=7, max_length=32, examples=["+573001234567"])
    country: str = Field(min_length=2, max_length=2, examples=["CO"])

    @field_validator("country")
    @classmethod
    def country_upper(cls, v: str) -> str:
        if not v.isalpha():
            raise ValueError("country debe ser un codigo ISO de 2 letras, por ejemplo CO")
        return v.upper()

    @field_validator("phone")
    @classmethod
    def phone_digits(cls, v: str) -> str:
        cleaned = v.replace(" ", "")
        if not cleaned.lstrip("+").isdigit():
            raise ValueError("phone solo admite digitos y un + inicial")
        return cleaned


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: EmailStr
    phone: str
    country: str
    status: str
    created_at: datetime


class KycRequest(BaseModel):
    document_type: Literal["cedula", "pasaporte", "licencia"]
    document_number: str = Field(min_length=5, max_length=32)

    @field_validator("document_number")
    @classmethod
    def doc_alnum(cls, v: str) -> str:
        if not v.isalnum():
            raise ValueError("document_number debe ser alfanumerico")
        return v


class KycOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    document_type: str
    document_last4: str
    verification_status: str
    provider_reference: str
    created_at: datetime


class KycResult(BaseModel):
    kyc: KycOut
    user_status: str
    event_published: bool
    event_name: str | None = None
