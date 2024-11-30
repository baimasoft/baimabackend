import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Address, User
from app.routers.jwt import get_current_active_user
from typing import Optional

router = APIRouter(prefix="/api/v1/address", tags=["address"])

class AddressCreate(BaseModel):
    user_id: int
    name: str
    address: str
    phone_number: str
    contact_name: Optional[str]
    contact_phone_number: Optional[str]

class AddressUpdate(BaseModel):
    name: str
    address: str
    phone_number: str
    contact_name: Optional[str]
    contact_phone_number: Optional[str]

class AddressResponse(AddressCreate):
    id: int
    created_at: datetime.datetime
    updated_at: datetime.datetime

    class Config:
        orm_mode = True

@router.post("/", response_model=AddressResponse)
async def create_address(address: AddressCreate, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    # 设置 user_id 为当前用户的 ID
    address_data = address.dict()
    address_data['user_id'] = current_user.id
    db_address = Address(**address_data)
    db.add(db_address)
    db.commit()
    db.refresh(db_address)
    return db_address

@router.get("/", response_model=List[AddressResponse])
async def read_addresses(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    addresses = db.query(Address).filter(Address.user_id == current_user.id).all()
    return addresses
@router.get("/{address_id}", response_model=AddressResponse)
async def read_address(address_id: int, db: Session = Depends(get_db)):
    address = db.query(Address).filter(Address.id == address_id).first()
    if address is None:
        raise HTTPException(status_code=404, detail="Address not found")
    return address

@router.put("/{address_id}", response_model=AddressResponse)
async def update_address(address_id: int, address_update: AddressUpdate, db: Session = Depends(get_db)):
    address = db.query(Address).filter(Address.id == address_id).first()
    if address is None:
        raise HTTPException(status_code=404, detail="Address not found")
    for key, value in address_update.dict().items():
        setattr(address, key, value)
    db.commit()
    db.refresh(address)
    return address

@router.delete("/{address_id}", response_model=AddressResponse)
async def delete_address(address_id: int, db: Session = Depends(get_db)):
    address = db.query(Address).filter(Address.id == address_id).first()
    if address is None:
        raise HTTPException(status_code=404, detail="Address not found")
    
    db.delete(address)
    db.commit()
    return address