import base64
import json
import re
from fastapi import APIRouter, HTTPException, Depends
from fastapi.security import OAuth2PasswordRequestForm
import requests
import configparser
from app.database import get_db
from sqlalchemy.orm import Session
from app.models import User
from datetime import datetime
from pydantic import BaseModel, Field, field_validator, validator
import bcrypt
from app.routers.jwt import create_access_token, get_current_active_user
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

router = APIRouter(prefix="/api/v1/user", tags=["user"])
config = configparser.ConfigParser()
config.read('config.ini')

class DecryptPhoneResponse(BaseModel):
    phone_number: str
    appid: str

class DecryptPhoneRequest(BaseModel):
    encryptedData: str
    iv: str
    session_key: str

class LoginRequest(BaseModel):
    username: str
    password: str

class WeChatLoginRequest(BaseModel):
    code: str
    iv: str
    encryptedData: str

class RegisterRequest(BaseModel):
    username: str
    password: str
    phone_number: str = Field(None, description="Optional phone number")
    @field_validator('username')
    def validate_username(cls, v):
        if len(v) < 5:
            raise ValueError('用户名至少五位')
        return v
    @field_validator('password')
    def validate_password(cls, v):
        if len(v) < 6:
            raise ValueError('密码至少六位')
        if not re.search(r'[a-zA-Z]', v):
            raise ValueError('密码至少要包含字母')
        if not re.search(r'\d', v):
            raise ValueError('密码至少要包含数字')
        return v
    @field_validator('phone_number')
    def validate_phone_number(cls, v):
        if v is not None and not re.match(r'^\d{11}$', v):
            raise ValueError('电话号码必须是11位数字')
        return v

class UserResponse(BaseModel):
    id: int
    username: str
    phone_number: str = Field(None, description="电话号码，选填")
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class LoginResponse(BaseModel):
    message: str
    token: str
    user: UserResponse

class UserUpdate(BaseModel):
    username: str
    phone_number: str
    avatar: str

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password.decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

# 注册路由
@router.post("/register", response_model=UserResponse)
async def register(register_request: RegisterRequest, db: Session = Depends(get_db)):
    username = register_request.username
    password = register_request.password
    phone_number = register_request.phone_number

    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already registered")

    if phone_number is not None and db.query(User).filter(User.phone_number == phone_number).first():
        raise HTTPException(status_code=400, detail="Phone number already registered")

    hashed_password = hash_password(password)
    new_user = User(username=username, password_hash=hashed_password, phone_number=phone_number)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user


# 普通登录路由
@router.post("/login", response_model=LoginResponse)
async def login(login_request: LoginRequest, db: Session = Depends(get_db)):
    username = login_request.username
    password = login_request.password

    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": str(user.id)})

    return {"message": "Login success", "token": access_token, "user": user}

# 认证路由
@router.post("/token", response_model=dict)
async def login_for_access_token(login_request: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    username = login_request.username
    password = login_request.password
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/welogin", response_model=LoginResponse)
async def wechat_login(login_request: WeChatLoginRequest, db: Session = Depends(get_db)):
    code = login_request.code
    encryptedData = login_request.encryptedData
    iv = login_request.iv

    if not code:
        raise HTTPException(status_code=400, detail="No code provided")

    # 使用 code 请求微信服务器，获取 access_token 和 wxid
    params = {
        'appid': config.get("app", "APP_ID"),
        'secret': config.get("app", "APP_SECRET"),
        'js_code': code,
        'grant_type': 'authorization_code'
    }
    response = requests.get(config.get("app", "WX_ACCESS_TOKEN_URL"), params=params)
    wx_response = response.json()

    if 'openid' not in wx_response or 'session_key' not in wx_response:
        raise HTTPException(status_code=400, detail=f"Failed to get session: {wx_response}")

    wxid = wx_response['openid']
    session_key = wx_response['session_key']

    # 解密手机号
    try:
        phone_number, _ = decrypt_phone_number(encryptedData, iv, session_key)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # 检查用户是否已注册
    user = db.query(User).filter(User.wxid == wxid).first()

    if not user:
        # 用户未注册，自动注册
        new_user = User(wxid=wxid, session_key=session_key, phone_number=phone_number)
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        user = new_user

    # 生成 JWT
    access_token = create_access_token(data={"sub": str(user.id)})

    return {"message": "Login success", "token": access_token, "user": user}

# 获取用户信息路由
@router.get("/", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return current_user

# 获取所有用户
@router.get("/all", response_model=list[UserResponse])
async def read_users_me(current_user: User = Depends(get_current_active_user),db:Session = Depends(get_db)):
    if current_user.username != "admin":
        return []
    return db.query(User)

# 更新用户信息路由
@router.put("/", response_model=UserResponse)
async def update_users_me(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db)
):
    # 更新用户信息
    if user_update.username is not None:
        current_user.username = user_update.username
    if user_update.avatar is not None:
        current_user.avatar = user_update.avatar
    if user_update.phone_number is not None:
        current_user.phone_number = user_update.phone_number

    # 更新 `updated_at` 字段
    current_user.updated_at = datetime.utcnow()

    # 提交事务
    db.commit()
    db.refresh(current_user)

    return current_user

def decrypt_phone_number(encrypted_data, iv, session_key):
    # 将 base64 编码的字符串转换为字节
    session_key = base64.b64decode(session_key)
    iv = base64.b64decode(iv)
    encrypted_data = base64.b64decode(encrypted_data)

    # 创建 AES 解密器
    cipher = AES.new(session_key, AES.MODE_CBC, iv)

    # 解密数据并去除填充
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)

    # 解析 JSON 数据
    decrypted_data = json.loads(decrypted_data.decode('utf-8'))

    return decrypted_data.get('phoneNumber', ''), decrypted_data.get('watermark', {}).get('appid', '')

@router.post("/decrypt-phone-number", response_model=DecryptPhoneResponse)
async def decrypt_phone_number_route(request: DecryptPhoneRequest):
    encrypted_data = request.encryptedData
    iv = request.iv
    session_key = request.session_key

    try:
        phone_number, appid = decrypt_phone_number(encrypted_data, iv, session_key)
        return {'phone_number': phone_number, 'appid': appid}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))