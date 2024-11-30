
import configparser
from datetime import datetime, timedelta
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from app.models import User
from app.routers.user import get_db

config = configparser.ConfigParser()
config.read('config.ini')

# JWT 配置
SECRET_KEY = config.get("app", "SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480

# OAuth2 密码承载者
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/v1/user/token")

access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
def create_access_token(data: dict, expires_delta: timedelta = access_token_expires):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 解码 JWT
def decode_jwt(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=400, detail="Invalid token")
        return username
    except JWTError:
        raise HTTPException(status_code=400, detail="Invalid token")
    

# 依赖项：获取当前用户
async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    id = decode_jwt(token)
    user = db.query(User).filter(User.id == id).first()
    if user is None:
        raise HTTPException(status_code=400, detail="User not found")
    return user


# 依赖项：获取当前活跃用户
async def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user