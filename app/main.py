from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.models import Base
from app.database import engine
from app.admin import init_admin  # 导入初始化 admin 的函数
from app.routers.user import router as user_router
from app.routers.address import router as address_router
from app.routers.order import router as order_router

app = FastAPI()

# 配置 CORS
origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,  # 允许的来源
    allow_credentials=True,  # 允许 cookies
    allow_methods=["*"],  # 允许所有方法
    allow_headers=["*"],  # 允许所有头
)

app.include_router(user_router)
app.include_router(address_router)
app.include_router(order_router)
init_admin(app)

@app.on_event("startup")
async def startup_event():
    Base.metadata.create_all(engine)
    
@app.get("/")
async def root():
    return "Not found"