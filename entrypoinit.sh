#!/bin/sh

# 运行 Alembic 迁移
alembic upgrade head

# 启动应用程序
exec uvicorn app.main:app --host 0.0.0.0 --port 8000