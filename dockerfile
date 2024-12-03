# 使用官方的 Python 基础镜像
FROM python:3.12-slim

# 设置工作目录
WORKDIR /app

# 将当前目录的内容复制到容器的 /app 目录
COPY . /app

# 安装依赖
RUN pip install --no-cache-dir -r requirements.txt

# 暴露端口
EXPOSE 8000

# 创建一个启动脚本
RUN chmod +x entrypoint.sh

# 使用启动脚本作为默认命令
CMD ["./entrypoint.sh"]