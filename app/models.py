from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()

class Application(Base):
    __tablename__ = 'applications'

    id = Column(Integer, primary_key=True, index=True)
    app_name = Column(String(255), unique=True, nullable=False)  # 指定长度为 255
    description = Column(String(255))  # 指定长度为 255
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    users = relationship('User', back_populates='application')

    def __str__(self):
        return self.app_name

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255))  # 指定长度为 255
    username1 = Column(String(255))  # 指定长度为 255
    app_id = Column(Integer, ForeignKey('applications.id'),nullable=False)  # 指定长度为 255 并匹配 Application 表
    wxid = Column(String(255), unique=True)  # 指定长度为 255
    session_key = Column(String(255))  # 指定长度为 255
    phone_number = Column(String(255))  # 指定长度为 255
    password_hash = Column(String(255))  # 指定长度为 255
    avatar = Column(String(255))  # 指定长度为 255
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    orders = relationship('Order', order_by='Order.id', back_populates='user')

    application = relationship('Application', back_populates='users')  # 新增关系
    # 确保 (username, app_id) 的组合是唯一的
    __table_args__ = (
        UniqueConstraint('username', 'app_id', name='uix_username_app_id'),
    )
    def __str__(self):
        return f"{self.username} ({self.app_id})"

class Order(Base):
    __tablename__ = 'orders'

    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String(255))  # 指定长度为 255
    user_id = Column(Integer, ForeignKey('users.id'))
    order_info = Column(String(255))  # 指定长度为 255
    price = Column(Integer, default=1)
    status = Column(String(50), default='pending')  # 指定长度为 50
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship('User', back_populates='orders', uselist=False)

    def __str__(self):
        return self.order_info