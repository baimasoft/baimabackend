from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, default="微信用户")
    wxid = Column(String, unique=True)
    session_key = Column(String)
    phone_number = Column(String)
    password_hash = Column(String)
    avatar = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    orders = relationship('Order', order_by='Order.id', back_populates='user')
    addresses = relationship('Address', back_populates='user')
    
    def __str__(self):
        return self.username
    

class Address(Base):
    __tablename__ = 'addresses'

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    name = Column(String)  # 下单人
    address = Column(String)  # 地址
    phone_number = Column(String)  # 手机号码
    contact_name = Column(String)  # 现场联系人
    contact_phone_number = Column(String)  # 现场联系人号码
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship('User', back_populates='addresses',uselist=False)
    def __str__(self):
        return self.address
    


class Order(Base):
    __tablename__ = 'orders'

    id = Column(Integer, primary_key=True, index=True)
    uuid = Column(String)
    user_id = Column(Integer, ForeignKey('users.id'))
    order_info = Column(String)
    price = Column(Integer,default=1)
    status = Column(String, default='pending')  
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = relationship('User', back_populates='orders',uselist=False)
    
    def __str__(self):
        return self.order_info
