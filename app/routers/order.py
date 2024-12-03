import configparser
import json
import os
import random
import string
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
import shortuuid
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import Order, User
from pydantic import BaseModel
from datetime import datetime
import requests
import hashlib
import xml.etree.ElementTree as ET

from app.routers.jwt import get_current_active_user

class OrderBase(BaseModel):
    order_info: str

class OrderResponse(OrderBase):
    id: int
    user_id: Optional[int]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
        
# 定义退款请求模型
class RefundRequest(BaseModel):
    order_id: int

router = APIRouter(prefix="/api/v1/orders", tags=["Orders"])
config = configparser.ConfigParser()
config.read('config.ini')
# 微信支付相关配置
WECHAT_APP_ID = config.get("app", "APP_ID")
WECHAT_MCH_ID = config.get("app", "WECHAT_MCH_ID")
WECHAT_API_KEY = config.get("app","WECHAT_API_KEY")
WECHAT_NOTIFY_URL = config.get("app",'DOMAIN')+"api/v1/orders/wechat_notify"
cert_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'cert')
cert_path = (os.path.join(cert_dir, 'apiclient_cert.pem'), os.path.join(cert_dir, 'apiclient_key.pem'))


# 创建订单
@router.post("/", response_model=OrderResponse)
async def create_order(order: OrderBase, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    db_order = Order(
        uuid=str(str(shortuuid.uuid())),
        user_id=current_user.id,
        order_info=order.order_info,
        status="pending"
    )
    db.add(db_order)
    db.commit()
    db.refresh(db_order)
    return db_order

# 获取当前用户的订单
@router.get("/", response_model=list[OrderResponse])
async def read_orders(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    orders = db.query(Order).filter(Order.user_id == current_user.id).all()
    return orders

# 获取所有的订单
@router.get("/all", response_model=list[OrderResponse])
async def read_orders(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if(current_user.username != "admin"):
        return []
    orders = db.query(Order).all()
    return orders


# 获取特定订单
@router.get("/{order_id}", response_model=OrderResponse)
async def read_order(order_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    db_order = db.query(Order).filter(Order.id == order_id).first()
    if not db_order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    if db_order.user_id != current_user.id and current_user.username!="admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    return db_order
# 更新订单-已完成
@router.put("/{order_id}",response_model=OrderResponse)
async def update_order(order_id: int, order: OrderBase, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
  db_order = db.query(Order).filter(Order.id == order_id).first()
  if not db_order:
    raise HTTPException(status_code=404, detail="Order not found")
  
  if db_order.user_id != current_user.id and current_user.username!="admin":
    raise HTTPException(status_code=403, detail="Not enough permissions")
  
  if(db_order.status == 'pending'):
    raise HTTPException(status_code=400, detail="unpaid")
  for key, value in order.dict().items():
    setattr(db_order, key, value)
  db.commit()
  return db_order

# 删除订单
@router.delete("/{order_id}", response_model=OrderResponse)
async def delete_order(order_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    db_order = db.query(Order).filter(Order.id == order_id).first()
    if not db_order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    if db_order.user_id != current_user.id and current_user.username != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    db.delete(db_order)
    db.commit()
    return db_order

# 微信支付
@router.post("/{order_id}/wechat_pay")
async def wechat_pay(order_id: int,request:Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    db_order = db.query(Order).filter(Order.id == order_id).first()
    
    if not db_order:
        raise HTTPException(status_code=404, detail="Order not found")
    order_info = json.loads(db_order.order_info)
    if db_order.user_id != current_user.id and current_user.username != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    # 构建微信支付参数
    params = {
        'appid': WECHAT_APP_ID,
        'mch_id': WECHAT_MCH_ID,
        'nonce_str': generate_nonce_str(),
        'body': order_info['details_title'],
        'out_trade_no': str(db_order.uuid),  # 确保是字符串
        'total_fee': str(db_order.price),  # 单位为分
        'spbill_create_ip': request.client.host,
        'notify_url': WECHAT_NOTIFY_URL,
        'trade_type': 'JSAPI',
        'openid': current_user.wxid  # 添加 openid 参数
    }
    # 签名
    sign = generate_sign(params, WECHAT_API_KEY)
    params['sign'] = sign
    # 发送请求
    xml_data = dict_to_xml(params)
    response = requests.post('https://api.mch.weixin.qq.com/pay/unifiedorder', data=xml_data.encode('utf-8'))
    
    # 显式指定编码为 UTF-8
    response.encoding = 'utf-8'
    print(response.text)
    
    # 解析响应
    root = ET.fromstring(response.text)
    if root.find('return_code').text == 'SUCCESS' and root.find('result_code').text == 'SUCCESS':
        prepay_id = root.find('prepay_id').text  # 提取 prepay_id
        nonceStr = root.find('nonce_str').text
        timeStamp = str(int(datetime.timestamp(datetime.now())))
        
        # 准备生成 paysign 的参数
        pay_params = {
            'appId': WECHAT_APP_ID,
            'timeStamp': timeStamp,
            'nonceStr': nonceStr,
            'package': f'prepay_id={prepay_id}',
            'signType': 'MD5'
        }
        
        # 生成 paysign
        paySign = generate_sign(pay_params, WECHAT_API_KEY)
        
        return {
            'appId': WECHAT_APP_ID,
            'timeStamp': timeStamp,
            'nonceStr': nonceStr,
            'prepay_id': f'prepay_id={prepay_id}',
            'signType': 'MD5',
            'paySign': paySign
        }
    else:
        raise HTTPException(status_code=500, detail="WeChat Pay request failed")
def generate_nonce_str(length=32):
    """生成随机字符串"""
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length))

def generate_sign(params, api_key):
    """生成签名"""
    sorted_params = sorted(params.items())  # 确保参数按字典顺序排列
    sign_str = '&'.join([f'{k}={v}' for k, v in sorted_params if v]) + f'&key={api_key}'
    sign = hashlib.md5(sign_str.encode('utf-8')).hexdigest().upper()
    return sign

def dict_to_xml(params):
    """将字典转换为 XML 格式"""
    xml = ['<xml>']
    for key, value in params.items():
        if isinstance(value, str):
            xml.append(f'<{key}><![CDATA[{value}]]></{key}>')
        else:
            xml.append(f'<{key}>{value}</{key}>')
    xml.append('</xml>')
    return ''.join(xml)

# 微信支付回调
@router.post("/wechat_notify")
async def wechat_notify(request: Request, db: Session = Depends(get_db)):
    xml_data = await request.body()
    root = ET.fromstring(xml_data)
    
    # 验证签名
    params = {child.tag: child.text for child in root}
    sign = params.pop('sign')
    if generate_sign(params, WECHAT_API_KEY) != sign:
        raise HTTPException(status_code=400, detail="Invalid signature")
    
    # 处理支付成功逻辑
    out_trade_no = params.get('out_trade_no')
    db_order = db.query(Order).filter(Order.uuid == str(out_trade_no)).first()
    if db_order:
        db_order.status = 'paid'
        db.commit()
    return {'return_code': 'SUCCESS', 'return_msg': 'OK'}

# 微信退款
@router.post("/refund")
async def refund(refund_request: RefundRequest, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    db_order = db.query(Order).filter(Order.id == refund_request.order_id).first()
    if not db_order:
        raise HTTPException(status_code=404, detail="Order not found")
    
    if db_order.user_id != current_user.id and current_user.username != "admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    
    if db_order.status != 'paid':
        raise HTTPException(status_code=400, detail="Order is not paid")
    
    # 构建微信退款参数
    params = {
        'appid': WECHAT_APP_ID,
        'mch_id': WECHAT_MCH_ID,
        'nonce_str': generate_nonce_str(),
        'out_trade_no': str(db_order.uuid),  # 原始订单号
        'out_refund_no': f"REFUND_{db_order.uuid}_{int(datetime.timestamp(datetime.now()))}",  # 退款单号
        'total_fee': db_order.price,  # 原始订单金额
        'refund_fee': db_order.price,  # 退款金额
        'op_user_id': WECHAT_MCH_ID
    }
    
    # 签名
    sign = generate_sign(params, WECHAT_API_KEY)
    params['sign'] = sign
    
    # 发送请求
    xml_data = dict_to_xml(params)
    response = requests.post('https://api.mch.weixin.qq.com/secapi/pay/refund', data=xml_data.encode('utf-8'), cert=cert_path)
    
    # 显式指定编码为 UTF-8
    response.encoding = 'utf-8'
    print(response.text)
    
    # 解析响应
    root = ET.fromstring(response.text)
    if root.find('return_code').text == 'SUCCESS' and root.find('result_code').text == 'SUCCESS':
        # 更新订单状态
        db_order.status = 'refunded'
        db.commit()
        return {"message": "Refund successful"}
    else:
        raise HTTPException(status_code=500, detail="WeChat Refund request failed")
