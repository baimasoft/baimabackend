from fastapi import FastAPI
from app.models import User, Order,Address
from app.database import engine
from sqladmin import Admin, ModelView
from sqladmin.authentication import AuthenticationBackend
from starlette.requests import Request

class AdminAuth(AuthenticationBackend):
    async def login(self, request: Request) -> bool:
        form = await request.form()
        username, password = form["username"], form["password"]

        if username != "devil" or password != "fjf88888":
            return False

        # Validate username/password credentials
        # And update session
        request.session.update({"token": "..."})

        return True

    async def logout(self, request: Request) -> bool:
        # Usually you'd want to just clear the session
        request.session.clear()
        return True

    async def authenticate(self, request: Request) -> bool:
        token = request.session.get("token")

        if not token:
            return False

        # Check the token in depth
        return True

class UserView(ModelView, model=User):
    column_list = [User.id, User.username, User.phone_number,User.avatar,User.wxid,User.session_key, User.addresses,User.orders,User.created_at, User.updated_at]
    form_excluded_columns = [User.password_hash]  # Exclude sensitive fields from the form

class OrderView(ModelView, model=Order):
    column_list = [Order.id, Order.user_id,Order.order_info,Order.price, Order.status,Order.user, Order.created_at, Order.updated_at]

class AddressView(ModelView, model=Address):
    column_list = [Address.id, Address.user_id,Address.name,Address.address,Address.contact_name,Address.contact_phone_number,Address.phone_number,Address.created_at, Address.updated_at]

def init_admin(app: FastAPI):
    authentication_backend = AdminAuth(secret_key="...")
    admin = Admin(app, engine, authentication_backend=authentication_backend)
    admin.add_view(UserView)
    admin.add_view(OrderView)
    admin.add_view(AddressView)