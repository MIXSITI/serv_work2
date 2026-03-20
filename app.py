from datetime import datetime
import time
import uuid
from typing import Optional
from fastapi import (
    FastAPI,
    Depends,
    Cookie,
    HTTPException,
    Response,
)
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, EmailStr, Field, validator
from itsdangerous import TimestampSigner, BadSignature, SignatureExpired

app = FastAPI(title="KR2 FastAPI (по методичкам 4–6)")
SECRET_KEY = "change_me_to_random_secret"
signer = TimestampSigner(SECRET_KEY)
SESSION_LIFETIME_SECONDS = 300         
SESSION_RENEW_THRESHOLD_SECONDS = 180   
security = HTTPBasic()

# № 3.1

class UserCreate(BaseModel):
    name: str = Field(..., description="Имя пользователя")
    email: EmailStr
    age: Optional[int] = Field(default=None, gt=0)
    is_subscribed: Optional[bool] = False

@app.post("/create_user")
async def create_user(user: UserCreate):
    return user

# № 3.2 

sample_product_1 = {
    "product_id": 123,
    "name": "Smartphone",
    "category": "Electronics",
    "price": 599.99,
}
sample_product_2 = {
    "product_id": 456,
    "name": "Phone Case",
    "category": "Accessories",
    "price": 19.99,
}
sample_product_3 = {
    "product_id": 789,
    "name": "Iphone",
    "category": "Electronics",
    "price": 1299.99,
}
sample_product_4 = {
    "product_id": 101,
    "name": "Headphones",
    "category": "Accessories",
    "price": 99.99,
}
sample_product_5 = {
    "product_id": 202,
    "name": "Smartwatch",
    "category": "Electronics",
    "price": 299.99,
}
sample_products = [
    sample_product_1,
    sample_product_2,
    sample_product_3,
    sample_product_4,
    sample_product_5,
]

@app.get("/product/{product_id}")
async def get_product(product_id: int):
    for p in sample_products:
        if p["product_id"] == product_id:
            return p
    raise HTTPException(status_code=404, detail="Product not found")

@app.get("/products/search")
async def search_products(
    keyword: str,
    category: Optional[str] = None,
    limit: int = 10,
):
    kw = keyword.lower()
    cat = category.lower() if category else None
    result = []
    for p in sample_products:
        if kw in p["name"].lower():
            if cat and p["category"].lower() != cat:
                continue
            result.append(p)
        if len(result) >= limit:
            break
    return result

# № 5.1–5.2

class LoginData(BaseModel):
    username: str
    password: str
def verify_credentials(username: str, password: str) -> bool:
    return bool(username) and bool(password)
@app.post("/login-basic")
async def login_basic(data: LoginData, response: Response):
    if not verify_credentials(data.username, data.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = str(uuid.uuid4())
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        max_age=SESSION_LIFETIME_SECONDS,
    )
    return {"message": "Logged in (basic)", "session_token": token}
@app.get("/user-basic")
async def user_basic(session_token: Optional[str] = Cookie(default=None)):
    if not session_token:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {"username": "user123", "session_token": session_token}

# № 5.2–5.3

def create_signed_value(user_id: str, ts: int) -> str:
    base = f"{user_id}.{ts}"
    signed = signer.sign(base.encode()).decode()
    return signed
def parse_signed_value(value: str) -> tuple[str, int]:
    try:
        unsigned = signer.unsign(value.encode(), max_age=SESSION_LIFETIME_SECONDS).decode()
    except SignatureExpired:
        raise HTTPException(status_code=401, detail="Session expired")
    except BadSignature:
        raise HTTPException(status_code=401, detail="Invalid session")
    parts = unsigned.split(".")
    if len(parts) != 2:
        raise HTTPException(status_code=401, detail="Invalid session")
    user_id, ts_str = parts
    try:
        ts = int(ts_str)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid session")
    return user_id, ts

@app.post("/login")
async def login(data: LoginData, response: Response):
    if not verify_credentials(data.username, data.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user_id = str(uuid.uuid4())
    now_ts = int(time.time())
    signed = create_signed_value(user_id, now_ts)
    response.set_cookie(
        key="session_token",
        value=signed,
        httponly=True,
        secure=False,  # для тестов
        max_age=SESSION_LIFETIME_SECONDS,
    )
    return {"user_id": user_id, "session_token": signed}

def check_and_renew(
    session_token: Optional[str],
    response: Response,
) -> str:
    if not session_token:
        raise HTTPException(status_code=401, detail="Session expired")
    user_id, last_ts = parse_signed_value(session_token)
    now_ts = int(time.time())
    diff = now_ts - last_ts
    if diff > SESSION_LIFETIME_SECONDS:
        raise HTTPException(status_code=401, detail="Session expired")
    if diff < SESSION_RENEW_THRESHOLD_SECONDS:
        return user_id
    new_signed = create_signed_value(user_id, now_ts)
    response.set_cookie(
        key="session_token",
        value=new_signed,
        httponly=True,
        secure=False,
        max_age=SESSION_LIFETIME_SECONDS,
    )
    return user_id

@app.get("/profile")
async def profile(
    response: Response,
    session_token: Optional[str] = Cookie(default=None),
):
    user_id = check_and_renew(session_token, response)
    return {"user_id": user_id, "message": "Profile data"}

# № 5.4–5.5 

class CommonHeaders(BaseModel):
    user_agent: str = Field(..., alias="User-Agent")
    accept_language: str = Field(..., alias="Accept-Language")

    @validator("accept_language")
    def validate_lang(cls, v: str):
        if ";" in v or "," in v:
            return v
        raise ValueError("Invalid Accept-Language format")
@app.get("/headers")
async def headers_route(
    headers: CommonHeaders = Depends(),
):
    return {
        "User-Agent": headers.user_agent,
        "Accept-Language": headers.accept_language,
    }

@app.get("/info")
async def info_route(
    response: Response,
    headers: CommonHeaders = Depends(),
):
    response.headers["X-Server-Time"] = datetime.utcnow().isoformat()
    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": headers.user_agent,
            "Accept-Language": headers.accept_language,
        },
    }

class BasicUser(BaseModel):
    username: str
    password: str

BASIC_USERS = [
    BasicUser(username="user1", password="pass1"),
    BasicUser(username="user2", password="pass2"),
]

def get_basic_user(username: str) -> Optional[BasicUser]:
    for u in BASIC_USERS:
        if u.username == username:
            return u
    return None

def authenticate_basic(credentials: HTTPBasicCredentials = Depends(security)) -> BasicUser:
    user = get_basic_user(credentials.username)
    if user is None or user.password != credentials.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return user

@app.get("/protected_resource")
async def protected_resource(user: BasicUser = Depends(authenticate_basic)):
    return {"message": "You have access to the protected resource!", "user": user}
