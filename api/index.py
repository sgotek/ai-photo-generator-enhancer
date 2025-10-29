# FastAPI Backend

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import Optional, Any
import os
from datetime import datetime, timedelta
from jose import JWTError, jwt
from passlib.context import CryptContext
import logging
import json

# Database setup (using SQLAlchemy for simplicity, adapt for async if needed)
import sqlalchemy
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, JSON, Identity
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.sql import func


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database URL from environment variable
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://user:password@localhost:5432/database")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# JWT Secret Key from environment variable
SECRET_KEY = os.environ.get("SECRET_KEY", "super-secret-key")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Database Models --- #

class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, Identity(), primary_key=True)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    username = Column(String, unique=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class AIGeneration(Base):
    __tablename__ = "ai_generations"

    generation_id = Column(Integer, Identity(), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.user_id", ondelete="CASCADE"))
    generation_type = Column(String, nullable=False)
    input_image_url = Column(String, nullable=False)
    output_image_url = Column(String)
    generation_parameters = Column(JSON)
    status = Column(String, default="pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class UserProfile(Base):
    __tablename__ = "user_profiles"

    profile_id = Column(Integer, Identity(), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.user_id", ondelete="CASCADE"), unique=True)
    profile_data = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class APIUsageLog(Base):
    __tablename__ = "api_usage_logs"

    log_id = Column(Integer, Identity(), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.user_id", ondelete="SET NULL"))
    endpoint = Column(String, nullable=False)
    request_timestamp = Column(DateTime(timezone=True), server_default=func.now())
    request_body = Column(JSON)
    response_code = Column(Integer)
    processing_time_ms = Column(Integer)

Base.metadata.create_all(bind=engine)

# --- Pydantic Models --- #

class UserCreate(BaseModel):
    email: str
    password: str
    username: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class AIGenerationCreate(BaseModel):
    generation_type: str
    input_image_url: str
    generation_parameters: Optional[dict] = None

class AIGenerationUpdate(BaseModel):
    output_image_url: Optional[str] = None
    status: Optional[str] = None

# --- Security --- #

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(SessionLocal)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("username")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user


async def get_current_active_user(current_user: User = Depends(get_current_user)):
    return current_user

# --- FastAPI App --- #

app = FastAPI()

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = datetime.utcnow()
    response = await call_next(request)
    process_time = (datetime.utcnow() - start_time).microseconds / 1000
    formatted_process_time = f'{process_time:.2f}ms'
    logger.info(f"Request: {request.method} {request.url} - Response: {response.status_code} - Time: {formatted_process_time}")

    # Log to database (consider using a background task for this)
    try:
        db = SessionLocal()
        api_log = APIUsageLog(
            user_id = request.state.user.user_id if hasattr(request.state, 'user') and request.state.user else None,
            endpoint = request.url.path,
            request_body = json.loads(await request.body()) if request.method in ["POST", "PUT", "PATCH"] else None,
            response_code = response.status_code,
            processing_time_ms = int(process_time)
        )
        db.add(api_log)
        db.commit()
    except Exception as e:
        logger.error(f"Error logging API usage: {e}")
    finally:
        db.close()

    return response


# --- Authentication Endpoints --- #

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"username": user.username},
        expires_delta=access_token_expires,
    )
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/users", response_model=None, status_code=status.HTTP_201_CREATED)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    hashed_password = get_password_hash(user.password)
    db_user = User(email=user.email, hashed_password=hashed_password, username=user.username)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "User created successfully"}


@app.get("/users/me", response_model=None)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    return {"username": current_user.username, "email": current_user.email, "user_id": current_user.user_id}

# --- AI Generation Endpoints --- #

@app.post("/ai-generations", response_model=None, status_code=status.HTTP_201_CREATED)
async def create_ai_generation(
    generation: AIGenerationCreate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    try:
        db_generation = AIGeneration(
            user_id=current_user.user_id,
            generation_type=generation.generation_type,
            input_image_url=generation.input_image_url,
            generation_parameters=generation.generation_parameters,
        )
        db.add(db_generation)
        db.commit()
        db.refresh(db_generation)
        return {"generation_id": db_generation.generation_id, "message": "AI generation request created"}
    except Exception as e:
        logger.error(f"Error creating AI generation request: {e}")
        db.rollback()
        raise HTTPException(status_code=500, detail="Failed to create AI generation request")


@app.get("/ai-generations/{generation_id}", response_model=None)
async def read_ai_generation(
    generation_id: int,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    db_generation = db.query(AIGeneration).filter(AIGeneration.generation_id == generation_id, AIGeneration.user_id == current_user.user_id).first()
    if db_generation is None:
        raise HTTPException(status_code=404, detail="AI generation request not found")
    return db_generation


@app.patch("/ai-generations/{generation_id}", response_model=None)
async def update_ai_generation(
    generation_id: int,
    generation_update: AIGenerationUpdate,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    db_generation = db.query(AIGeneration).filter(AIGeneration.generation_id == generation_id, AIGeneration.user_id == current_user.user_id).first()
    if db_generation is None:
        raise HTTPException(status_code=404, detail="AI generation request not found")

    update_data = generation_update.dict(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_generation, key, value)

    db_generation.updated_at = datetime.utcnow()
    db.add(db_generation)
    db.commit()
    db.refresh(db_generation)
    return {"message": "AI generation request updated"}


# --- User Profile Endpoints (Example) --- #

@app.get("/profile", response_model=None)
async def read_user_profile(current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    profile = db.query(UserProfile).filter(UserProfile.user_id == current_user.user_id).first()
    if profile:
        return profile.profile_data
    else:
        return {}

@app.put("/profile", response_model=None)
async def update_user_profile(profile_data: dict, current_user: User = Depends(get_current_active_user), db: Session = Depends(get_db)):
    profile = db.query(UserProfile).filter(UserProfile.user_id == current_user.user_id).first()

    if profile:
        profile.profile_data = profile_data
        profile.updated_at = datetime.utcnow()
    else:
        profile = UserProfile(user_id=current_user.user_id, profile_data=profile_data)
        db.add(profile)

    db.commit()
    return {"message": "Profile updated successfully"}


@app.get("/")
async def root():
    return {"message": "AI Photo Generator API is running"}
