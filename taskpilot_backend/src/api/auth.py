# Authentication routes and logic for the TaskPilot backend.
from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import JWTError, jwt

from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

# Dummy DB for demonstration (in-memory):
fake_users_db = {}

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# SECRET KEY for signing JWTs -- replace with environment variable or configuration in production!
SECRET_KEY = "supersecret-dev-key"  # TODO: Use .env in real setup
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

router = APIRouter(prefix="/auth", tags=["auth"])


# PUBLIC_INTERFACE
class User(BaseModel):
    """User DB model (simulation for this prototype)."""
    username: str
    email: EmailStr
    hashed_password: str


# PUBLIC_INTERFACE
class UserCreate(BaseModel):
    """Schema for user registration."""
    username: str = Field(..., description="Unique username")
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=6, description="Plaintext password")


# PUBLIC_INTERFACE
class UserLogin(BaseModel):
    """Schema for user login."""
    username: str = Field(..., description="Username")
    password: str = Field(..., min_length=6, description="Plaintext password")


# PUBLIC_INTERFACE
class UserOut(BaseModel):
    """Schema for returning user data (safe)."""
    username: str
    email: EmailStr


# PUBLIC_INTERFACE
class Token(BaseModel):
    """Schema for access token response."""
    access_token: str
    token_type: str = "bearer"


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# --- Utility functions ---

# PUBLIC_INTERFACE
def verify_password(plain_password, hashed_password):
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)

# PUBLIC_INTERFACE
def get_password_hash(password):
    """Hash a password for storage."""
    return pwd_context.hash(password)

# PUBLIC_INTERFACE
def authenticate_user(username: str, password: str):
    """Authenticate user by username and password, return User if valid."""
    user = fake_users_db.get(username)
    if not user:
        return None
    if not verify_password(password, user['hashed_password']):
        return None
    return User(**user)

# PUBLIC_INTERFACE
def create_access_token(data: dict, expires_delta: timedelta | None = None):
    """Create a new JWT access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


# --- Auth Endpoints ---

# PUBLIC_INTERFACE
@router.post("/register", response_model=UserOut, status_code=201, summary="Register new user", description="Create a new user account. Username and email must be unique.")
def register(user: UserCreate):
    if user.username in fake_users_db:
        raise HTTPException(status_code=400, detail="Username already registered")
    if any(u['email'] == user.email for u in fake_users_db.values()):
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(username=user.username, email=user.email, hashed_password=hashed_password)
    fake_users_db[user.username] = new_user.dict()
    return UserOut(username=new_user.username, email=new_user.email)

# PUBLIC_INTERFACE
@router.post("/login", response_model=Token, summary="User login", description="Authenticate user and get JWT access token.")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

# PUBLIC_INTERFACE
def get_current_user(token: str = Depends(oauth2_scheme)):
    """Extract user from JWT token."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = fake_users_db.get(username)
    if user is None:
        raise credentials_exception
    return UserOut(username=user["username"], email=user["email"])
