from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import and include the authentication router
from .auth import router as auth_router

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register authentication endpoints
app.include_router(auth_router)

@app.get("/")
def health_check():
    """Health check route for service status."""
    return {"message": "Healthy"}

