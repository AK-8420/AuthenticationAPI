from fastapi import FastAPI, Depends
from fastapi.security import OAuth2PasswordBearer
from src import models

app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

@app.get("/")
async def root():
    return {"message":"Hello, World!"}


@app.get("/users/")
async def get_users(token: str = Depends(oauth2_scheme)):
    return {"token": token}