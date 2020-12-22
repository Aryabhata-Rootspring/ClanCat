from fastapi import Depends, BackgroundTasks, WebSocket, APIRouter 
import asyncio
import secrets
import string
import smtplib
import time
import ssl
from pydantic import BaseModel, ValidationError, validator, BaseSettings
from typing import Optional
from passlib.context import CryptContext
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import json
from datetime import date
import inflect
import hashlib
import math
import pyotp
import requests
import config
import logging
import sys
import sys
sys.path.append("..")
inflect_engine = inflect.engine()
logging.captureWarnings(True)

SERVER_URL = "https://127.0.0.1:443"  # Main Server URL
HASH_SALT = "66801b86-06ff-49c7-a163-eeda39b8cba9_66bc6c6c-24e3-11eb-adc1-0242ac120002_66bc6c6c-24e3-11eb-adc1-0242ac120002"
EXP_RATE = 11 # This is the rate at which users will get experience per concept (11 exp points per completed concept)
pwd_context = CryptContext(schemes=["pbkdf2_sha512"], deprecated="auto")

def hash_pwd(username: str, password: str) -> str:
    return pwd_context.hash("Shadowsight1" + HASH_SALT + username + password)

def verify_pwd(username: str, password: str, hashed_pwd: str) -> bool:
    return pwd_context.verify("Shadowsight1" + HASH_SALT + username + password, hashed_pwd)

def get_token(length: str) -> str:
    secure_str = "".join(
        (secrets.choice(string.ascii_letters + string.digits) for i in range(length))
    )
    return secure_str

def brsret(*, code: str = None, html: str = None, outer_scope: dict = None, support: bool = False, **kwargs: str) -> dict:
    if outer_scope is None:
        eMsg = {"code": code, "context": kwargs}
    else:
        eMsg = {"code": code, **outer_scope, "context": kwargs}
    if html != None:
        eMsg["html"] = f"<p style='text-align: center; color: red'>{html}"
        if support is True:
            eMsg["html"] += "<br/>Contact CatPhi Support for more information and support."
        eMsg["html"] += "</p>"
    return eMsg

async def authorize_user(username, token):
    # Check if the username is even registered with us and if the username
    # given in data.keys() is correct
    login_cred = await db.fetchrow("SELECT username, scopes FROM login WHERE token = $1", token)
    if login_cred is None:
        return False
    elif login_cred["scopes"] is None:
        return False
    elif login_cred["username"] != username:
        return False
    elif "admin" not in login_cred["scopes"].split(":"):
        return False
    return True

def server_watchdog():
    print("Watchdog: New Event Dispatched To Client")
    requests.get(SERVER_URL + "/api/internal/brs/cache/update", verify = config.SECURE)
    return

class TokenModel(BaseModel):
    token: str

# Model for things that need MFA
class MFAModel(TokenModel):
    otp: Optional[str] = None

# Basic model for things that need a username
class UserModel(TokenModel):
    username: str

# Basic model for things that need a username and password
class UserPassModel(BaseModel):
    username: str
    password: str

