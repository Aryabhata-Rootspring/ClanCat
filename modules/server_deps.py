import asyncio
import smtplib
import time
import ssl
from pydantic import BaseModel
from datetime import date
import inflect
import hashlib
import math
import pyotp
import requests
import logging
import sys
import sys
from .common_deps import *
from .config import SECURE, SERVER_URL, EXP_RATE, AUTH_LIMIT
from .coremeow import *
inflect_engine = inflect.engine()
logging.captureWarnings(True)

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
    requests.get(SERVER_URL + "/clancat/brs/internal/cache/update", verify = SECURE)
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

