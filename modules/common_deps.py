import string
import secrets
from fastapi import Request, Depends, BackgroundTasks, WebSocket, APIRouter
from typing import Optional


def get_token(length: str) -> str:
    secure_str = "".join(
        (secrets.choice(
            string.ascii_letters + string.digits) for i in range(length))
    )
    return secure_str
