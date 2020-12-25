# Basic dependencies
from fastapi import APIRouter, Depends, BackgroundTasks, Request, Form as FastForm
import asyncio
import time
from starlette.exceptions import HTTPException as StarletteHTTPException
from markupsafe import Markup, escape
from pydantic import BaseModel, ValidationError, validator, BaseSettings
from typing import Optional
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import json
import requests
import config
import requests as __r__
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_302_FOUND,HTTP_303_SEE_OTHER
from starlette_wtf import StarletteForm, CSRFProtectMiddleware, csrf_protect
from starlette_session import SessionMiddleware
from starlette_session.backends import BackendType
import aioredis
import builtins
from .common_deps import *
import logging
from .rt import render_template
logging.captureWarnings(True)

api = "https://127.0.0.1:443/api/v1"

# Wrappers
# A wrapper around requests
class requests():
    @staticmethod
    def get(url):
        return __r__.get(url, verify = config.SECURE)
    @staticmethod
    def post(url, json):
        return __r__.post(url, json = json, verify = config.SECURE)

# BRS class to deal with servers BRS stuff
class BRS():
    def __init__(self, request_json):
        # NOTE: We cureently ignore metaid/subject for now until there is need for it
        brs_dict = {} # {tid: []}
        for obj in request_json:
            if obj["tid"] in brs_dict.keys():
                # We already have this tid as a key, add to it
                brs_dict[obj["tid"]].append([obj["topic_name"], obj["cid"], obj["concept_name"]])
            else:
                brs_dict[obj["tid"]] = [[obj["topic_name"], obj["cid"], obj["concept_name"]]]
        self.brs_dict = brs_dict

# redirect wrapper
def redirect(path):
    return RedirectResponse(path, status_code=HTTP_303_SEE_OTHER)

# abort wrapper
def abort(code):
    raise StarletteHTTPException(status_code=code)

# Lots of modules need this, so...
class SaveExperimentPage(BaseModel):
    username: str
    token: str
    code: str

