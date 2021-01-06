import pyximport
pyximport.install(pyimport = True) # Enable CYthon

# Basic dependencies
from pydantic import BaseModel
from fastapi import Form as FastForm
from starlette_wtf import csrf_protect
from markupsafe import Markup
import asyncio
from .common_deps import *
from .coremeow import render_template, BRS, requests, api, redirect, abort
import builtins


# Lots of modules need this, so...
class SaveExperimentPage(BaseModel):
    username: str
    token: str
    code: str
