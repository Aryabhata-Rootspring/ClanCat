import builtins
from starlette_wtf import StarletteForm
from fastapi.templating import Jinja2Templates
templates = Jinja2Templates(directory="templates")
from .config import SECURE, API as api
import requests as __r__
import logging; logging.captureWarnings(True); # Capture warnings
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.responses import RedirectResponse
from starlette.status import HTTP_303_SEE_OTHER

builtins.api = api

# Dummy form for Starlette-WTF and render_template
class Form(StarletteForm):
    pass

async def render_template(request, f, **kwargs):
    # This is a BristleRootShadow (brs) object which basically contains
    if f.__contains__("login.html") or f.__contains__("register.html") or f.__contains__("reset"):
        login_register = True
    else:
        login_register = False
    if request.session.get("csrf") is None:
        form = await Form.from_formdata(request)
    else:
        form = None
        request.session["csrf"] = None
    if request.session.get("status_code") is not None:
        status_code = request.session.get("status_code")
        request.session["status_code"] = None
    else:
        status_code = 200
    base_dict = {'request': request, "username": request.session.get("username"), "brs_list": builtins.brs, "login_register": login_register, "form": form}
    return templates.TemplateResponse(f, {**base_dict, **kwargs}, status_code = status_code)

class BRS():
    def __init__(self, request_json):
        self.brs_dict = {}
        for obj in request_json:
            if obj["tid"] in self.brs_dict.keys(): #We either already have this tid as a key (append) or we should make a new key
                self.brs_dict[obj["tid"]].append([obj["topic_name"], obj["cid"], obj["concept_name"]])
            else:
                self.brs_dict[obj["tid"]] = [[obj["topic_name"], obj["cid"], obj["concept_name"]]]

class requests():
    @staticmethod
    def get(url):
        return __r__.get(url, verify = SECURE)
    @staticmethod
    def post(url, json):
        return __r__.post(url, json = json, verify = SECURE)

def redirect(path):
    return RedirectResponse(path, status_code=HTTP_303_SEE_OTHER)

def abort(code):
    raise StarletteHTTPException(status_code=code)

builtins.requests = requests
builtins.BRS = BRS
