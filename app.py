from fastapi import FastAPI, Depends, BackgroundTasks, Request, Form as FastForm
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette_wtf import CSRFProtectMiddleware
from starlette_session import SessionMiddleware
from starlette_session.backends import BackendType
import aioredis
import builtins
import requests as __r__
import config
import logging; logging.captureWarnings(True); # Capture warnings
import os
import importlib
from modules.rt import render_template

# FastAPI App Code
app = FastAPI()
app.add_middleware(CSRFProtectMiddleware, csrf_secret='1f03eea1ffb7446294f71342bf110f21b91a849377144b789219a6a314ffb7815a0b69b2d6274bae84dd66b734393241')
api = "https://127.0.0.1:443/api/v1"
RKEY = open("rkey").read().replace("\n", "").replace(" ", "")

@app.on_event("startup")
async def on_startup():
    redis_client = await aioredis.create_redis_pool(("localhost", 6379))
    app.add_middleware(SessionMiddleware, secret_key="iiqEEZ0z1wXWeJ3lRJnPsamlvbmEq4tesBDJ38HD3dj329Ddrejrj34jfjrc4j3fwkjVrT34jkFj34jkgce3jfqkeieiei3jd44584830290riuejnfdiuwrjncjnwe8uefhnewfu553kf84EyfFH48SHSWk", cookie_name="catphi_session-" + RKEY, backend_type=BackendType.aioRedis, backend_client=redis_client, same_site = 'strict', max_age = 7 * 24 * 60 * 60, https_only = True)

# A wrapper around requests and BRS sruff
class requests():
    @staticmethod
    def get(url):
        return __r__.get(url, verify = config.SECURE)
    @staticmethod
    def post(url, json):
        return __r__.post(url, json = json, verify = config.SECURE)
builtins.requests = requests
class BRS():
    def __init__(self, request_json):
        self.brs_dict = {}
        for obj in request_json:
            if obj["tid"] in self.brs_dict.keys(): #We either already have this tid as a key (append) or we should make a new key
                self.brs_dict[obj["tid"]].append([obj["topic_name"], obj["cid"], obj["concept_name"]])
            else:
                self.brs_dict[obj["tid"]] = [[obj["topic_name"], obj["cid"], obj["concept_name"]]]
builtins.brs = BRS(requests.get(api + "/clancat/bristlefrost/rootspring/shadowsight").json()).brs_dict
# Exceptions
@app.exception_handler(StarletteHTTPException)
async def not_found(request, exc):
    if str(exc).__contains__("CSRF"):
        request.session["csrf"], request.session["status_code"] = True, 400
        return await render_template(request, "generic_error.html", header = "CSRF Error", error = "CSRF Forgery Alert. Your request cannot be processed right now as it may not have come from you. Please click Back and then refresh your page and try again. Thank you :)")
    request.session["status_code"] = 404
    return await render_template(request, "generic_error.html", header = "404", error = "We can't find what you're looking for... Ooops.")

print("APP: Loading Modules")
# Include all the modules
for f in os.listdir("modules/app"):
    if not f.startswith("_"):
        print("APP MODLOAD: modules.app." + f.replace(".py", ""))
        route = importlib.import_module("modules.app." + f.replace(".py", ""))
        app.include_router(route.router)

