import pyximport
pyximport.install(pyimport = True) # Enable CYthon

from fastapi import FastAPI
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette_wtf import CSRFProtectMiddleware
from starlette.middleware.sessions import SessionMiddleware
import builtins
import os
import importlib
from modules.coremeow import (
    api,
    render_template,
    BRS,
    requests,
    CSRF_SECRET,
    SESSION_SECRET
)
# FastAPI App Code
app = FastAPI()
app.add_middleware(CSRFProtectMiddleware, csrf_secret=CSRF_SECRET)

@app.on_event("startup")
async def on_startup():
    app.add_middleware(
        SessionMiddleware,
        secret_key=SESSION_SECRET,
        same_site='strict',
        max_age=7 * 24 * 60 * 60,
        https_only=True
    )

builtins.brs = BRS(requests.get(
    api + "/clancat/bristlefrost/rootspring/shadowsight"
    ).json()).brs_dict


# Exceptions
@app.exception_handler(StarletteHTTPException)
async def not_found(request, exc):
    if str(exc).__contains__("CSRF"):
        request.session["csrf"], request.session["status_code"] = True, 400
        return await render_template(
            request,
            "generic_error.html",
            header="CSRF Error. Contact us for more info",
        )
    request.session["status_code"] = 404
    return await render_template(
        request,
        "generic_error.html",
        header="404",
        error="We can't find what you're looking for... Ooops."
    )

print("APP: Loading Modules")
# Include all the modules
for f in os.listdir("modules/app"):
    if not f.startswith("_"):
        print("APP MODLOAD: modules.app." + f.replace(".py", ""))
        route = importlib.import_module("modules.app." + f.replace(".py", ""))
        app.include_router(route.router)
