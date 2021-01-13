import pyximport
pyximport.install()

from fastapi import FastAPI
from fastapi.responses import ORJSONResponse
import builtins
import importlib
import os
from modules.db import setup_db

app = FastAPI(
    root_path="/api/v1",
    servers=[{"url": "/api/v1", "description": "Backend API"}],
    default_response_class = ORJSONResponse
)


@app.on_event("startup")
async def startup():
    print("SERVER: Setting up database")
    builtins.db = await setup_db()


@app.on_event("shutdown")
async def shutdown():
    print("SERVER: Closing database")
    await db.close()

print("SERVER: Loading Modules")

# Include all the modules
for f in os.listdir("modules/server"):
    if not f.startswith("_"):
        module = "modules.server." + f.replace(".py", "")
        print("SERVER MODLOAD: " + module)
        route = importlib.import_module(module)
        app.include_router(route.router)


@app.get("/")
async def root():
    return {"message": "Pong!"}
