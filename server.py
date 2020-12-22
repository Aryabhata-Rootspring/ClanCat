from fastapi import FastAPI, Depends, BackgroundTasks, WebSocket
import asyncio
import asyncpg
import builtins
import importlib
import os
async def setup_db():
    __db = await asyncpg.create_pool(
        host="127.0.0.1", user="catphi", password="Rootspring11,", database="catphi"
    )  # Login stuff
    # Always do this to ensure best performance
    await __db.execute("VACUUM")
    # Represents a subject
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS subject_table (metaid TEXT, name TEXT, description TEXT)"
    )
    # Create an index for the subjects
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS subject_index ON subject_table (metaid, name, description)"
    )
    # Represents a topic
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS topic_table (metaid TEXT, name TEXT, description TEXT, tid TEXT)"
    )
    # Create an index for the topics
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS topic_index ON topic_table (metaid, name, description, tid)"
    )
    # Represents a concept
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS concept_table (tid TEXT, title TEXT, cid INTEGER NOT NULL, content TEXT)"
    )
    # Create an index for the concepts
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS concept_index ON concept_table (tid, title, cid, content)"
    )
    # Represents a single login in the database
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS login (token TEXT, username TEXT, password TEXT, email TEXT, status INTEGER, scopes TEXT, mfa BOOLEAN, mfa_shared_key TEXT, backup_key TEXT)"
    )
    # Create an index for login
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS login_index ON login (token, username, password, email, status, scopes, mfa, mfa_shared_key, backup_key)"
    )
    # A profile of a user
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS profile (username TEXT, joindate DATE, public BOOLEAN, badges TEXT, level TEXT, listing BOOLEAN, items TEXT, followers TEXT[], following TEXT[])"
    )
    # Create an index for the three things that will never/rarely change,
    # namely join date , username and public/private profile
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS profile_index ON profile (username, joindate, public, badges, level, listing, items, followers, following)"
    )
    # All the topics a user has completed or is working on
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS profile_topic (username TEXT, tid TEXT, progress TEXT, done BOOLEAN)"
    )
    # Profile Concept Index
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS profile_topic_index ON profile_topic (username, tid, done)"
    )
    # General Purpose Simulations
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS experiments (sid TEXT, description TEXT, code TEXT, type TEXT)"
    )
    # Generic Simulations (Experiments) Index
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS experiments_index ON experiments (sid, description, code, type)"
    )
    # Topic Practice
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS topic_practice (tid TEXT, qid INTEGER, type TEXT, question TEXT, answers TEXT, correct_answer TEXT, solution TEXT DEFAULT 'There is no solution for this problem yet!', recommended_time INTEGER)"
    )
    # Topic Practice Index
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS topic_practice_index ON topic_practice (tid, qid, type, question, answers, correct_answer, solution, recommended_time)"
        )
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS topic_practice_tracker (username TEXT, tid TEXT, qid INTEGER, answer TEXT, lives TEXT, path TEXT)"
    )
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS topic_practice_index ON topic_practice_tracker (username, tid, qid, answer, lives, path)"
    )
    return __db


app = FastAPI(root_path="/api/v1", servers=[
    {"url": "/", "description": "Frontend"},
    {"url": "/api/v1", "description": "Backend API"},
    ])

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
        print("SERVER MODLOAD: modules.server." + f.replace(".py", ""))
        route = importlib.import_module("modules.server." + f.replace(".py", ""))
        app.include_router(route.router)

@app.get("/")
async def root():
    return {"message": "Pong!"}
