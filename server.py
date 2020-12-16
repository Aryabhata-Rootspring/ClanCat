from fastapi import FastAPI, Depends, BackgroundTasks
import asyncio
import secrets
import string
import smtplib
import time
import asyncpg
import ssl
from pydantic import BaseModel, ValidationError, validator, BaseSettings
from typing import Optional
from passlib.context import CryptContext
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import json
from datetime import date
import inflect
import hashlib
import hmac
import math
import pyotp
import requests
import config
import logging
inflect_engine = inflect.engine()
logging.captureWarnings(True)

SERVER_URL = "https://127.0.0.1:443"  # Main Server URL
HASH_SALT = "66801b86-06ff-49c7-a163-eeda39b8cba9_66bc6c6c-24e3-11eb-adc1-0242ac120002_66bc6c6c-24e3-11eb-adc1-0242ac120002"
EXP_RATE = 11 # This is the rate at which users will get experience per concept (11 exp points per completed concept)
pwd_context = CryptContext(schemes=["pbkdf2_sha512"], deprecated="auto")

def get_token(length: str) -> str:
    secure_str = "".join(
        (secrets.choice(string.ascii_letters + string.digits) for i in range(length))
    )
    return secure_str

def brsret(*, code: str = None, html: str = None, support: bool = False, **kwargs: str) -> dict:
    eMsg = {"code": code, "context": kwargs}
    if html != None:
        eMsg["html"] = f"<p style='text-align: center; color: red'>{html}"
        if support is True:
            eMsg["html"] += "<br/>Contact CatPhi Support for more information and support."
        eMsg["html"] += "</p>"
    return eMsg

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
        "CREATE TABLE IF NOT EXISTS profile (username TEXT, joindate DATE, public BOOLEAN, badges TEXT, level TEXT, listing BOOLEAN, items TEXT)"
    )
    # Create an index for the three things that will never/rarely change,
    # namely join date , username and public/private profile
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS profile_index ON profile (username, joindate, public, badges, level, listing, items)"
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

# resetDict is a dictionary of password reset requests
# currently present
resetDict = {}

# mfaDict is a dictionary for MFA Logins
mfaDict = {}

# mfaNewDict is a dictionary for new MFA setup
mfaNewDict = {}

SENDER_EMAIL = "sandhoners123@gmail.com"
SENDER_PASS = "onsybsptaicdvtwc"

# Badge Data
# Format is bid = {name: Name of the badge, image: Image URL to the badge, experience: Experience needed to get the badge}.
# To make sure it works on older clients, send the entire BADGES dict in a badge request

BADGES = {
    "FIRST_TIME": {
        "name": "Welcome To CatPhi!!!",
        "description": "Thank you for registering with CatPhi",
        "image": "https://interactive-examples.mdn.mozilla.net/media/cc0-images/grapefruit-slice-332-332.jpg",
        "experience": 0
    },
    "FIRST_BADGE": {
        "name": "First Badge",
        "description": "It's your first badge! Enjoy!!!!",
        "image": "https://cdn.pixabay.com/photo/2015/04/23/22/00/tree-736885__340.jpg",
        "experience": 10,
    },
    "APPRENTICE_I": {
        "name": "CatPhi Apprentice I",
        "description": "Congratulations on your first accomplishment as an apprentice",
        "image": "https://cdn.pixabay.com/photo/2015/04/23/22/00/tree-736885__340.jpg",
        "experience": 40, 
    },
    "APPRENTICE_II": {
        "name": "CatPhi Apprentice II",
        "description": "Your almost a warrior now.",
        "image": "https://cdn.pixabay.com/photo/2015/04/23/22/00/tree-736885__340.jpg",
        "experience": 90,
    },
}

RANKS = {
    "leader": {
        "name": "Leader",
        "desc": "A CatPhi Leader. They make sure that CatPhi works correctly and they handle the entire website including the backend!<br/><strong><em>Not much else is known about them...</strong></em>",
    },
    "apprentice": {
        "name": "Apprentice",
        "desc": "A new explorer arrives... It's OK! Everone has to start somewhere!",
        "levelup": 100,
        "next": "young_warrior"
    },
    "young_warrior": {
        "name": "Young Warrior",
        "desc": "TODO",
        "levelup": 600,
        "next": "TODO"
    }
}

ITEMS = {
    "experience": {
        "name": "Experience Points",
        "desc": "A rare mystical substance found in the land of CatPhi that can do some magical and mysterious things. You can earn these from the Witches Of CatPhi by doing more topics and solving more practice questions<br/><strong><em>There is no other known way to get these...</strong></em>",
        "display": "<i class='fas fa-magic' style='margin-right: 3px'></i>",
        "special_effects": {
            "levelup:young_warrior": 100
        }
    }, 
}

# Get all new badges given a current set of badges and the new exp_point value
def get_new_badges(curr_badges, exp_points):
    new_badges = []
    for badge in BADGES.keys():
        if badge in curr_badges:
            continue # Ignore badges we already have
        if int(BADGES[badge]["experience"]) <= int(exp_points):
            new_badges.append(badge)
    return "||".join(new_badges), "||".join(curr_badges.split("||") + new_badges)


class Settings(BaseSettings):
    openapi_url: str = "/rootspring/openapi.json"

settings = Settings()

app = FastAPI(openapi_url=settings.openapi_url, root_path="/api/v1", servers=[
    {"url": "/", "description": "Frontend"},
    {"url": "/api/v1", "description": "Backend API"},
    ])

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

# Basic model for all authentication
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


class Save(UserModel):
    async def save(self, type):
        if type not in ["topic", "generic", "concept", "topic_practice"]:
            return {"error": "Invalid Arguments"} # Invalid Arguments

        auth_check = await authorize_user(self.username, self.token)
        if auth_check == False:
            return {"error": "Not Authorized"}
        if type == "generic":
            await db.execute(
                "UPDATE experiments SET code = $1 WHERE sid = $2",
                self.code,
                self.sid,
            )
        elif type == "topic":
            await db.execute(
                "UPDATE topic_table SET description = $1 WHERE tid = $2",
                self.description,
                self.tid,
            )
        elif type == "concept":
            # Firstly, make sure the topic actually exists in
            # topic_table
            tcheck = await db.fetchrow("SELECT tid FROM topic_table WHERE tid = $1", self.tid)
            if tcheck is None:
                # Topic Does Not Exist
                return {"error": "Topic Does Not Exist"}
            concept_count = await db.fetch("SELECT COUNT(cid) FROM concept_table WHERE tid = $1", self.tid)
            if int(concept_count[0]["count"]) < int(self.cid):
                return {"error": "0002"}  # Invalid Arguments
            concepts = await db.fetch("SELECT cid FROM concept_table WHERE tid = $1 ORDER BY cid ASC", self.tid)  # Get all the concepts in ascending order
            absolute_cid = concepts[int(self.cid) - 1]["cid"] # Calculate the absolute concept id
            await db.execute(
                "UPDATE concept_table SET content = $1 WHERE tid = $2 AND cid = $3",
                self.code,
                self.tid,
                int(absolute_cid),
            )
        # tid TEXT, qid INTEGER, type TEXT, question TEXT, answers TEXT, correct_answer TEXT, solution TEXT DEFAULT 'There is no solution for this problem yet!', recommended_time INTEGER
        elif type == "topic_practice":
            await db.execute(
                "UPDATE topic_practice SET type = $1, question = $2, answers = $3, correct_answer = $4, solution = $5, recommended_time = $6 WHERE tid = $7 AND qid = $8",
                self.type,
                self.question,
                self.answers,
                self.correct_answer, 
                self.solution,
                self.recommended_time,
                self.tid,
                self.qid,
            )
        return {"error": "Successfully saved entity!"}

class SaveTopic(Save):
    tid: str
    description: str

class SaveTopicConcept(Save):
    tid: str
    cid: int
    code: str

class SaveTopicPractice(Save):
    type: str
    question: str
    answers: Optional[str] = None
    correct_answer: str
    tid: str
    qid: int
    solution: str
    recommended_time: Optional[int] = 0

class SaveExperiment(Save):
    sid: str
    code: str

# Auth Models
class AuthUsernameEdit(MFAModel):
    old_username: str
    new_username: str
    password: str

class AuthPasswordEdit(MFAModel):
    username: str
    password: str
    old_password: str

class AuthResetRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None

class AuthResetChange(TokenModel):
    new_password: str

class AuthLoginRequest(UserPassModel):
    pass

class AuthMFANewRequest(TokenModel):
    pass

class AuthMFARequest(MFAModel):
    pass

class AuthLogoutRequest(BaseModel):
    username: str

class AuthRegisterRequest(UserPassModel):
    email: str

class AuthRecoveryRequest(BaseModel):
    backup_key: str

# Profile Models

class ProfileVisibleRequest(UserModel):
    state: str
    disable_state: Optional[int] = None

class ProfileTrackWriter(UserModel):
    tid: str
    status: str 
    cid: int

class ProfileTrackPracticeWriter(UserModel):
    tid: str
    qid: int
    answer: str
    lives: str
    path: str

class ProfileDeleteRequest(MFAModel):
    username: str

# **New Methods

class GenericExperimentNew(UserModel):
    description: str
    exp_type: Optional[str] = "glowscript"

class TopicNew(UserModel):
    name: str
    description: str
    metaid: str

class SubjectNew(UserModel):
    name: str
    description: str

class ConceptNew(UserModel):
    tid: str
    title: str

class TopicPracticeNew(UserModel):
    type: str
    question: str
    answers: Optional[str] = None
    correct_answer: str
    tid: str
    solution: str

# Basic Classes
class catphi():
    @staticmethod
    async def new(*, bt, type, username, token, name = None, description = None, cid = None, tid = None, concept_title = None, question = None, correct_answer = None, answers = None, question_type = None, metaid = None, solution = None, exp_type = "glowscript"):
        auth_check = await authorize_user(username, token)
        if auth_check == False:
            return {"error": "Not Authorized"}
        if type == "subject":
            table = "subject_table"
            id_table = "metaid"
        elif type == "experiment":
            table = "experiments"
            id_table = "sid"
        elif type == "topic":
            table = "topic_table"
            id_table = "tid"
            tcheck = await db.fetchrow("SELECT name FROM subject_table WHERE metaid = $1", metaid)
            if tcheck is None:
                return {"error": "Subject Does Not Exist"}
        elif type == "topic_practice":
            tcheck = await db.fetchrow("SELECT tid FROM topic_table WHERE tid = $1", tid)
            if tcheck is None:
                # Topic Does Not Exist
                return {"error": "Topic Does Not Exist"}
            
            if len(solution) < 3:
                solution = "There is no solution for this problem yet!"
            
            practice_count = await db.fetch("SELECT COUNT(qid) FROM topic_practice WHERE tid = $1", tid)
            qid=practice_count[0]["count"] + 1 # Get the count + 1 for next concept

            if question_type == "MCQ":
                await db.execute(
                    "INSERT INTO topic_practice (qid, tid, type, question, correct_answer, answers, solution, recommended_time) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                    qid,
                    tid,
                    question_type,
                    question,
                    correct_answer,
                    answers,
                    solution,
                    0,
                )
            else:
                await db.execute(
                    "INSERT INTO topic_practice (qid, tid, type, question, correct_answer, solution, recommended_time) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                    qid,
                    tid,
                    question_type,
                    question,
                    correct_answer,
                    solution,
                    0,
                )
            return {"error": "1000"}


        elif type == "concept":
            tcheck = await db.fetchrow("SELECT tid FROM topic_table WHERE tid = $1", tid)
            if tcheck is None:
                # Topic Does Not Exist
                return {"error": "Topic Does Not Exist"}
            
            concept_count = await db.fetch("SELECT COUNT(cid) FROM concept_table WHERE tid = $1", tid)
            cid=concept_count[0]["count"] + 1 # Get the count + 1 for next concept

            await db.execute(
                "INSERT INTO concept_table (tid, title, content, cid) VALUES ($1, $2, $3, $4)",
                tid,
                concept_title,
                f"Type your content for concept {concept_title} here!",
                cid
            )
            bt.add_task(server_watchdog) #Update the client
            return {"error": "1000", "page_count": concept_count[0]["count"] + 1}

        while True:
            id = get_token(101)
            id_check = await db.fetchrow(f"SELECT {id_table} FROM {table} WHERE {id_table} = $1", id)
            if id_check is None:
                break
        if type == "experiment":
            await db.execute(
                "INSERT INTO experiments (sid, description, code, type) VALUES ($1, $2, $3, $4)",
                id,
                description,
                "arrow();",
                exp_type
            )
            # No need to update the client here for this
        elif type == "subject":
            await db.execute(
                "INSERT INTO subject_table (metaid, name, description) VALUES ($1, $2, $3)",
                id,
                name,
                description,
            )
            bt.add_task(server_watchdog) # Update the client

        elif type == "topic":
            await db.execute(
                "INSERT INTO topic_table (name, description, tid, metaid) VALUES ($1, $2, $3, $4)",
                name,
                description,
                id,
                metaid,
            )
            bt.add_task(server_watchdog)# Update the client
        return {"error": "1000", id_table: id}

def server_watchdog():
    print("Watchdog: New Event Dispatched To Client")
    requests.get(SERVER_URL + "/api/internal/brs/cache/update", verify = config.SECURE)
    return

@app.on_event("startup")
async def startup():
    global db
    db = await setup_db()


@app.on_event("shutdown")
async def shutdown():
    await db.close()

@app.get("/", tags=["Server Status"])
async def root():
    return {"message": "Pong!"}

# Experiments

@app.get("/experiment/get", tags=["Experiments"])
async def get_experiment(sid: str):
    experiment = await db.fetchrow("SELECT description, code, type FROM experiments WHERE sid = $1", sid)
    if experiment is None:
        return brsret(code = "FORBIDDEN", html = "Forbidden Request")  # Not Authorized
    return brsret(code = None, sid = sid, description = experiment["description"], exp_code = experiment["code"], type = experiment["type"])

# Saving

@app.post("/experiment/save", tags=["Experiments"])
async def save_experiment(save: SaveExperiment):
    return await save.save("generic")


@app.post("/topics/save", tags=["Topics"])
async def topic_save(save: SaveTopic):
    return await save.save("topic")

@app.post("/topics/concepts/save", tags=["Topics", "Concepts"])
async def topic_concept_save(save: SaveTopicConcept):
    return await save.save("concept")

@app.post("/topics/practice/save", tags = ["Topics", "Topic Practice"])
async def topic_practice_save(save: SaveTopicPractice):
    return await save.save("topic_practice")

# Authentication Code

@app.post("/auth/account/delete", tags = ["Authentication", "Profile"])
async def delete_profile_and_account(request: ProfileDeleteRequest, bt: BackgroundTasks):
    profile_db = await db.fetchrow(
        "SELECT mfa, mfa_shared_key FROM login WHERE token = $1 AND username = $2",
        request.token,
        request.username
    )
    if profile_db is None:
        return brsret(code = "INVALID_PROFILE")
    elif profile_db["mfa"] is True:
        if request.otp is None:
            return brsret(code = "MFA_NEEDED", mfaChallenge = "mfa")
        else:
            otp = pyotp.TOTP(profile_db["mfa_shared_key"])
            if otp.verify(request.otp) is False:
                return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    bt.add_task(delete_disable_account_backend, request.token, request.username)
    return brsret()

async def delete_disable_account_backend(token: str, username: str):
    # Delete the user from login and profile
    await db.execute("DELETE FROM login WHERE token = $1", token)
    await db.execute("DELETE FROM profile WHERE username = $1", username)
    await db.execute("DELETE FROM profile_topic WHERE username = $1", username)
    await db.execute("DELETE FROM topic_practice_tracker WHERE username = $1", username)

@app.post("/auth/account/edit/username", tags = ["Authentication", "Profile"])
async def edit_account_username(request: AuthUsernameEdit, bt: BackgroundTasks):
    profile_db = await db.fetchrow(
        "SELECT mfa, mfa_shared_key, password FROM login WHERE token = $1 AND username = $2",
        request.token,
        request.old_username
    )
    new_account_db = await db.fetchrow(
        "SELECT mfa FROM login WHERE username = $1", 
        request.new_username
    )
    if profile_db is None:
        return brsret(code = "INVALID_PROFILE", html = "Invalid Profile.", support = True)
    elif new_account_db is not None:
        return brsret(code = "USERNAME_TAKEN", html = "That username has been taken. Please choose another one")
    elif profile_db["password"] is None:
        # Invalid Username Or Password
        return brsret(code = "INVALID_USER_PASS", html = "Account Recovery is needed.", support = False)
    elif pwd_context.verify("Shadowsight1" + HASH_SALT + request.old_username + request.password, profile_db["password"]) is False:
        return brsret(code = "INVALID_USER_PASS", html = "Invalid username or password.", support = False)
    elif profile_db["mfa"] is True:
        if request.otp is None:
            return brsret(code = "MFA_NEEDED", mfaChallenge = "mfa")
        else:
            otp = pyotp.TOTP(profile_db["mfa_shared_key"])
            if otp.verify(request.otp) is False:
                return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    # Rehash the password
    password = pwd_context.hash("Shadowsight1" + HASH_SALT + request.new_username + request.password)
    bt.add_task(edit_account_backend, "username", request.token, request.new_username, password, request.old_username)
    return brsret()

@app.post("/auth/account/edit/password", tags = ["Authentication", "Profile"])
async def edit_account_password(request: AuthPasswordEdit, bt: BackgroundTasks):
    profile_db = await db.fetchrow(
        "SELECT mfa, mfa_shared_key, password FROM login WHERE token = $1 AND username = $2",
        request.token,
        request.username
    )
    if profile_db is None:
        return brsret(code = "INVALID_PROFILE", html = "Invalid Profile.", support = True)
    elif profile_db["password"] is None:
        # Invalid Username Or Password
        return brsret(code = "INVALID_USER_PASS", html = "Account Recovery is needed.", support = False)
    elif pwd_context.verify("Shadowsight1" + HASH_SALT + request.username + request.old_password, profile_db["password"]) is False:
        return brsret(code = "INVALID_USER_PASS", html = "Invalid username or password.", support = False)
    elif profile_db["mfa"] is True:
        if request.otp is None:
            return brsret(code = "MFA_NEEDED", mfaChallenge = "mfa")
        else:
            otp = pyotp.TOTP(profile_db["mfa_shared_key"])
            if otp.verify(request.otp) is False:
                return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    # Rehash the password
    password = pwd_context.hash("Shadowsight1" + HASH_SALT + request.username + request.password)
    bt.add_task(edit_account_backend, "password", request.token, password)
    return brsret()


async def edit_account_backend(mode: str, token: str, new_data: str, password: Optional[str] = None, old_username: Optional[str] = None):
    if mode == "username":
        await db.execute(f"UPDATE login SET username = $1, password = $2 WHERE token = $3", new_data, password, token)
        await db.execute("UPDATE profile SET username = $1 WHERE username = $2", new_data, old_username)
        await db.execute("UPDATE profile_topic SET username = $1 WHERE username = $2", new_data, old_username)
        await db.execute("UPDATE topic_practice_tracker SET username = $1 WHERE username = $2", new_data, old_username)
    elif mode == "password":
        await db.execute(f"UPDATE login SET password = $2 WHERE token = $3", new_data, token)

# Send a reset email (stage2 auth)
@app.post("/auth/reset/send", tags = ["Authentication", "Password Reset"])
async def reset_password_send(reset: AuthResetRequest, background_tasks: BackgroundTasks):
    if reset.username is None and reset.email is not None:
        login_cred = await db.fetchrow(
            "SELECT token, username FROM login WHERE email = $1", reset.email
        )
        if login_cred is None:
            # Invalid Username Or Password
            return {"error": "1001"}

        email = reset.email
    elif reset.email is None and reset.username is not None:
        login_cred = await db.fetchrow(
            "SELECT token, username, email from login WHERE username = $1", reset.username
        )

        if login_cred is None:
            # Invalid Username Or Password
            return {"error": "1001"}
        
        email = login_cred["email"]
    else:
            # Invalid Username Or Password
            return {"error": "1001"}

    url_flag = True  # Flag to check if we have a good url id yet
    while url_flag:
        atok = get_token(101)
        if atok not in resetDict.values():
            url_flag = False
    resetDict[login_cred["token"]] = atok
    # Now send an email to the user
    reset_link = SERVER_URL + "/reset/stage2?token=" + atok
    reset_message = f"Subject: CCTP Password Reset\n\nUsername {login_cred['username']}\nPlease use {reset_link} to reset your password.\n\nIf you didn't authorize this action, please change your password immediately"
    background_tasks.add_task(send_email, email, reset_message)
    return {"error": "1000"}  # Success

def send_email(email: str, reset_message: str = ""):
    email_session = smtplib.SMTP("smtp.gmail.com", 587)
    email_session.starttls()  # TLS for security
    email_session.login(SENDER_EMAIL, SENDER_PASS)  # Email Auth
    email_session.sendmail(SENDER_EMAIL, email, reset_message)
    email_session.close()


# Change the actual password (stage3 auth)
@app.post("/auth/reset/change", tags = ["Authentication", "Password Reset"])
async def reset_password_change(reset: AuthResetChange, background_tasks: BackgroundTasks):
    if reset.token not in resetDict.values():
        # Reset Token Not Authorized
        return {"error": "1001"}
    # Change the password of the field related to that users
    # account
    token = None
    for item in resetDict.items():
        if item[1] == reset.token:
            token = item[0]
            break
    login_cred = await db.fetchrow("SELECT username, status, email FROM login WHERE token = $1", token)
    if login_cred is None:
        return {"error": "1001"}
    if int(login_cred["status"]) == 2:
        return {"error": "1101"}
    username = login_cred["username"]
    password = pwd_context.hash("Shadowsight1" + HASH_SALT + username + reset.new_password)
    # Make sure we cant use the same token again
    resetDict[token] = None
    
    # Get a new token on reset
    flag = True
    while flag:
        # Keep getting and checking token with DB
        new_token = get_token(1037)
        login_creds = await db.fetchrow(
            "SELECT username from login WHERE token = $1", new_token
        )
        if login_creds is not None:
            continue
        flag = False
    reset_message = "Subject: Your CCTP Password Was Just Reset\n\nYour CatPhi password was just reset\n\nIf you didn't authorize this action, please change your password immediately"
    # Add the two background tasks and return
    background_tasks.add_task(send_email, login_cred["email"], reset_message)
    background_tasks.add_task(reset_backend, password, token, new_token)
    return {"error": "1000"}  # Success

# Background task to update db on reset
async def reset_backend(password: str, token: str, new_token: str):
    await db.execute("UPDATE login SET password = $1, token = $3 WHERE token = $2", password, token, new_token)
    await db.execute("UPDATE login SET status = 0 WHERE token = $1", new_token)


# This checks if the reset request is in resetDict and
# returns the result


@app.get("/auth/reset/check/token", tags = ["Authentication", "Password Reset"])
async def check_reset_token(token: str = None):
    if token is None or token not in resetDict.values():
        return brsret(code = False)
    return brsret(code = True)


@app.post("/auth/login", tags = ["Authentication"])
async def login(login: AuthLoginRequest):
    if login.username is None or login.password is None:
        return brsret(code = "INVALID_USER_PASS", html = "Invalid username or password.", support = False)
    pwd = await db.fetchrow(
        "SELECT password, mfa from login WHERE username = $1",
        login.username
    )
    if pwd is None:
        # Invalid Username Or Password
        return brsret(code = "INVALID_USER_PASS", html = "Invalid username or password.", support = False)

    elif pwd_context.verify("Shadowsight1" + HASH_SALT + login.username + login.password, pwd["password"]) is False:
        return brsret(code = "INVALID_USER_PASS", html = "Invalid username or password.", support = False)

    # Check for MFA
    elif pwd["mfa"] is True:
        flag = True
        while flag:
            token = get_token(101)
            if token not in mfaDict.values() and token not in mfaDict.keys():
                flag = False
        mfaDict[token] = login.username
        return brsret(mfaChallenge = "mfa", mfaToken = token)

    login_creds = await db.fetchrow(
        "SELECT token, status, scopes from login WHERE username = $1",
        login.username,
    )
    if login_creds is None:
        return {"error": "1001"}
    if login_creds["status"] in [None, 0]:
        pass
    else:
        # This account is flagged as disabled (1) or disabled-by-admin (2)
        return brsret(code = "ACCOUNT_DISABLED", status = login_creds["status"]) # Flagged Account
    return brsret(token = login_creds["token"], scopes = login_creds["scopes"])


@app.post("/auth/mfa", tags = ["Authentication", "MFA"])
async def multi_factor_authentication(mfa: AuthMFARequest):
    if mfa.token not in mfaDict.keys():
        return brsret(code = "FORBIDDEN", html = "Forbidden Request<br/>Try logging out and back in again", support = True) # Forbidden as mfa token is wrong
    login_creds = await db.fetchrow(
        "SELECT mfa_shared_key, token, status, scopes FROM login WHERE username = $1",
        mfaDict[mfa.token],
    )
    if login_creds is None or login_creds["mfa_shared_key"] is None:
        return brsret(code = "MFA_NOT_FOUND", html = "No MFA Shared Key was found.", support = True)
    mfa_shared_key = login_creds["mfa_shared_key"]
    otp = pyotp.TOTP(mfa_shared_key)
    if otp.verify(mfa.otp) is False:
        return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    del mfaDict[mfa.token]
    if login_creds["status"] in [None, 0]:
        pass
    else:
        # This account is flagged as disabled (1) or disabled-by-admin (2)
        return brsret(code =  "ACCOUNT_DISABLED", status = login_creds["status"]) # Flagged or disabled account
    return brsret(token = login_creds["token"], scopes = login_creds["scopes"])


@app.post("/auth/mfa/disable", tags = ["Authentication", "MFA"])
async def multi_factor_authentication_disable(mfa: AuthMFARequest):
    login_creds = await db.fetchrow(
        "SELECT mfa_shared_key FROM login WHERE token = $1",
        mfa.token,
    )
    if login_creds is None or login_creds["mfa_shared_key"] is None:
        return brsret(code = "MFA_NOT_FOUND", html = "No MFA Shared Key was found.", support = True)
    mfa_shared_key = login_creds["mfa_shared_key"]
    otp = pyotp.TOTP(mfa_shared_key)
    if otp.verify(mfa.otp) is False:
        return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    await db.execute("UPDATE login SET mfa = $1 WHERE token = $2", False, mfa.token)
    return brsret(code = None)


@app.post("/auth/mfa/setup/1", tags = ["Authentication", "MFA"])
async def multi_factor_authentication_generate_shared_key(token: AuthMFANewRequest):
    login_creds = await db.fetchrow(
            "SELECT mfa_shared_key, status, email FROM login WHERE token = $1",
        token.token,
    )
    if login_creds is None or login_creds["status"] not in [None, 0]:
        return brsret(code = "ACCOUNT_DISABLED_OR_DOES_NOT_EXIST") # Flagged or disabled account and/or account does not exist
    key = pyotp.random_base32() # MFA Shared Key
    mfaNewDict[token.token] = {"key": key, "email": login_creds["email"]}
    return brsret(code = None, key = key)


@app.post("/auth/mfa/setup/2", tags = ["Authentication", "MFA"])
async def multi_factor_authentication_enable(mfa: AuthMFARequest, background_tasks: BackgroundTasks):
    if mfa.token not in mfaNewDict.keys():
        return brsret(code = "FORBIDDEN", html = "Forbidden Request", support = True) # The other steps have not yet been done yet 
    otp = pyotp.TOTP(mfaNewDict[mfa.token]["key"])
    if otp.verify(mfa.otp) is False:
        return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    await db.execute("UPDATE login SET mfa = $1, mfa_shared_key = $2 WHERE token = $3", True, mfaNewDict[mfa.token]["key"], mfa.token)
    background_tasks.add_task(send_email, mfaNewDict[mfa.token]["email"], f"Hi there\n\nSomeone has just tried to enable MFA on your account. If it wasn't you, please disable (and/or re-enable) MFA immediately using your backup code.\n\nThank you and have a nice day!")
    return brsret(code = None)


@app.post("/auth/recovery", tags = ["Authentication"])
async def account_recovery(account: AuthRecoveryRequest):
    login_creds = await db.fetchrow(
        "SELECT username, status FROM login WHERE backup_key = $1",
        account.backup_key,
    )
    if login_creds is None:
        return brsret(code = "INVALID_BACKUP_CODE", html = "Invalid Backup Code. Please try again", support = False)
    elif login_creds["status"] == 2:
        return brsret(code = "ACCOUNT_DISABLED", html = "Your account has been disabled by an administrator for violating our policies.", support = True)
    
    flag = True
    while flag:
        # Keep getting and checking token with DB (new token)
        token = get_token(1037)
        __login_creds = await db.fetchrow(
            "SELECT username from login WHERE token = $1", token
        )
        if __login_creds is not None:
            continue
        flag = False

    # Create new account recovery code/backup key
    flag = True
    while flag:
        backup_key = ""
        for i in range(0, 3):
            backup_key += pyotp.random_hex()
        __login_creds = await db.fetchrow(
            "SELECT username from login WHERE backup_key = $1", backup_key
        )
        if __login_creds is not None:
            continue
        flag = False

    def_password = pyotp.random_hex()
    def_password_hashed = pwd_context.hash("Shadowsight1" + HASH_SALT + login_creds["username"] + def_password)
    await db.execute("UPDATE login SET mfa = $1, password = $3, token = $4, backup_key = $5, status = 0 WHERE backup_key = $2", False, account.backup_key, def_password_hashed, token, backup_key)
    return brsret(code = None, html = f"Your account has successfully been recovered.<br/>Username: {login_creds['username']}<br/>Temporary Password: {def_password}<br/>New Backup Key: {backup_key}<br/>Change your password as soon as you login")


@app.post("/auth/register", tags = ["Authentication"])
async def register(register: AuthRegisterRequest, background_tasks: BackgroundTasks):
    username = register.username
    password = pwd_context.hash("Shadowsight1" + HASH_SALT + username + register.password)
    email = register.email
    login_creds = await db.fetchrow(
        "SELECT token from login WHERE username = $1 OR email = $2", username, email
    )
    if login_creds is not None:
        # That username or email is in use
        return brsret(code = "USERNAME_OR_EMAIL_IN_USE", html = "That username or email is currently in use. Please try using another one")
    flag = True
    while flag:
        # Keep getting and checking token and account backup key with DB
        token = get_token(1037)
        backup_key = ""
        for i in range(0, 3):
            backup_key += pyotp.random_hex()
        login_creds = await db.fetchrow(
            "SELECT username from login WHERE token = $1 OR backup_key = $2", 
            token,
            backup_key
        )
        if login_creds is not None:
            continue
        flag = False

    # Registration Validation Was Successful. Add the background task to add the user to the database and exit
    background_tasks.add_task(register_backend, token, username, password, email, backup_key)
    return brsret(code = None, token = token, backup_key = backup_key)


async def register_backend(token: str, username: str, password: str, email: str, backup_key: str):
    await db.execute(
        "INSERT INTO login (token, username, password, email, status, scopes, mfa, backup_key) VALUES ($1, $2, $3, $4, 0, $5, $6, $7);",
        token,
        username,
        password,
        email,
        "user",
        False,
        backup_key
    )
    # Register their join date and add the first time registration badge
    await db.execute(
        "INSERT INTO profile (username, joindate, public, badges, level, items) VALUES ($1, $2, $3, $4, $5, $6);",
        username,
        date.today(),
        True,
        "FIRST_TIME",
        "apprentice",
        "experience:0",
    )


# Profile
@app.post("/profile/visible", tags=["Profile"])
async def change_visibility(pvr: ProfileVisibleRequest):
    # This includes account disabling which is also changing the visibility as well
    if pvr.state not in ["public", "private", "disable", "enable"]:
        return {"error": "1001"}
    usertok = await db.fetchrow("SELECT username, scopes FROM login WHERE token = $1", pvr.token)
    if usertok is None:
        return {"error": "1002"}
    is_admin = ("admin" in usertok["scopes"].split(":"))
    # Check if username and token match
    if(usertok["username"] == pvr.username or is_admin):
        pass
    else:
        return {"error": "1003"}

    # For account disabling, set state to private and flag account as disabled
    if pvr.state == "disable":
        if is_admin:
            return {"error": "1002"}
        state = "private" # Make the profile private on disable
        if pvr.disable_state is not None and is_admin:
            status = int(pvr.disable_state) # Admin disable
        else:
            status = 1
        await db.execute(
            "UPDATE login SET status = $1 WHERE username = $2", status, pvr.username
        )

    # For account re-enabling, first make sure the state is not 2 (admin disable) unless the user doing this is an admin
    elif pvr.state == "enable":
        status = await db.fetchrow(
            "SELECT status, scopes FROM login WHERE username = $1", pvr.username
        )
        if status is None or scopes is None:
            return {"error": "1001"}

        status = status["status"]
        if int(status) == 2:
            if "admin" in status["scopes"].split(":"): # Admin check
                pass
            else:
                return {"error": "1002"} # Only admins can reinstate state 2 disables
        await db.execute(
            "UPDATE login SET status = 0 WHERE username = $1", pvr.username # Re-enable the account now
        )
        return {"error": "1000"}


    elif pvr.state in ["public", "private"]:
        visible = bool(pvr.state == "public")
        await db.execute(
            "UPDATE profile SET public = $1 WHERE username = $2", visible, pvr.username
        )
        return {"error": "1000"}


@app.get("/profile", tags = ["Profile"])
async def get_profile(username: str, token: str = None):
    # Get the profile
    profile_db = await db.fetchrow(
        "SELECT profile.public, profile.joindate, profile.badges, profile.level, profile.items, login.scopes, login.mfa FROM profile INNER JOIN login ON profile.username = login.username WHERE profile.username = $1",
        username,
    )
    if profile_db is None:
        return brsret(code = "INVALID_PROFILE")
    elif not profile_db["public"]:
        private = True
        if token is None:
            return brsret(code = "PRIVATE_PROFILE")
        usertok = await db.fetchrow("SELECT username, scopes FROM login WHERE token = $1", token) # Get User Scopes
        if "admin" in usertok["scopes"].split(":") or usertok["username"] == username:
            pass
        else:
            return brsret(code = "PRIVATE_PROFILE")
    else:
        private = False
    join_obj = profile_db['joindate']
    
    # Format date
    day = join_obj.strftime("%-d")
    day = inflect_engine.ordinal(day)
    year = join_obj.strftime("%Y")
    month = join_obj.strftime("%-B")
    join = " ".join((month, day + ",", year))
    
    # Get badge URLs
    badges = {}
    for badge in profile_db["badges"].split("||"):
        try:
            badges[badge] = {"name": BADGES[badge]["name"], "image": BADGES[badge]["image"], "experience": BADGES[badge]["experience"], "description": BADGES[badge]["description"]}
        except:
            continue # Illegal badge
    
    # Get rank
    if "admin" in profile_db["scopes"].split(":"):
        level = RANKS["leader"]
        levelup_name = None
    else:
        level = RANKS[profile_db["level"]]
        levelup_name = RANKS[level["next"]]["name"]

    # Get items
    idict = []
    i = 0
    for item_obj in profile_db["items"].split("||"):
        item = item_count = item_obj.split(":")[0]
        item_count = item_obj.split(":")[1]
        idict.append({})
        idict[i] = ITEMS[item]
        idict[i]["internal_name"] = item
        idict[i]["count"] = int(item_count)
        i+=1

    mfa = profile_db['mfa']
    mfa = (mfa == True)

    return {
            "username": username,
            "scopes": profile_db["scopes"],
            "join": join,
            "private": private,
            "mfa": mfa,
            "badges": badges,
            "level": level,
            "levelup_name": levelup_name,
            "items": idict 
    }

# Track users progress
# TODO: Add quizzes and other things
@app.post("/profile/track", tags = ["Profile"])
async def profile_track_writer(tracker: ProfileTrackWriter):
    # First check if the user and token even exist
    profile_db = await db.fetchrow("SELECT mfa FROM login WHERE username = $1 AND token = $2", tracker.username, tracker.token)
    if profile_db is None:
        return brsret(code = "USER_DOES_NOT_EXIST")
    mode = 0 # Do nothing mode
    entry = await db.fetchrow("SELECT profile_topic.done, profile.badges, profile.items FROM profile_topic RIGHT JOIN profile ON profile_topic.username=profile.username WHERE profile_topic.tid = $1 AND profile.username = $2", tracker.tid, tracker.username)
    if entry is None:
        mode = 1 # Don't update, use insert statement mode
    elif entry["done"] is not True:
        mode = 2 # Update mode
    if mode == 1:
        await db.execute("INSERT INTO profile_topic (username, tid, progress, done) VALUES ($1, $2, $3, $4)", tracker.username, tracker.tid, tracker.status + str(tracker.cid), False)
        entry = await db.fetchrow("SELECT profile_topic.done, profile.badges, profile.items FROM profile_topic RIGHT JOIN profile ON profile_topic.username=profile.username WHERE profile_topic.tid = $1 AND profile.username = $2", tracker.tid, tracker.username)
    elif mode == 2:
        await db.execute("UPDATE profile_topic SET progress = $3 WHERE username = $1 AND tid = $2", tracker.username, tracker.tid, tracker.status + str(tracker.cid))
    elif mode == 0:
        return brsret(code = None, debug = mode)

    item_list = []
    for item in entry["items"].split("||"):
        if item.split(":")[0] != "experience":
            item_list.append(item)
            continue
        exp_points = str(int(item.split(":")[1]) + 10) # 10 new experience points per page
        item_list.append("experience:" + exp_points)
        break
    items = "||".join(item_list)
    exp_points = int(exp_points)
    # Get all the new badges a user has unlocked
    new_badges = get_new_badges(entry["badges"], exp_points)
    if new_badges[0] == '':
        await db.execute("UPDATE profile SET items = $2 WHERE username = $1", tracker.username, items)
        return brsret(code = None, debug = mode)
    await db.execute("UPDATE profile SET badges = $2, items = $3 WHERE username = $1", tracker.username, new_badges[1], items)
    return brsret(code = None, debug = mode, items = items, new_badges = new_badges[0])


@app.get("/profile/track", tags = ["Profile"])
async def profile_track_reader(tid: str, username: str):
    info = await db.fetchrow("SELECT progress, done FROM profile_topic WHERE username = $1 AND tid = $2", username, tid) # Get the page info
    if info is None or info["progress"] is None:
        return brsret(
            status = "LP", # Default State is LP
            cid = 1,
            done = False,
        )
    status = info["progress"][0] + info["progress"][1]
    cid = info["progress"][2:]
    done = info["done"]
    if done is not True:
        done = False
    else:
        done = True
    return brsret(
        status = status,
        cid = cid,
        done = done,
    )
    return brsret(code = "INVALID_ARGUMENTS")  # Invalid arguments (Default)

@app.post("/profile/track/practice", tags = ["Profile"])
async def profile_track_writer(tracker: ProfileTrackPracticeWriter):
    profile_db = await db.fetchrow("SELECT mfa FROM login WHERE username = $1 AND token = $2", tracker.username, tracker.token)
    if profile_db is None:
        return brsret(code = "USER_DOES_NOT_EXIST")
    mode = 0 # Do nothing mode
    entry = await db.fetchrow("SELECT profile_topic.done, profile.badges, profile.items FROM profile_topic RIGHT JOIN profile ON profile_topic.username=profile.username INNER JOIN topic_practice_tracker ON profile.username=topic_practice_tracker.username WHERE topic_practice_tracker.tid = $1 AND topic_practice_tracker.username = $2 AND topic_practice_tracker.qid = $3", tracker.tid, tracker.username, tracker.qid)
    if entry is None:
        mode = 1 # Don't update, use insert statement mode
    elif entry["done"] is not True:
        mode = 2 # Update mode
    if mode == 1:
        await db.execute("INSERT INTO topic_practice_tracker (username, tid, qid, answer, lives, path) VALUES ($1, $2, $3, $4, $5, $6)", tracker.username, tracker.tid, tracker.qid, tracker.answer, tracker.lives, tracker.path)
        entry = await db.fetchrow("SELECT profile_topic.done, profile.badges, profile.items FROM profile_topic RIGHT JOIN profile ON profile_topic.username=profile.username INNER JOIN topic_practice_tracker ON profile.username=topic_practice_tracker.username WHERE topic_practice_tracker.tid = $1 AND topic_practice_tracker.username = $2 AND topic_practice_tracker.qid = $3", tracker.tid, tracker.username, tracker.qid)
    elif mode == 2:
        await db.execute("UPDATE topic_practice_tracker SET answer = $4, lives = $5, path = $6 WHERE username = $1 AND tid = $2 AND qid = $3", tracker.username, tracker.tid, tracker.qid, tracker.answer, tracker.lives, tracker.path)
    elif mode == 0:
        return brsret(code = None, debug = mode)

    item_list = []
    for item in entry["items"].split("||"):
        if item.split(":")[0] != "experience":
            item_list.append(item)
            continue
        exp_points = str(int(item.split(":")[1]) + 10) # 10 new experience points per page
        item_list.append("experience:" + exp_points)
        break
    items = "||".join(item_list)
    exp_points = int(exp_points)
    # Get all the new badges a user has unlocked
    new_badges = get_new_badges(entry["badges"], exp_points)
    if new_badges[0] == '':
        await db.execute("UPDATE profile SET items = $2 WHERE username = $1", tracker.username, items)
        return brsret(code = None, debug = mode)
    await db.execute("UPDATE profile SET badges = $2, items = $3 WHERE username = $1", tracker.username, new_badges[1], items)
    return brsret(code = None, debug = mode, items = items, new_badges = new_badges[0])


# New Stuff!!!

@app.post("/experiment/new", tags = ["Experiments"])
async def new_experiment(experiment: GenericExperimentNew, bt: BackgroundTasks):
    return await catphi.new(type="experiment", bt = bt, username = experiment.username, token = experiment.token, description = experiment.description, exp_type = experiment.exp_type)

@app.post("/topics/new", tags = ["Topics"])
async def new_topic(topic: TopicNew, bt: BackgroundTasks):
    return await catphi.new(type="topic", bt = bt, username = topic.username, token = topic.token, name = topic.name, description = topic.description, metaid = topic.metaid)

@app.post("/subjects/new", tags = ["Subjects"])
async def new_subject(subject: SubjectNew, bt: BackgroundTasks):
    return await catphi.new(type="subject", bt = bt, username = subject.username, token = subject.token, name = subject.name, description = subject.description)

@app.post("/topics/concepts/new", tags = ["Concepts"])
async def new_concept(concept: ConceptNew, bt: BackgroundTasks):
    return await catphi.new(type="concept", bt = bt, username = concept.username, token = concept.token, tid = concept.tid, concept_title = concept.title)

@app.post("/topics/practice/new", tags = ["Topics", "Topic Practice"])
async def new_topic_practice(topic_practice: TopicPracticeNew, bt: BackgroundTasks): 
    return await catphi.new(type="topic_practice", bt = bt, username = topic_practice.username, token = topic_practice.token, question_type = topic_practice.type, tid = topic_practice.tid, question = topic_practice.question, correct_answer = topic_practice.correct_answer, answers = topic_practice.answers, solution = topic_practice.solution)

# List Functions

@app.get("/topics/concepts/list", tags = ["Concepts"])
async def list_concepts(tid: str):
    concepts = await db.fetch("SELECT title FROM concept_table WHERE tid = $1 ORDER BY title ASC", tid)
    if len(concepts) == 0:
        # 0002 = No Experiments Found
        return {"error": "0002"}
    cjson = {}
    i = 1
    for concept in concepts:
        cjson[concept['title']] = i
        i+=1
    return cjson

@app.get("/topics/list", tags = ["Topics"])
async def list_topics():
    topics = await db.fetch("SELECT name, tid FROM topic_table")
    tjson = {}
    for topic in topics:
        tjson[topic["name"]] = topic["tid"]
    return tjson

@app.get("/subjects/list", tags = ["Subjects"])
async def list_subjects():
    subjects = await db.fetch("SELECT name, metaid FROM subject_table")
    sjson = {}
    for subject in subjects:
        sjson[subject["name"]] = subject["metaid"]
    return sjson

# List All Route (Called /bristlefrost/rootspring/shadowsight
@app.get("/bristlefrost/rootspring/shadowsight", tags = ["Clan Cat"])
async def bristlefrost_x_rootspring_x_shadowsight():
    # Get all topics
    topics = await db.fetch("SELECT subject_table.metaid, topic_table.tid, topic_table.name AS topic_name, concept_table.cid, concept_table.title AS concept_name from concept_table INNER JOIN topic_table ON topic_table.tid = concept_table.tid INNER JOIN subject_table ON topic_table.metaid = subject_table.metaid ORDER BY tid, cid ASC")
    return topics

# Get Functions

@app.get("/topics/get", tags = ["Topics", "Topic Experiments"])
async def get_topic(tid: str, simple: Optional[int] = 0):
    """NOTE: Simple determines whether to just fetch the name or to fetch both the name and the description"""
    if simple == 0:
        topic = await db.fetchrow("SELECT name, description FROM topic_table WHERE tid = $1", tid)
    else:
        topic = await db.fetchrow("SELECT name FROM topic_table WHERE tid = $1", tid)
    if topic is None:
        return brsret(code = "TOPIC_DOES_NOT_EXIST", html = "This topic does not exist yet")
    if simple == 0:
        if topic["description"] in ["", None]:
            topic_desc = "<script>alert('This topic has not yet been configured yet!');</script>"
        else:
            topic_desc = topic["description"]
        return brsret(code = None, name = topic["name"], description = topic_desc)
    else:
        return brsret(code = None, name = topic["name"])

@app.get("/topics/concepts/get/count", tags = ["Topics", "Concepts"])
async def get_concept_count(tid: str):
    concept_count = await db.fetch("SELECT COUNT(cid) FROM concept_table WHERE tid = $1", tid)
    return {"concept_count": concept_count[0]["count"]}

@app.get("/topics/concepts/get", tags = ["Topics", "Concepts"])
async def get_concept(tid: str, cid: int):
    concept = await db.fetch("SELECT title, content FROM concept_table WHERE tid = $1 ORDER BY cid ASC", tid)
    if len(concept) == 0 or len(concept) < int(cid) or int(cid) <= 0:
        return {"error": "0002"} # Invalid Parameters
    return {"title": concept[int(cid) - 1]["title"], "content": concept[int(cid) - 1]["content"]}

@app.get("/topics/practice/get/count", tags = ["Topics", "Topic Practice"])
async def get_topic_practice_count(tid: str):
    topic_practice = await db.fetch("SELECT COUNT(1) FROM topic_practice WHERE tid = $1", tid)
    return {"practice_count": topic_practice[0]["count"]}

@app.get("/topics/practice/get", tags = ["Topics", "Topic Practice"])
async def get_concept_practice(tid: str, qid: int):
    question = await db.fetch("""
        SELECT type, question, correct_answer, 
        answers, solution, recommended_time 
        FROM topic_practice 
        WHERE tid = $1 AND qid = $2 
        ORDER BY qid ASC""", 
        tid, 
        qid
    )
    if len(question) == 0 or int(qid) <= 0:
        return {"error": "0002"}
    question = question[0] # Get the absolute practice question ID
    if question["solution"] is None or len(question["solution"]) < 3:
        solution = "There is no solution for this problem yet!"
    else:
        solution = question["solution"]
    return {
        "type": question["type"],
        "question": question["question"],
        "correct_answer": question["correct_answer"],
        "answers": question["answers"],
        "solution": solution,
        "recommended_time": question["recommended_time"],
    }
