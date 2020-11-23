from fastapi import FastAPI, Depends
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

SERVER_URL = "https://127.0.0.1:443"  # Main Server URL
HASH_SALT = "66801b86-06ff-49c7-a163-eeda39b8cba9_66bc6c6c-24e3-11eb-adc1-0242ac120002_66bc6c6c-24e3-11eb-adc1-0242ac120002"
EXP_RATE = 11 # This is the rate at which users will get experience per concept (11 exp points per completed concept)
pwd_context = CryptContext(schemes=["pbkdf2_sha512"], deprecated="auto")

def get_token(length):
    secure_str = "".join(
        (secrets.choice(string.ascii_letters + string.digits) for i in range(length))
    )
    return secure_str

async def setup_db():
    print("Setting up DB")
    __db = await asyncpg.create_pool(
        host="127.0.0.1", user="catphi", password="Rootspring11,", database="catphi"
    )  # Login stuff
    # Always do this to ensure best performance
    await __db.execute("VACUUM")
    # Represents a concept on the database.
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS concept_table (subject TEXT, topic TEXT, owner TEXT, concept_experiment TEXT, cid TEXT, name TEXT)"
    )
    # Create an index for the experiments
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS concept_index ON concept_table (owner, concept_experiment, cid, subject, topic)"
    )
    # Represents a page on the database
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS concept_page_table (page_number SERIAL NOT NULL, cid TEXT, title TEXT, content TEXT)"
    )
    # Create an index for the experiments
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS concept_page_index ON concept_page_table (cid, title, content)"
    )
    # Represents a single login in the database
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS login (token TEXT, username TEXT, password TEXT, email TEXT, status INTEGER, scopes TEXT)"
    )
    # Create an index for login
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS login_index ON login (token, username, password, email, status, scopes)"
    )
    # A profile of a user
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS profile (username TEXT, join_epoch BIGINT, public BOOLEAN, exp_points BIGINT, badges TEXT)"
    )
    # Create an index for the three things that will never/rarely change,
    # namely join date , username and public/private profile
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS profile_index ON profile (username, join_epoch, public)"
    )
    # All the concepts a user has completed or is working on
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS profile_concept (username TEXT, cid TEXT, progress TEXT, done BOOLEAN)"
    )
    # Profile Concept Index
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS profile_concept_index ON profile_concept (username, cid, done)"
    )
    # All General Purpose Simulations for a concept (these are not linked to the concept itself)
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS experiment_table (sid TEXT, description TEXT, code TEXT)"
    )
    # Generic Simulations (Experiments) Index
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS experiment_index ON experiment_table (sid, description, code)"
    )
    # Concept Practice
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS concept_practice_table (cid TEXT, qid SERIAL NOT NULL, type TEXT, question TEXT, answer TEXT, recommended_time INTEGER)"
    )
    # Concept Practice Index
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS concept_practice_index ON concept_practice_table (cid, qid, type, question, answer, recommended_time)"
    )

    return __db

# resetDict is a dictionary of password reset requests
# currently present
resetDict = {}
eresetDict = {}

SENDER_EMAIL = "sandhoners123@gmail.com"
SENDER_PASS = "Ravenpaw11,"

class Settings(BaseSettings):
    openapi_url: str = "/rootspring/openapi.json"

settings = Settings()


app = FastAPI(openapi_url=settings.openapi_url)

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

class UserModel(BaseModel):
    username: str
    token: str

class UserPassModel(BaseModel):
    username: str
    password: str

class Save(UserModel):
    async def save_experiment(self, type):
        if type not in ["concept", "generic", "concept_page", "concept_practice"]:
            return {"error": "Invalid Arguments"} # Invalid Arguments

        auth_check = await authorize_user(self.username, self.token)
        if auth_check:
            return {"error": "Not Authorized"}
        if type == "generic":
            await db.execute(
                "UPDATE experiment_table SET code = $1 WHERE sid = $2",
                self.code,
                self.sid,
            )
        elif type == "concept":
            await db.execute(
                "UPDATE concept_table SET concept_experiment = $1 WHERE cid = $2",
                self.code,
                self.cid,
            )
        elif type == "concept_page":
            # Firstly, make sure the concept actually exists in
            # concept_table
            tcheck = await db.fetchrow(
                "SELECT subject FROM concept_table WHERE cid = $1", self.cid
            )
            if tcheck is None:
                # Concept Does Not Exist
                return {"error": "Concept Does Not Exist"}
            page_count = await db.fetch(
                "SELECT COUNT(page_number) FROM concept_page_table WHERE cid = $1", self.cid
            )
            if int(page_count[0]["count"]) < int(self.page_number):
                return {"error": "0002"}  # Invalid Arguments
            pages = await db.fetch("SELECT page_number FROM concept_page_table WHERE cid = $1 ORDER BY page_number ASC", self.cid)  # Get all the page numbers in ascending order
            page_number = pages[int(self.page_number) - 1]["page_number"] # Calculate the absolute page number
            await db.execute(
                "UPDATE concept_page_table SET content = $1 WHERE cid = $2 AND page_number = $3",
                self.code,
                self.cid,
                int(page_number),
            )
        elif type == "concept_practice":
            await db.execute(
                "UPDATE concept_practice_table SET question = $1, answer = $2  WHERE cid = $3",
                self.question,
                self.answer,
                self.cid,
            )
        return {"error": "Successfully saved entity!"}

class SaveConceptExperiment(Save):
    cid: str
    code: str

class SaveConceptPage(Save):
    cid: str
    page_number: int
    code: str

class SaveConceptPractice(Save):
    type: str
    cid: str
    question: str
    answer: str

class SaveExperiment(Save):
    sid: str
    code: str

# Auth Models

class AuthResetRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None

class AuthResetChange(BaseModel):
    token: str
    new_password: str

class AuthLoginRegister(UserPassModel):
    pass

class AuthLoginRequest(AuthLoginRegister):
    pass

class AuthLogoutRequest(BaseModel):
    username: str

class AuthRegisterRequest(AuthLoginRegister):
    email: str

# Profile Models

class ProfileVisibleRequest(UserModel):
    state: str
    disable_state: Optional[int] = None

class ProfileTrackWriter(BaseModel):
    cid: str
    username: str
    status: str    
    page: str

# **New Methods

class GenericExperimentNew(UserModel):
    description: str

class ConceptNew(UserModel):
    topic: str
    concept: str

class PageNew(UserModel):
    cid: str
    title: str

class TopicNew(UserModel):
    topic: str

class ConceptPracticeNew(UserModel):
    type: str
    question: str
    answer: str
    cid: str


# Basic Classes
class catphi():
    @staticmethod
    async def new(*, type, username, token, description = None, topic = None, concept = None, id = None, page_title = None, question = None, answer = None, question_type = None):
        auth_check = await authorize_user(self.username, self.token)
        if auth_check:
            return {"error": "Not Authorized"} 
        if type == "experiment":
            table = "experiment_table"
            id_table = "sid"
        elif type == "concept":
            table = "concept_table"
            id_table = "cid"
        elif type == "concept_practice":
            tcheck = await db.fetchrow("SELECT subject FROM concept_table WHERE cid = $1", id)
            if tcheck is None:
                # Concept Does Not Exist
                return {"error": "Concept Does Not Exist"}
            await db.execute(
                "INSERT INTO concept_practice_table (cid, type, question, answer, recommended_time) VALUES ($1, $2, $3, $4, $5)",
                id,
                question_type,
                question,
                answer,
                0,
            )
            return {"error": "1000"}


        elif type == "page":
            tcheck = await db.fetchrow("SELECT subject FROM concept_table WHERE cid = $1", id)
            if tcheck is None:
                # Concept Does Not Exist
                return {"error": "Concept Does Not Exist"}
            await db.execute(
                "INSERT INTO concept_page_table (cid, title, content) VALUES ($1, $2, $3)",
                id,
                page_title,
                f"Type your content for page {page_title} here!",
            )
            page_count = await db.fetch("SELECT COUNT(page_number) FROM concept_page_table WHERE cid = $1", id)
            return {"error": "1000", "page_count": page_count[0]["count"]}
        elif type == "topic":
            tcheck = await db.fetchrow("SELECT subject FROM concept_table WHERE topic = $1", topic)
            if tcheck is not None:
                return {"error": "Topic Already Exists"}
            id, name = "default", "default"
            type = "concept"
            id_table = "cid"

        while id != "default":
            id = get_token(101)
            id_check = await db.fetchrow(
                f"SELECT {id_table} FROM {table} WHERE {id_table} = $1", id
            )
            if id_check is None:
                break
        if type == "experiment":
            await db.execute(
                "INSERT INTO experiment_table (sid, description, code) VALUES ($1, $2, $3)",
                id,
                description,
                "arrow();",
            )
        elif type == "concept":
            await db.execute(
                "INSERT INTO concept_table (subject, topic, cid, name) VALUES ($1, $2, $3, $4)",
                "Physics",
                topic,
                id,
                concept,
            )
        return {"error": "1000", id_table: id}


@app.on_event("startup")
async def startup():
    global db
    db = await setup_db()


@app.on_event("shutdown")
async def shutdown():
    await db.close()

@app.get("/", tags=["Server Status", "R"])
async def root():
    return {"message": "Pong!"}

# Experiments

@app.get("/experiment/get", tags=["Experiments", "R"])
async def get_experiment(sid: str = None):
    if sid == None:
        return {"error": "0001"}  # Invalid Arguments
    experiment = await db.fetchrow("SELECT description, code FROM experiment_table WHERE sid = $1", sid)
    if experiment is None:
        return {"error": "1001"}  # Not Authorized
    return {"sid": sid, "description": experiment["description"], "code": experiment["code"]}

# Saving

@app.post("/experiment/save", tags=["Experiments", "W"])
async def save_experiment(save: SaveExperiment):
    return await save.save_experiment("generic")


@app.post("/concepts/experiment/save", tags=["Experiments", "Concepts", "Concept Experiments", "W"])
async def concept_experiment_save(save: SaveConceptExperiment):
    return await save.save_experiment("concept")

@app.post("/concepts/page/save", tags=["Concepts", "W"])
async def save_concept(save: SaveConceptPage):
    return await save.save_experiment("concept_page")

@app.post("/concepts/practice/save", tags = ["Concepts", "Concept Practice", "W"])
async def concept_practice_save(save: SaveConceptPractice):
    return await save.save_experiment("concept_practice")

# Authentication Code

# Send a reset email (stage2 auth)
@app.post("/auth/reset/send", tags = ["Authentication", "Password Reset", "RW"])
async def reset_password_send(reset: AuthResetRequest):
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
    email_session = smtplib.SMTP("smtp.gmail.com", 587)
    email_session.starttls()  # TLS for security
    email_session.login(SENDER_EMAIL, SENDER_PASS)  # Email Auth
    email_session.sendmail(SENDER_EMAIL, email, reset_message)
    email_session.close()
    return {"error": "1000"}  # Success


# Change the actual password (stage3 auth)
@app.post("/auth/reset/change", tags = ["Authentication", "Password Reset", "W"])
async def reset_password_change(reset: AuthResetChange):
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
    await db.execute("UPDATE login SET password = $1 WHERE token = $2", password, token)
    await db.execute("UPDATE login SET status = 0 WHERE token = $1", token)
    reset_message = "Subject: Your CCTP Password Was Just Reset\n\nYour CatPhi password was just reset\n\nIf you didn't authorize this action, please change your password immediately"
    email_session = smtplib.SMTP("smtp.gmail.com", 587)
    email_session.starttls()  # TLS for security
    email_session.login(SENDER_EMAIL, SENDER_PASS)  # Email Auth
    email_session.sendmail(SENDER_EMAIL, login_cred["email"], reset_message)
    email_session.close()
    return {"error": "1000"}  # Success


# This checks if the reset request is in resetDict and
# returns the result


@app.get("/auth/reset/check/token", tags = ["Authentication", "Password Reset", "R"])
async def check_reset_token(token: str = None):
    if token is None or token not in resetDict.values():
        return {"status": "0"}
    else:
        return {"status": "1"}


@app.post("/auth/login", tags = ["Authentication", "Login/Logout", "RW"])
async def login(login: AuthLoginRequest):
    if login.username is None or login.password is None:
        return {"error": "0001"}
    username = login.username
    pwd = await db.fetchrow(
        "SELECT password from login WHERE username = $1",
        username
    )
    if pwd is None:
        # Invalid Username Or Password
        return {"error": "1001"}

    elif pwd_context.verify("Shadowsight1" + HASH_SALT + username + login.password, pwd["password"]) == False:
        # Invalid Username Or Password
        return {"error": "1001"}

    login_creds = await db.fetchrow(
        "SELECT token, status, scopes from login WHERE username = $1",
        username,
    )
    if login_creds is None:
        # Invalid Username Or Password
        return {"error": "1001"}
    if login_creds["status"] in [None, 0]:
        pass
    else:
        # This account is flagged as disabled (1) or disabled-by-admin (2)
        return {"error": "1002", "status": login_creds["status"]} # Flagged Account
    # Add you to the list of logged in users
    return {"error": "1000", "token": login_creds["token"], "scopes": login_creds["scopes"]}


@app.post("/auth/register", tags = ["Authentication", "Registration", "RW"])
async def register(register: AuthRegisterRequest):
    # For every password and email, encode it to bytes and
    # SHA512 to get hash
    username = register.username
    password = pwd_context.hash("Shadowsight1" + HASH_SALT + username + register.password)
    email = register.email
    login_creds = await db.fetchrow(
        "SELECT token from login WHERE username = $1 OR email = $2", username, email
    )
    print(login_creds)
    if login_creds is not None:
        # That username or email is in use
        return {"error": "1001"}
    flag = True
    while flag:
        # Keep getting and checking token with DB
        token = get_token(1037)
        login_creds = await db.fetchrow(
            "SELECT username from login WHERE token = $1", token
        )
        if login_creds is not None:
            continue
        flag = False
    await db.execute(
        "INSERT INTO login (token, username, password, email, status, scopes) VALUES ($1, $2, $3, $4, 0, $5);",
        token,
        username,
        password,
        email,
        "user"
    )
    # Register their join date
    await db.execute(
        "INSERT INTO profile (username, join_epoch, public, exp_points) VALUES ($1, $2, $3, $4);",
        username,
        int(round(time.time())),
        True,
        0,
    )
    # Login Was Successful!
    return {"error": "1000", "token": token}


# Profile
@app.post("/profile/visible", tags=["Profile", "RW"])
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
        print("Disabling account")
        state = "private" # Make the profile private on disable
        if pvr.disable_state is not None and is_admin:
            status = int(pvr.disable_state) # Admin disable
        else:
            status = 1
        print(status)
        await db.execute(
            "UPDATE login SET status = $1 WHERE username = $2", status, pvr.username
        )

    # For account re-enabling, first make sure the state is not 2 (admin disable) unless the user doing this is an admin
    elif pvr.state == "enable":
        print("Verifying request")
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


@app.get("/profile", tags = ["Profile", "R"])
async def get_profile(username: str, token: str = None):
    # Get the profile
    profile_db = await db.fetchrow(
        "SELECT public, join_epoch, exp_points FROM profile WHERE username = $1",
        username,
    )
    profile_scopes = await db.fetchrow(
        "SELECT scopes FROM login WHERE username = $1",
        username,
    )
    if profile_db is None or profile_scopes is None:
        return {"error": "1001"}
    elif not profile_db["public"]:
        priv = 1
        if token is None:
            return {"error": "1002"}  # Private
        usertok = await db.fetchrow("SELECT username, scopes FROM login WHERE token = $1", token) # Get User Scopes
        if "admin" in usertok["scopes"].split(":") or usertok["username"] == username:
            pass
        else:
            return {"error": "1002"}  # Private
    else:
        priv = 0

    return {
            "username": username,
            "scopes": profile_scopes["scopes"],
            "join": profile_db["join_epoch"],
            "priv": priv,
            "experience": profile_db["exp_points"],
        }

# Track users progress
# TODO: Add quizzes and other things
@app.post("/profile/track", tags = ["Profile", "W"])
async def profile_track_writer(tracker: ProfileTrackWriter):
    mode = 0 # Do nothing mode
    entry = await db.fetchrow("SELECT done FROM profile_concept WHERE cid = $1 AND username = $2", tracker.cid, tracker.username)
    if entry is None:
        mode = 1 # Don't update, use insert statement mode
    elif entry["done"] is not True:
        mode = 2 # Update mode
    if mode == 1:
        await db.execute("INSERT INTO profile_concept (username, cid, progress, done) VALUES ($1, $2, $3, $4)", tracker.username, tracker.cid, tracker.status + tracker.page, False)
    elif mode == 2:
        await db.execute("UPDATE profile_concept SET progress = $3 WHERE username = $1 AND cid = $2", tracker.username, tracker.cid, tracker.status + tracker.page)
    return {"error": "1000", "debug": mode}

@app.get("/profile/track", tags = ["Profile", "R"])
async def profile_track_reader(cid: str, username: str):
    info = await db.fetchrow("SELECT progress, done FROM profile_concept WHERE username = $1 AND cid = $2", username, cid) # Get the page info
    if info is None:
        return {
            "status": "LP", # Default State is LP
            "page": '1',
            "done": '0',
        }
    status = info["progress"][0] + info["progress"][1] # Status is always first two characters (LP, PP)
    page = info["progress"][2:] # Get the page number from XY123 string by stripping first two characters from string
    done = info["done"]
    if done is not True:
        done = '0'
    else:
        done = '1'
    return {
        "status": status,
        "page": page,
        "done": done,
    }
    return {"error": "0001"}  # Invalid arguments (Default)

# New Stuff!!!

@app.post("/experiment/new", tags = ["Experiments", "RW"])
async def new_experiment(experiment: GenericExperimentNew):
    return await catphi.new(type="experiment", username = experiment.username, token = experiment.token, description = experiment.description)

@app.post("/concepts/new", tags = ["Concepts", "W"])
async def new_concept(concept: ConceptNew):
    return await catphi.new(type="concept", username = concept.username, token = concept.token, topic = concept.topic, concept = concept.concept)

@app.post("/concepts/page/new", tags = ["Concepts", "W"])
async def new_concept_page(page: PageNew):
    return await catphi.new(type="page", username = page.username, token = page.token, id = page.cid, page_title = page.title)

@app.post("/topics/new", tags = ["Topics", "W"])
async def new_topic(topic: TopicNew):
    return await catphi.new(type="topic", username = topic.username, token = topic.token, topic = topic.topic)

@app.post("/concepts/practice/new", tags = ["Concepts", "Concept Practice", "W"])
async def new_concept_practice(concept_practice: ConceptPracticeNew):
    return await catphi.new(type="concept_practice", username = concept_practice.username, token = concept_practice.token, question_type = concept_practice.type, id = concept_practice.cid, question = concept_practice.question, answer = concept_practice.answer)

# List Functions

@app.get("/concepts/list", tags = ["Concepts", "R"])
async def list_concepts(topic: str):
    experiments = await db.fetch("SELECT DISTINCT cid, name, topic FROM concept_table WHERE topic = $1 ORDER BY name DESC", topic)
    if len(experiments) == 0:
        # 0002 = No Experiments Found
        return {"error": "0002"}
    ejson = {}
    counters = {}
    for exp in experiments:
        # Add the experiment to the eJSON (experiment JSON)
        if ejson.get(exp["topic"]) is None:
            ejson[exp["topic"]] = {}  # Initial value
            ejson[exp["topic"]]["0"] = {"cid": exp["cid"], "name": exp["name"]}
            counters[exp["topic"]] = 1
        else:
            ejson[exp["topic"]][str(counters[exp["topic"]])] = {
                "cid": exp["cid"],
                "name": exp["name"],
            }
            counters[exp["topic"]] += 1
    return ejson

@app.get("/topics/list", tags = ["Topics", "R"])
async def list_topics():
    topics = await db.fetch("SELECT DISTINCT topic FROM concept_table")
    tjson = {}
    i = 1
    for topic in topics:
        tjson[str(i)] = topic["topic"]
        i += 1
    tjson["total"] = len(topics)
    return tjson

# Get Functions

@app.get("/concepts/get/experiment", tags = ["Concepts", "Concept Experiments", "R"])
async def get_concept_experiment(id: str, username: str):
    concept = await db.fetchrow("SELECT name, concept_experiment FROM concept_table WHERE cid = $1", id)
    if concept is None:
        return {"error": "0002"}
    elif concept["concept_experiment"] in ["", None]:
        code = "alert('This concept has not yet been configured yet!')"
    else:
        code = concept["concept_experiment"]
    return {"name": concept["name"], "code": code}

@app.get("/concepts/get/page/count", tags = ["Concepts", "R"])
async def get_concept_page_count(id: str):
    page_count = await db.fetch("SELECT COUNT(page_number) FROM concept_page_table WHERE cid = $1", id)
    return {"page_count": page_count[0]["count"]}

@app.get("/concepts/get/page", tags = ["Concepts", "R"])
async def get_concept_page(id: str, page_number: int):
    page = await db.fetch("SELECT title, content FROM concept_page_table WHERE cid = $1 ORDER BY page_number ASC", id)
    if len(page) == 0 or len(page) < int(page_number) or int(page_number) <= 0:
        return {"error": "0002"} # Invalid Parameters
    return {"title": page[int(page_number) - 1]["title"], "content": page[int(page_number) - 1]["content"]}

@app.get("/concepts/get/practice/count", tags = ["Concepts", "Concept Practice", "R"])
async def get_concept_practice_count(id: str):
    concept_practice = await db.fetch("SELECT COUNT(1) FROM concept_practice_table WHERE cid = $1", id)
    return {"practice_count": concept_practice[0]["count"]}

@app.get("/concepts/get/practice", tags = ["Concepts", "Concept Practice", "R"])
async def get_concept_practice(id: str, question_number: int):
    question = await db.fetchrow("SELECT type, question, answer, recommended_time FROM concept_practice_table WHERE cid = $1 AND qid = $2", id, question_number)
    if question is None:
        return {"error": "0002"}
    return {
        "type": question["type"],
        "question": question["question"],
        "answer": question["answer"],
        "recommended_time": question["recommended_time"],
    }
