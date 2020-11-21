from fastapi import FastAPI
import asyncio
import secrets
import string
from hashlib import sha512
import smtplib
import time
import asyncpg
import ssl
from pydantic import BaseModel, ValidationError, validator
from typing import Optional

SERVER_URL = "https://127.0.0.1:443"  # Main Server URL
HASH_SALT = "66801b86-06ff-49c7-a163-eeda39b8cba9_66bc6c6c-24e3-11eb-adc1-0242ac120002_66bc6c6c-24e3-11eb-adc1-0242ac120002"
EXP_RATE = 11 # This is the rate at which users will get experience per concept (11 exp points per completed concept)


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
    # Represents a simulation on the database.
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS experiment_table (subject TEXT, topic TEXT, owner TEXT, code TEXT, cid TEXT, name TEXT)"
    )
    # Create an index for the experiments
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS experiment_index ON experiment_table (owner, code, cid, subject, topic)"
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
        "CREATE TABLE IF NOT EXISTS login (token TEXT, username TEXT, password TEXT, email TEXT, status INTEGER)"
    )
    # Create an index for login
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS login_index ON login (token, username, password, email, status)"
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
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS profile_concept_index ON profile_concept (username, cid, done)"
    )
    # All General Purpose Simulations for a concept (these are not linked to the concept itself)
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS simulation_table (sid TEXT, description TEXT, code TEXT)"
    )
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS simulation_table_index ON simulation_table (sid, description, code)"
    )

    return __db

# resetDict is a dictionary of password reset requests
# currently present
resetDict = {}
eresetDict = {}
loginDict = {}

SENDER_EMAIL = "sandhoners123@gmail.com"
SENDER_PASS = "Ravenpaw11,"

adminDict = {
    "sandstar": "PnJuetyqNsXeAoLcCphqpnOGtOLvsrpsXTUcDAOZWIGMXUNXXatSzflBLkKRvrZuxlBYyaikpFwqkkoVyVuqGKUuvOBApycbpstfx",  # Sandstar
}

app = FastAPI(port=3000)


# Basic Models


class Save(BaseModel):
    username: str
    token: str
    sid: Optional[str] = None # Simulations
    cid: Optional[str] = None # Concept Simulations
    page_number: Optional[int] = None # Pages
    code: str # Code

    async def save_experiment(self, type):
        if type not in ["concept", "generic", "concept_page"]:
            return {"error": "0001"} # Invalid Arguments
        elif type == "generic" and self.sid == None:
            return {"error": "0001"}  # Invalid Arguments
        elif type in ["concept", "concept_page"] and self.cid == None:
            return {"error": "0001"}  # Invalid Arguments
        username = self.username
        # Check if the username is even registered with us and if the username
        # given in data.keys() is correct
        login_cred = await db.fetchrow(
            "SELECT username FROM login WHERE token = $1", self.token
        )
        if login_cred == None:
            return {"error": "Not Authorized"}  # Not Authorized
        elif login_cred["username"] != username:
            return {"error": "Not Authorized"}  # Not Authorized
        elif self.token not in adminDict.values() or username not in loginDict.keys():
            return {"error": "Not Authorized"}  # Not Authorized
        if type == "generic":
            await db.execute(
                "UPDATE simulation_table SET code = $1 WHERE sid = $2",
                self.code,
                self.sid,
            )
        elif type == "concept":
            await db.execute(
                "UPDATE experiment_table SET code = $1 WHERE cid = $2",
                self.code,
                self.cid,
            )
        elif type == "concept_page":
            # Firstly, make sure the concept actually exists in
            # experiment_table
            tcheck = await db.fetchrow(
                "SELECT subject FROM experiment_table WHERE cid = $1", self.cid
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

        return {"error": "Successfully saved experiment/page!"}

# Auth Models

class AuthResetRequest(BaseModel):
    email: str

class AuthResetChange(BaseModel):
    token: str
    new_password: str

class AuthLoginRequest(BaseModel):
    username: str
    password: str

class AuthLogoutRequest(BaseModel):
    username: str

class AuthRegisterRequest(BaseModel):
    email: str
    username: str
    password: str

# Profile Models

class ProfileVisibleRequest(BaseModel):
    state: str
    username: str
    token: str
    disable_state: Optional[int] = None

class ProfileTrackWriter(BaseModel):
    cid: str
    username: str
    status: str    
    page: Optional[str] = None

# *New Methods

class GenericExperimentNew(BaseModel):
    username: str
    token: str
    description: str

class ConceptNew(BaseModel):
    username: str
    token: str
    topic: str
    concept: str

class PageNew(BaseModel):
    username: str
    token: str
    cid: str
    title: str

class TopicNew(BaseModel):
    username: str
    token: str
    topic: str

# Basic Classes
class catphi():
    @staticmethod
    async def new(*, type, username, token, description = None, topic = None, concept = None, id = None, page_title = None):
        # Check if the username is even registered with us and if the username
        # given in data.keys() is correct
        login_cred = await db.fetchrow(
            "SELECT username FROM login WHERE token = $1", token
        )
        if login_cred is None:
            return {"error": "Not Authorized"}  # Not Authorized
        elif login_cred["username"] != username:
            return {"error": "Not Authorized"}  # Not Authorized
        elif token not in adminDict.values():
            return {"error": "Not Authorized"}  # Not Authorized
    
        if type == "experiment":
            table = "simulation_table"
            id_table = "sid"
        elif type == "concept":
            table = "experiment_table"
            id_table = "cid"
        elif type == "page":
            tcheck = await db.fetchrow(
                "SELECT subject FROM experiment_table WHERE cid = $1", id
            )
            if tcheck is None:
                # Concept Does Not Exist
                return {"error": "Concept Does Not Exist"}
            await db.execute(
                "INSERT INTO concept_page_table (cid, title, content) VALUES ($1, $2, $3)",
                id,
                page_title,
                f"Type your content for page {page_title} here!",
            )
            page_count = await db.fetch(
                "SELECT COUNT(page_number) FROM concept_page_table WHERE cid = $1", id
            )
            return {"error": "1000", "page_count": page_count[0]["count"]}
        elif type == "topic":
            tcheck = await db.fetchrow(
                "SELECT subject FROM experiment_table WHERE topic = $1", topic
            )
            if tcheck is not None:
                return {"error": "Topic Already Exists"}
            id = "default"
            name = "default"
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
                "INSERT INTO simulation_table (sid, description, code) VALUES ($1, $2, $3)",
                id,
                description,
                "arrow();",
            )
        elif type == "concept":
            await db.execute(
                "INSERT INTO experiment_table (subject, topic, cid, name) VALUES ($1, $2, $3, $4)",
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

@app.get("/")
async def root():
    return {"message": "Hello World"}

# Experiments

@app.get("/experiment/get")
async def get_experiment(sid: str = None):
    if sid == None:
        return {"error": "0001"}  # Invalid Arguments
    experiment = await db.fetch(
        "SELECT description, code FROM simulation_table WHERE sid = $1",
        sid,
    )
    if len(experiment) == 0:
        return {"error": "1001"}  # Not Authorized
    return {"sid": sid, "description": experiment[0]["description"], "code": experiment[0]["code"]}

# Saving

@app.post("/experiment/save")
async def save_experiment(save: Save):
    return await save.save_experiment("generic")


@app.post("/concept/experiment/save")
async def concept_experiment_save(save: Save):
    return await save.save_experiment("concept")

@app.post("/concepts/page/save")
async def save_concept(save: Save):
    return await save.save_experiment("concept_page")

# Authentication Code

# Send a reset email (stage2 auth)
@app.post("/auth/reset/send")
async def reset_passwd_send(reset: AuthResetRequest):
    email = sha512(reset.email.encode()).hexdigest()
    login_cred = await db.fetchrow(
        "SELECT token, username from login WHERE email = $1", email
    )
    if login_cred is None:
        # Invalid Username Or Password
        return {"error": "1001"}
    url_flag = True  # Flag to check if we have a good url id yet
    while url_flag:
        atok = get_token(101)
        if atok not in resetDict.values():
            url_flag = False
    resetDict[login_cred["token"]] = atok
    eresetDict[atok] = reset.email
    # Now send an email to the user
    reset_link = SERVER_URL + "/reset/stage2?token=" + atok
    reset_message = f"Subject: CCTP Password Reset\n\nUsername {login_cred['username']}\nPlease use {reset_link} to reset your password.\n\nIf you didn't authorize this action, please change your password immediately"
    email_session = smtplib.SMTP("smtp.gmail.com", 587)
    email_session.starttls()  # TLS for security
    email_session.login(SENDER_EMAIL, SENDER_PASS)  # Email Auth
    email_session.sendmail(SENDER_EMAIL, reset.email, reset_message)
    email_session.close()
    return {"error": "1000"}  # Success


# Change the actual password (stage3 auth)
@app.post("/auth/reset/change")
async def reset_passwd_change(reset: AuthResetChange):
    if reset.token not in resetDict.values():
        # Reset Token Not Authorized
        return {"error": "1001"}
    # Change the password of the field related to that users
    # account
    token = None
    for item in resetDict.items():
        if item[1] == reset.token:
            token = item[0]
            email = eresetDict.get(token)
            break
    login_cred = await db.fetchrow("SELECT username, status FROM login WHERE token = $1", token)
    if login_cred is None:
        return {"error": "1001"}
    if int(login_cred["status"]) == 2:
        return {"error": "1101"}
    username = login_cred["username"]
    password = sha512(
        ("Shadowsight1" + HASH_SALT + username + reset.new_password).encode()
    ).hexdigest()  # New password
    # Make sure we cant use the same token again
    resetDict[token] = None
    await db.execute("UPDATE login SET password = $1 WHERE token = $2", password, token)
    await db.execute("UPDATE login SET status = 0 WHERE token = $1", token)
    reset_message = "Subject: Your CCTP Password Was Just Reset\n\nYour CatPhi password was just reset\n\nIf you didn't authorize this action, please change your password immediately"
    email_session = smtplib.SMTP("smtp.gmail.com", 587)
    email_session.starttls()  # TLS for security
    email_session.login(SENDER_EMAIL, SENDER_PASS)  # Email Auth
    email_session.sendmail(SENDER_EMAIL, email, reset_message)
    email_session.close()
    return {"error": "1000"}  # Success


# This checks if the reset request is in resetDict and
# returns the result


@app.get("/auth/gset")
async def gset(token: str = None):
    if token is None or token not in resetDict.values():
        return {"status": "0"}
    else:
        return {"status": "1"}


@app.post("/auth/login")
async def login(login: AuthLoginRequest):
    if login.username is None or login.password is None:
        return {"error": "0001"}
    username = login.username
    password = sha512(
        ("Shadowsight1" + HASH_SALT + username + login.password).encode()
    ).hexdigest()
    login_creds = await db.fetchrow(
        "SELECT token, status from login WHERE username = $1 and password = $2",
        username,
        password,
    )
    if login_creds is None:
        # Invalid Username Or Password
        return {"error": "1001"}
    if login_creds["token"] in adminDict.values():
        is_admin = 1
    else:
        is_admin = 0
    if login_creds["status"] in [None, 0]:
        pass
    else:
        # This account is flagged as disabled (1) or disabled-by-admin (2)
        return {"error": "1002", "status": login_creds["status"]} # Flagged Account
    # Add you to the list of logged in users
    loginDict[username] = login_creds["token"]
    return {"error": "1000", "token": login_creds["token"], "admin": is_admin}


@app.post("/auth/logout")
async def logout(logout: AuthLogoutRequest):
    username = logout.username
    if username is None:
        return {"error": "0001"}
    try:
        # Removes you from the list of logged in users
        del loginDict[username]
    except KeyError:
        pass
    return {"error": "1000"}


@app.post("/auth/register")
async def register(register: AuthRegisterRequest):
    # For every password and email, encode it to bytes and
    # SHA512 to get hash
    username = register.username
    password = sha512(
        ("Shadowsight1" + HASH_SALT + username + register.password).encode()
    ).hexdigest()
    email = sha512(register.email.encode()).hexdigest()
    login_creds = await db.fetchrow(
        "SELECT token from login WHERE username = $1 OR email = $2", username, email
    )
    if login_creds is not None:
        # That username or email is in use
        return {"error": "1001"}
    flag = True
    while flag:
        # Keep getting and checking token with DB
        token = get_token(101)
        login_creds = await db.fetchrow(
            "SELECT username from login WHERE token = $1", token
        )
        if login_creds is not None:
            continue
        flag = False
    await db.execute(
        "INSERT INTO login (token, username, password, email, status) VALUES ($1, $2, $3, $4, 0);",
        token,
        username,
        password,
        email,
    )
    # Register their join date
    await db.execute(
        "INSERT INTO profile (username, join_epoch, public, exp_points) VALUES ($1, $2, $3, $4);",
        username,
        int(round(time.time())),
        True,
        0,
    )
    loginDict[username] = token
    # Login Was Successful!
    return {"error": "1000", "token": token}


# Profile
@app.post("/profile/visible")
async def change_visibility(pvr: ProfileVisibleRequest):
    # This includes account disabling which is also changing the visibility as well
    if pvr.state not in ["public", "private", "disable", "enable"]:
        return {"error": "1001"}
    usertok = await db.fetchrow("SELECT token FROM login WHERE username = $1", pvr.username)
    # Check if username and token match
    if usertok is not None and (usertok["token"] == pvr.token or pvr.token in adminDict.values()):
        pass
    else:
        return {"error": "1002"}

    # For account disabling, set state to private and flag account as disabled
    if pvr.state == "disable":
        if pvr.token in adminDict.values() and usertok["token"] in adminDict.values():
            # An admin cannot be disabled
            return {"error": "1002"}
        print("Disabling account")
        state = "private" # Make the profile private on disable
        if pvr.disable_state is not None and pvr.token in adminDict.values():
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
            "SELECT status FROM login WHERE username = $1", pvr.username
        )
        if status is None:
            return {"error": "1001"}

        status = status["status"]
        if int(status) == 2:
            if pvr.token in adminDict.values(): # Admin check
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


@app.get("/profile")
async def get_profile(username: str, token: str = None):
    # Get the profile
    profile_db = await db.fetchrow(
        "SELECT public, join_epoch, exp_points FROM profile WHERE username = $1",
        username,
    )
    usertok = await db.fetchrow("SELECT token FROM login WHERE username = $1", username)
    if profile_db is None:
        return {"error": "1001"}
    elif not profile_db["public"]:
        priv = 1
        if token is None:
            return {"error": "1002"}  # Private
        elif usertok["token"] == token or token in adminDict.values():
            pass
        else:
            return {"error": "1002"}  # Private
    else:
        priv = 0

    if usertok["token"] in adminDict.values():
        is_admin = 1
    else:
        is_admin = 0
    return {
            "username": username,
            "admin": is_admin,
            "join": profile_db["join_epoch"],
            "priv": priv,
            "experience": profile_db["exp_points"],
        }

# Track users progress
# TODO: Add quizzes and other things
@app.post("/profile/track")
async def profile_track_writer(tracker: ProfileTrackWriter):
    if tracker.status == "LP": # Learn Page Change
        mode = 0 # Do nothing mode
        if tracker.page is None:
            return {"error": "0001"}  # Invalid arguments
        entry = await db.fetchrow("SELECT done FROM profile_concept WHERE cid = $1 AND username = $2", tracker.cid, tracker.username)
        if entry is None:
            mode = 1 # Don't update, use insert statement mode
        elif entry["done"] is not True:
            mode = 2 # Update mode
        if mode == 0:
            return {"error": "1000", "debug": mode}
        elif mode == 1:
            await db.execute("INSERT INTO profile_concept (username, cid, progress, done) VALUES ($1, $2, $3, $4)", tracker.username, tracker.cid, "LP" + tracker.page, False)
            return {"error": "1000", "debug": mode}
        elif mode == 2:
            await db.execute("UPDATE profile_concept SET progress = $3 WHERE username = $1 AND cid = $2", tracker.username, tracker.cid, "LP" + tracker.page)
            return {"error": "1000", "debug": mode}
    return {"error": "0001"}  # Invalid arguments (Default)

@app.get("/profile/track")
async def profile_track_reader(cid: str, username: str, status: str):
    if username not in loginDict.keys():
        print(username + " is not logged in")
        return {"error": "0002", "auth": 0}
    elif status == "LP": # Learn Page Status/Target
        info = await db.fetchrow("SELECT progress, done FROM profile_concept WHERE username = $1 AND cid = $2", username, cid) # Get the page info
        if info is None:
            return {
                    "page": '1',
                    "done": '0',
                }

        page = info["progress"].split("LP")[1] # Get the page number from LPXYZ string
        done = info["done"]
        if done is not True:
            done = '0'
        else:
            done = '1'
        return {
                "page": page,
                "done": done,
            }
    return {"error": "0001"}  # Invalid arguments (Default)

# New Stuff!!!

@app.post("/experiment/new")
async def new_experiment(experiment: GenericExperimentNew):
    return await catphi.new(type="experiment", username = experiment.username, token = experiment.token, description = experiment.description)

@app.post("/concepts/new")
async def new_concept(concept: ConceptNew):
    return await catphi.new(type="concept", username = concept.username, token = concept.token, topic = concept.topic, concept = concept.concept)

@app.post("/concepts/page/new")
async def new_concept_page(page: PageNew):
    return await catphi.new(type="page", username = page.username, token = page.token, id = page.cid, page_title = page.title)

@app.post("/topics/new")
async def new_topic(topic: TopicNew):
    return await catphi.new(type="topic", username = topic.username, token = topic.token, topic = topic.topic)

# List Functions

@app.get("/concepts/list")
async def list_concepts(topic: str = None):
    if topic is not None:
        # We want to get all experiments/concepts with a
        # specific topic
        experiments = await db.fetch(
            "SELECT DISTINCT cid, name, topic FROM experiment_table WHERE topic = $1 ORDER BY name DESC",
            topic,
        )
    else:
        # 0003 = No Experiments Found. You must provide a topic in order to use
        # this
        return {"error": "0003"}
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

@app.get("/topics/list")
async def list_topics():
    topics = await db.fetch("SELECT DISTINCT topic FROM experiment_table")
    tjson = {}
    i = 1
    for topic in topics:
        tjson[str(i)] = topic["topic"]
        i += 1
    tjson["total"] = len(topics)
    return tjson

# Get Functions

@app.get("/concepts/get/experiment")
async def get_concept_experiment(id: str = None, username: str = None):
    if id is None or username is None or username not in loginDict.keys(): # Only logged in users can see all experiments
        # 0002 = No Experiments Found Or Not Authorized
        print(username, loginDict)
        if username not in loginDict.keys() or username is None:
            authed = 0
        else:
            authed = 1
        return {"error": "0002", "auth": authed}
    experiments = await db.fetchrow(
        "SELECT name, code FROM experiment_table WHERE cid = $1", id
    )
    if experiments is None:
        # 0002 = No Experiments Found
        return {"error": "0002"}
    elif experiments["code"] in ["", None]:
        code = "alert('This concept has not yet been configured yet!')"
    else:
        code = experiments["code"]
    experiments = {"name": experiments["name"], "code": code}
    return experiments

# This isnt important enough for a password (and might actually be better without one)
@app.get("/concepts/get/page/count")
async def get_concept_page_count(id: str = None):
    if id is None:
        return {"error": "0002"}
    page_count = await db.fetch(
        "SELECT COUNT(page_number) FROM concept_page_table WHERE cid = $1", id
    )
    if len(page_count) == 0:
        page_count_json = {"page_count": 0}
    else:
        page_count_json = {"page_count": page_count[0]["count"]}
    return page_count_json

@app.get("/concepts/get/page")
async def get_concept_page(id: str = None, page_number: int = None, username: str = None):
    if id is None or page_number is None or username is None or username not in loginDict.keys(): # Only logged in users can see all experiments
        # 0002 = No Experiments Found Or Not Authorized
        print(username, loginDict)
        if username not in loginDict.keys() or username is None:
            authed = 0
        else:
            authed = 1
        return {"error": "0003", "auth": authed}
    page = await db.fetch(
        "SELECT title, content FROM concept_page_table WHERE cid = $1 ORDER BY page_number ASC",
        id,
    )
    if len(page) == 0 or len(page) < int(page_number) or int(page_number) <= 0:
        return {"error": "0002"} # Invalid Parameters
    page_count_json = {"title": page[int(page_number) - 1]["title"], "content": page[int(page_number) - 1]["content"]}
    return page_count_json

