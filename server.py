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
import json

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
        "CREATE TABLE IF NOT EXISTS topic_table (metaid TEXT, name TEXT, description TEXT, topic_experiment TEXT, tid TEXT)"
    )
    # Create an index for the topics
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS topic_index ON topic_table (metaid, name, description, topic_experiment, tid)"
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
    # All the topics a user has completed or is working on
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS profile_topic (username TEXT, tid TEXT, progress TEXT, done BOOLEAN)"
    )
    # Profile Concept Index
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS profile_topic_index ON profile_topic (username, tid, done)"
    )
    # All General Purpose Simulations for a concept (these are not linked to the concept itself)
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS experiment_table (sid TEXT, description TEXT, code TEXT)"
    )
    # Generic Simulations (Experiments) Index
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS experiment_index ON experiment_table (sid, description, code)"
    )
    # Topic Practice
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS topic_practice_table (tid TEXT, qid INTEGER, type TEXT, question TEXT, answers TEXT, correct_answer TEXT, solution TEXT DEFAULT 'There is no solution for this problem yet!', recommended_time INTEGER)"
    )
    # Topic Practice Index
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS topic_practice_index ON topic_practice_table (tid, qid, type, question, answers, correct_answer, solution, recommended_time)"
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
        if type not in ["topic", "generic", "concept", "topic_practice"]:
            return {"error": "Invalid Arguments"} # Invalid Arguments

        auth_check = await authorize_user(self.username, self.token)
        if auth_check == False:
            return {"error": "Not Authorized"}
        if type == "generic":
            await db.execute(
                "UPDATE experiment_table SET code = $1 WHERE sid = $2",
                self.code,
                self.sid,
            )
        elif type == "topic":
            await db.execute(
                "UPDATE topic_table SET topic_experiment = $1 WHERE tid = $2",
                self.code,
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
        elif type == "topic_practice":
            await db.execute(
                "UPDATE topic_practice_table SET question = $1, answer = $2  WHERE tid = $3",
                self.question,
                self.answer,
                self.tid,
            )
        return {"error": "Successfully saved entity!"}

class SaveTopicExperiment(Save):
    tid: str
    code: str

class SaveTopicConcept(Save):
    tid: str
    cid: int
    code: str

class SaveTopicPractice(Save):
    type: str
    tid: str
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
    tid: str
    username: str
    status: str    
    cid: str

# **New Methods

class GenericExperimentNew(UserModel):
    description: str

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
    async def new(*, type, username, token, name = None, description = None, cid = None, tid = None, concept_title = None, question = None, correct_answer = None, answers = None, question_type = None, metaid = None, solution = None):
        auth_check = await authorize_user(username, token)
        if auth_check == False:
            return {"error": "Not Authorized"}
        if type == "subject":
            table = "subject_table"
            id_table = "metaid"
        elif type == "experiment":
            table = "experiment_table"
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
            
            practice_count = await db.fetch("SELECT COUNT(qid) FROM topic_practice_table WHERE tid = $1", tid)
            qid=practice_count[0]["count"] + 1 # Get the count + 1 for next concept

            if question_type == "MCQ":
                await db.execute(
                    "INSERT INTO topic_practice_table (qid, tid, type, question, correct_answer, answers, solution, recommended_time) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
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
                    "INSERT INTO topic_practice_table (qid, tid, type, question, correct_answer, solution, recommended_time) VALUES ($1, $2, $3, $4, $5, $6, $7)",
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
            return {"error": "1000", "page_count": concept_count[0]["count"] + 1}

        while True:
            id = get_token(101)
            id_check = await db.fetchrow(f"SELECT {id_table} FROM {table} WHERE {id_table} = $1", id)
            if id_check is None:
                break
        if type == "experiment":
            await db.execute(
                "INSERT INTO experiment_table (sid, description, code) VALUES ($1, $2, $3)",
                id,
                description,
                "arrow();",
            )

        elif type == "subject":
            await db.execute(
                "INSERT INTO subject_table (metaid, name, description) VALUES ($1, $2, $3)",
                id,
                name,
                description,
            )

        elif type == "topic":
            print(id)
            await db.execute(
                "INSERT INTO topic_table (name, description, topic_experiment, tid, metaid) VALUES ($1, $2, $3, $4, $5)",
                name,
                description,
                "alert('This topic has not been setup yet');",
                id,
                metaid,
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


@app.post("/topics/experiment/save", tags=["Experiments", "Topic Experiments", "W"])
async def topic_experiment_save(save: SaveTopicExperiment):
    return await save.save_experiment("topic")

@app.post("/topics/concepts/save", tags=["Topics", "Concepts", "W"])
async def topic_concept_save(save: SaveTopicConcept):
    return await save.save_experiment("concept")

@app.post("/topics/practice/save", tags = ["Topics", "Topic Practice", "W"])
async def topic_practice_save(save: SaveTopicPractice):
    return await save.save_experiment("topic_practice")

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
    entry = await db.fetchrow("SELECT done FROM profile_topic WHERE tid = $1 AND username = $2", tracker.tid, tracker.username)
    if entry is None:
        mode = 1 # Don't update, use insert statement mode
    elif entry["done"] is not True:
        mode = 2 # Update mode
    if mode == 1:
        await db.execute("INSERT INTO profile_topic (username, tid, progress, done) VALUES ($1, $2, $3, $4)", tracker.username, tracker.tid, tracker.status + tracker.cid, False)
    elif mode == 2:
        await db.execute("UPDATE profile_topic SET progress = $3 WHERE username = $1 AND tid = $2", tracker.username, tracker.tid, tracker.status + tracker.cid)
    return {"error": "1000", "debug": mode}

@app.get("/profile/track", tags = ["Profile", "R"])
async def profile_track_reader(tid: str, username: str):
    info = await db.fetchrow("SELECT progress, done FROM profile_topic WHERE username = $1 AND tid = $2", username, tid) # Get the page info
    if info is None:
        return {
            "status": "LP", # Default State is LP
            "cid": '1',
            "done": '0',
        }
    status = info["progress"][0] + info["progress"][1]
    cid = info["progress"][2:]
    done = info["done"]
    if done is not True:
        done = '0'
    else:
        done = '1'
    return {
        "status": status,
        "cid": cid,
        "done": done,
    }
    return {"error": "0001"}  # Invalid arguments (Default)

# New Stuff!!!

@app.post("/experiment/new", tags = ["Experiments", "RW"])
async def new_experiment(experiment: GenericExperimentNew):
    return await catphi.new(type="experiment", username = experiment.username, token = experiment.token, description = experiment.description)

@app.post("/topics/new", tags = ["Topics", "W"])
async def new_topic(topic: TopicNew):
    return await catphi.new(type="topic", username = topic.username, token = topic.token, name = topic.name, description = topic.description, metaid = topic.metaid)

@app.post("/subjects/new", tags = ["Subjects", "W"])
async def new_subject(subject: SubjectNew):
    return await catphi.new(type="subject", username = subject.username, token = subject.token, name = subject.name, description = subject.description)

@app.post("/topics/concepts/new", tags = ["Concepts", "W"])
async def new_concept(concept: ConceptNew):
    return await catphi.new(type="concept", username = concept.username, token = concept.token, tid = concept.tid, concept_title = concept.title)

@app.post("/topics/practice/new", tags = ["Topics", "Topic Practice", "W"])
async def new_topic_practice(topic_practice: TopicPracticeNew): 
    return await catphi.new(type="topic_practice", username = topic_practice.username, token = topic_practice.token, question_type = topic_practice.type, tid = topic_practice.tid, question = topic_practice.question, correct_answer = topic_practice.correct_answer, answers = topic_practice.answers, solution = topic_practice.solution)

# List Functions

@app.get("/topics/concepts/list", tags = ["Concepts", "R"])
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

@app.get("/topics/list", tags = ["Topics", "R"])
async def list_topics():
    topics = await db.fetch("SELECT name, tid FROM topic_table")
    tjson = {}
    for topic in topics:
        tjson[topic["name"]] = topic["tid"]
    return tjson

@app.get("/subjects/list", tags = ["Subjects", "R"])
async def list_subjects():
    subjects = await db.fetch("SELECT name, metaid FROM subject_table")
    sjson = {}
    for subject in subjects:
        sjson[subject["name"]] = subject["metaid"]
    return sjson

# List All Route (Called /bristlefrost/rootspring/shadowsight
@app.get("/bristlefrost/rootspring/shadowsight")
async def bristlefrost_rootspring_shadowsight():
    # Get all topics
    topics = await db.fetch("SELECT subject_table.metaid, topic_table.tid, topic_table.name AS topic_name, concept_table.cid, concept_table.title AS concept_name from concept_table INNER JOIN topic_table ON topic_table.tid = concept_table.tid INNER JOIN subject_table ON topic_table.metaid = subject_table.metaid ORDER BY tid, cid ASC")
    return topics

# Get Functions

@app.get("/topics/experiment/get", tags = ["Topics", "Topic Experiments", "R"])
async def get_topic_experiment(tid: str):
    topic = await db.fetchrow("SELECT name, topic_experiment FROM topic_table WHERE tid = $1", tid)
    if topic is None:
        return {"error": "0002"}
    elif topic["topic_experiment"] in ["", None]:
        code = "alert('This topic has not yet been configured yet!');"
    else:
        code = topic["topic_experiment"]
    return {"name": topic["name"], "code": code}

@app.get("/topics/concepts/get/count", tags = ["Topics", "Concepts", "R"])
async def get_concept_count(tid: str):
    concept_count = await db.fetch("SELECT COUNT(cid) FROM concept_table WHERE tid = $1", tid)
    return {"concept_count": concept_count[0]["count"]}

@app.get("/topics/concepts/get", tags = ["Topics", "Concepts", "R"])
async def get_concept(tid: str, cid: int):
    concept = await db.fetch("SELECT title, content FROM concept_table WHERE tid = $1 ORDER BY cid ASC", tid)
    if len(concept) == 0 or len(concept) < int(cid) or int(cid) <= 0:
        return {"error": "0002"} # Invalid Parameters
    return {"title": concept[int(cid) - 1]["title"], "content": concept[int(cid) - 1]["content"]}

@app.get("/topics/practice/get/count", tags = ["Topics", "Topic Practice", "R"])
async def get_topic_practice_count(tid: str):
    topic_practice = await db.fetch("SELECT COUNT(1) FROM topic_practice_table WHERE tid = $1", tid)
    return {"practice_count": topic_practice[0]["count"]}

@app.get("/topics/practice/get", tags = ["Topics", "Topic Practice", "R"])
async def get_concept_practice(tid: str, qid: int):
    question = await db.fetch("SELECT type, question, correct_answer, answers, solution, recommended_time FROM topic_practice_table WHERE tid = $1 AND qid = $2 ORDER BY qid ASC", tid, qid)
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
