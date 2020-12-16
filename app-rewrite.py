# Basic dependencies
from fastapi import FastAPI, Depends, BackgroundTasks, Request, Form as FastForm
import asyncio
import secrets
import string
import time
from starlette.exceptions import HTTPException as StarletteHTTPException
from markupsafe import Markup, escape


# Pydantic
from pydantic import BaseModel, ValidationError, validator, BaseSettings
from typing import Optional
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import json
import requests
import config
import logging


# Requests
logging.captureWarnings(True)
import requests as __r__


# Middleware
from starlette.middleware.sessions import SessionMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.status import HTTP_302_FOUND,HTTP_303_SEE_OTHER
from starlette_wtf import StarletteForm, CSRFProtectMiddleware, csrf_protect


# FastAPI App Code
app = FastAPI()
app.add_middleware(SessionMiddleware, secret_key="qEEZ0z1wXWeJ3lRJnPsamlvbmEq4tesBDJ38HD3dj329Ddrejrj34jfjrc4j3fwkjVrT34jkFj34jkgce3jfqkeieiei3jd44584830290riuejnfdiuwrjncjnwe8uefhnewfu553kf84EyfFH48SHSWk", same_site = 'strict', max_age = 7 * 24 * 60 * 60, https_only = True)
app.add_middleware(CSRFProtectMiddleware, csrf_secret='1f03eea1ffb7446294f71342bf110f21b91a849377144b789219a6a314ffb7815a0b69b2d6274bae84dd66b734393241')
templates = Jinja2Templates(directory="templates")
api = "https://127.0.0.1:443/api/v1"


# Wrappers
# A wrapper around requests
class requests():
    @staticmethod
    def get(url):
        return __r__.get(url, verify = config.SECURE)
    @staticmethod
    def post(url, json):
        return __r__.post(url, json = json, verify = config.SECURE)

# Bypass python scoping using a class
class Storage():
    pass

stor = Storage()

# BRS class to deal with servers BRS stuff
class BRS():
    def __init__(self, request_json):
        # NOTE: We cureently ignore metaid/subject for now until there is need for it
        brs_dict = {} # {tid: []}
        for obj in request_json:
            if obj["tid"] in brs_dict.keys():
                # We already have this tid as a key, add to it
                brs_dict[obj["tid"]].append([obj["topic_name"], obj["cid"], obj["concept_name"]])
            else:
                brs_dict[obj["tid"]] = [[obj["topic_name"], obj["cid"], obj["concept_name"]]]
        self.brs_dict = brs_dict

# Initial Cache On First Launch
stor.brs = BRS(requests.get(api + "/bristlefrost/rootspring/shadowsight").json()).brs_dict

# Dummy form for Starlette-WTF
class Form(StarletteForm):
    pass

# Server sends a GET request this when we need to recache /bristlefrost/rootspring/shadowsight 
@app.get("/api/internal/brs/cache/update") # Old URL
@app.get("/brs/internal/cache/update") # New URL
async def brs_request_loop():
    print("NOTE: Updating cache on server request")
    stor.brs = BRS(requests.get(api + "/bristlefrost/rootspring/shadowsight").json()).brs_dict
    return "DONE"

# Render template wrapper
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
    base_dict = {'request': request, "username": request.session.get("username"), "brs_list": stor.brs, "login_register": login_register, "form": form}
    return templates.TemplateResponse(f, {**base_dict, **kwargs}, status_code = status_code)

# redirect wrapper
def redirect(path):
    return RedirectResponse(path, status_code=HTTP_303_SEE_OTHER)

# abort wrapper
def abort(code):
    raise StarletteHTTPException(status_code=code)

# Classes
class TopicPracticeSolve(BaseModel):
    answer: str
    lives: int
    path: str

class SaveExperimentPage(BaseModel):
    username: str
    token: str
    code: str

class SaveTopic(BaseModel):
    username: str
    token: str
    description: str


# Exceptions
@app.exception_handler(StarletteHTTPException)
async def not_found(request, exc):
    if str(exc).__contains__("CSRF"):
        request.session["csrf"] = True
        request.session["status_code"] = 400
        return await render_template(request, "csrf_error.html")
    request.session["status_code"] = 404
    return await render_template(request, "404.html")

# Routes
@app.get("/")
async def index(request: Request):
    return await render_template(request, "index.html")

@app.get("/experiment/{sid}/edit")
async def experiment_edit_simulation(request: Request, sid: str):
    if request.session.get("token") == None:
        request.session["redirect"] = "/experiment/" + sid + "/edit"
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    ejson = requests.get(
        api + f"/experiment/get?sid={sid}"
    ).json()  # Get the experiment pertaining to the concept
    if ejson.get("code") != None:
        return abort(404)
    return await render_template(
        request,
        "generic_simulation_editor.html",
        sid=sid,
        token=request.session.get("token"),
        code=ejson["context"]["exp_code"],
    )

@app.post("/experiment/new")
async def new_simulation_post(request: Request, exp_type: str = FastForm("glowscript"), description: str = FastForm("No description yet")):
    poster = requests.post(api + "/experiment/new", json = {
        "username": request.session.get("username"),
        "token": request.session.get("token"),
        "description": description,
        "exp_type": exp_type
    }).json()
    return poster

@app.get("/experiment/new")
async def new_simulation_get(request: Request):
    if request.session.get("token") == None:
        request.session["redirect"] = "/experiment/new"
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    return await render_template(
        request,
        "admin_simulation_new.html",
    )

@app.post("/experiment/{sid}/save")
async def experiment_save(sid: str, data: SaveExperimentPage):
    a = requests.post(
        api + "/experiment/save",
        json={
            "username": data.username,
            "token": data.token,
            "code": data.code,
            "sid": sid,
        },
    )
    a = a.json()
    return a

# Profile Operations
@app.get("/profile/me/")
@app.get("/profile/me")
async def profile_me(request: Request):
    if request.session.get("token") == None or request.session.get("username") == None:
        request.session["redirect"] = "/profile/me"
        return redirect("/login")
    return redirect("/profile/" + request.session.get("username"))

@app.post("/topics/{tid}/concepts/{cid}/save")
async def save_page(tid: str, cid: str, data: SaveExperimentPage):
    a = requests.post(
        api + "/topics/concepts/save",
        json={
            "username": data.username,
            "token": data.token,
            "code": data.code,
            "cid": cid,
            "tid": tid,
        },
    )
    a = a.json()
    return a

@app.post("/topics/<tid>/save")
async def save_topics(request: Request, tid: str, data: SaveTopic):
    a = requests.post(
        api + "/topics/save",
        json={
            "username": data.username,
            "token": data.token,
            "description": data.description,
            "tid": tid,
        },
    )
    a = a.json()
    return a

@app.route("/iframe/{sid}")
async def iframe_simulation(request: Request, sid: str):
    simulation = requests.get(api + "/experiment/get?sid=" + sid).json()
    if simulation.get("code") != None:
        return abort(404)
    return await render_template(
        request,
        "iframe_simulation.html",
        desc = simulation["context"]["description"],
        code = simulation["context"]["exp_code"]
    )

@app.get("/login")
@csrf_protect
async def login_get(request: Request):
    if request.session.get("token") is not None:
        return redirect("/redir")

    elif request.session.get("redirect") is not None and request.session.get('defmsg') is None:
        request.session['defmsg'] = "You need to login in order to access this resource"
    elif request.session.get("defmsg") is None:
        return await render_template(request, "login.html")
    else:
        defmsg = request.session.get("defmsg")
        del request.session['defmsg']
        return await render_template(request, "login.html", error = defmsg)
    
@app.post("/login")
@csrf_protect
async def login_post(request: Request, username: str = FastForm(None), password: str = FastForm(None)):
    rc = requests.post(
        api + "/auth/login", json={"username": username, "password": password}
    )
    rc = rc.json()
    if rc["context"].get("mfaChallenge") != None:
        return redirect(f"/login/mfa/{r['username']}/{rc['context']['mfaToken']}")
    elif rc["code"] == None:
        rc = rc["context"] # Get the status context
        request.session.clear() # remove old session
        # Check if the user is an admin
        if "admin" in rc["scopes"].split(":"):
            request.session["admin"] = 1
        else:
            request.session["admin"] = 0
        request.session["username"] = username
        request.session["token"] = rc["token"]
        return redirect("/topics")
    if rc["code"] == "INVALID_USER_PASS":
        return await render_template(
            request,
            "login.html",
            error = Markup(rc["html"]),
        )
    if rc["code"] == "ACCOUNT_DISABLED":
        if rc["context"]["status"] == 1:
            msg = "We could not log you in as you have disabled your account. Please click <a href='/reset'>here</a> to reset your password and re-enable your account"
        elif rc["context"]["status"] == 2:
            msg = "We could not log you in as an admin has disabled your account. Please click <a href='/contactus'>here</a> to contact our customer support"
        else:
            msg = f"Unknown account state. Please click <a href='/contactus'>here</a> to contact our customer support"
        return await render_template(
            request, 
            "login.html",
            error = msg,
        )
    return rc

@app.get("/login/mfa/{username}/{token}")
async def login_mfa_get(request: Request, username: str, token: str):
    if request.session.get("token") is not None:
        return redirect("/redir")
    if request.method == "GET":
        return await render_template(request, "mfa.html", mode = "login", proposed_username = username)

@app.post("/login/mfa/{username}/{token}")
@csrf_protect
async def login_mfa_post(request: Request, username: str, token: str, otp: str = FastForm("")):
    otp = str(otp.replace(' ', ''))
    if len(otp) != 6: # Take 5 in to account as well
        return await render_template(request, "mfa.html", mode = "login", error = "OTP must be 6 digit number", proposed_username = username)
    rc = requests.post(api + "/auth/mfa", json = {
        "token": token,
        "otp": otp
    }).json()
    if rc["code"] != None:
        return await render_template(request, "mfa.html", mode = "login", error = rc["html"], proposed_username = username)
    elif rc["code"] == None:
        rc = rc["context"] # Get the status context
        request.session.clear() # remove old session
        # Check if the user is an admin
        if "admin" in rc["scopes"].split(":"):
            request.session["admin"] = 1
        else:
            request.session["admin"] = 0
        request.session["username"] = username
        request.session["token"] = rc["token"]
        return redirect("/topics")
    if rc["code"] == "ACCOUNT_DISABLED":
        if rc["context"]["status"] == 1:
            msg = "We could not log you in as you have disabled your account. Please click <a href='/reset'>here</a> to reset your password and re-enable your account"
        elif rc["context"]["status"] == 2:
            msg = "We could not log you in as an admin has disabled your account. Please click <a href='/contactus'>here</a> to contact our customer support"
        else:
            msg = f"Unknown account state. Please click <a href='/contactus'>here</a> to contact our customer support"
        return await render_template(
            request,
            "mfa.html",
            mode = "login",
            error = Markup(msg),
        )
    return rc

@app.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return redirect("/")

@app.get("/recovery")
@csrf_protect
async def recovery_get(request: Request):
    if request.method == "GET":
        return await render_template(request, "mfa.html", mode = "backup", done = False)

@app.post("/recovery")
@csrf_protect
async def recovery_post(request: Request, otp: str = FastForm("")):
    rc = requests.post(api + "/auth/recovery", json = {
        "backup_key": otp
    }).json()
    if rc["code"] != None:
        return await render_template(request, "mfa.html", mode = "backup", error = Markup(rc["html"]), done = False)
    return await render_template(
        request,
        "mfa.html",
        mode = "backup",
        error = Markup(rc["html"]),
        done = True
    )

@app.get("/recovery/options")
async def recovery_options(request: Request):
    return await render_template(request, "recovery_options.html")

@app.get("/redir")
async def redir(request: Request):
    if request.session.get("redirect") == None:
            return redirect("/topics")
    rdir = request.session.get("redirect")
    try:
        del request.session["redirect"]
    except:
        pass
    return redirect(rdir)

@app.get("/register")
async def register_get(request: Request):
    if request.session.get("token") != None:
        return redirect("/redir")
    
    return await render_template(request, "register.html")

@app.post("/register")
@csrf_protect
async def register_post(request: Request, email: str = FastForm(None), password = FastForm(None), cpassword = FastForm(None), username = FastForm(None)):
    if email == None or password == None or cpassword == None or username == None:
        return await render_template(
            request,
            "register.html",
            error="Please fill in all required fields",
        )
    elif username in ["", " ", "me"]:
        return await render_template(
            request,
            "register.html",
            error="Please enter a proper username that is not reserved (me etc.)",
        )
    elif password != cpassword:
        return await render_template(
            request,
            "register.html",
            error="Your retyped password does not match",
        )
    rc = requests.post(
        api + "/auth/register",
        json={
            "email": email,
            "username": username,
            "password": password,
        },
    )
    rc = rc.json()
    if rc["code"] == None:
        request.session["username"] = username
        request.session["token"] = rc["context"]["token"]
        return await render_template(request, "backup_key.html", backup_key = rc["context"]["backup_key"])
    else:
        return await render_template(
            request,
            "register.html",
            error=rc["html"],
        )

# Stage 1 (sending the email)
@app.get("/reset")
async def reset_pwd_s1_get(request: Request):
    if request.method == "GET":
        return await render_template(
            request,
            "/reset_gen.html",
        )

@app.post("/reset")
@csrf_protect
async def reset_pwd_s1_post(request: Request, username: str = FastForm(None), email: str = FastForm(None)):
    if username is None or username == "":
        json={"email": email}
    else:
        json={"username": username}
    x = requests.post(
            api + "/auth/reset/send", json=json
    ).json()
    if x["error"] == "1000":
        msg = "We have sent a confirmation email to the email you provided. Please check your spam folder if you did not recieve one"
    else:
        msg = "Something has went wrong. Please recheck your email and make sure it is correct"
    return await render_template(
        request,
        "/reset_confirm.html",  
        msg=msg
    )

@app.get("/reset/stage2")
async def reset_pwd_get(request: Request, token: str):
    a = requests.get(api + f"/auth/reset/check/token?token={token}").json()
    print(a)
    if a["code"] == False:
        request.session["status_code"] = 403
        return await render_template(request, "reset_fail.html")
    return await render_template(request, "reset.html")

@app.post("/reset/stage2")
async def reset_pwd_post(request: Request, token: str, password: str = FastForm("None"), cpassword: str = FastForm("Nothing")):
    if password != cpassword:
        return await render_template(
            request,
            "/reset.html",
            error="The passwords do not match",
        )
    if len(password) < 9:
        return await render_template(
            request,
            "reset.html",
            error="Your password must be at least 9 characters long",
        )
    x = requests.post(
        api + "/auth/reset/change",
        json={"token": token, "new_password": password},
    ).json()
    if x["error"] == "1000":
        msg = "Your password has been reset successfully."
    else:
        if x["error"] == "1101":
            msg = "Your account has been disabled by an administrator. It may not have its password reset."
        else:
            msg = "Something has went wrong while we were trying to reset your password. Please try again later."
    return await render_template(
        request,
        "/reset_confirm.html",  
        msg=msg
    )

@app.get("/subject/new")
async def new_subjects_get(request: Request):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics"
        return redirect("/login")
    if request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    return await render_template(
        request,
        "subject_new.html",
    )

@app.post("/subject/new")
@csrf_protect
async def new_subjects_post(request: Request, name: str = FastForm(None), description: str = FastForm(None)):
    x = requests.post(
        api + "/subjects/new",
        json={
            "username": request.session.get("username"),
            "token": request.session.get("token"),
            "name": name,
            "description": description
        },
    ).json()
    return x

@app.get("/topics/")
@app.get("/topics")
async def topics(request: Request):
    topic_list_json = requests.get(api + "/topics/list").json()  # Get the list of topics in JSON
    topic_list = []  # ejson as list
    if topic_list_json.get("error") is not None:
        return await render_template(
            request,
            "topic_list.html",
            topic_list=[]
        )
    for topic in topic_list_json.keys():
        topic_list.append([topic, topic_list_json[topic]])
    return await render_template(
        request,
        "topic_list.html",
        topic_list=topic_list,
        admin = request.session.get("admin"),
    )

@app.get("/topics/{tid}")
@app.get("/topics/{tid}/")
async def get_topic_index(request: Request, tid: str):
    topic_json = requests.get(
        api + f"/topics/get?tid={tid}&simple=0"
    ).json()  # Get the full topic info
    if topic_json.get("code") != None:
        return abort(404)
    return await render_template(
        request,
        "topic_page.html",
        name=topic_json["context"]["name"],
        description=topic_json["context"]["description"],
        tid=tid,
        admin = request.session.get("admin"),
    )

@app.get("/topics/{tid}/concepts/new")
async def new_concept_get(request: Request, tid: str):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics"
        return redirect("/login")
    if request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    return await render_template(
        request,
        "concept_new.html",
    )

@app.post("/topics/{tid}/concepts/new")
@csrf_protect
async def new_concept_post(request: Request, tid: str, concept: str = FastForm("Untitled Concept")):
    x = requests.post(
        api + "/concepts/new",
        json={
            "username": request.session.get("username"),
            "token": request.session.get("token"),
            "topic": tid,
            "concept": concept,
        },
    ).json()
    return x

@app.get("/topics/{tid}/edit")
async def topics_edit_description(request: Request, tid: str):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics/" + tid
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    ejson = requests.get(
        api + f"/topics/get?tid={tid}&simple=0" # We need the description here. No simple mode
    ).json()
    if ejson.get("code") != None:
        return abort(404)
    return await render_template(
        request,
        "editor.html",
        type = "topic",
        tid=tid,
        token=request.session.get("token"),
        description=ejson["context"]["description"],
    )

@app.get("/topics/{tid}/editmenu")
@app.get("/topics/{tid}/editmenu/")
@csrf_protect
async def topics_edit_menu(request: Request, tid: str):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics/" + tid + "/edit"
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    topic_exp_json = requests.get(api + f"/topics/get?tid={tid}&simple=1").json()
    if topic_exp_json.get("code") != None:
        return abort(404)
    return await render_template(
        request,
        "topic_edit_menu.html",
        tid=tid,
    )

@app.get("/topics/{tid}/edit/concepts")
@csrf_protect
async def topic_edit_concepts(request: Request, tid: str):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics/" + tid
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    exp_json = requests.get(api + f"/topics/get?tid={tid}&simple=1").json()
    if exp_json.get("code") != None:
        return abort(404)
    concepts_json = requests.get(api + f"/topics/concepts/list?tid={tid}").json()
    print(concepts_json)
    if concepts_json.get("error") is not None:
        concepts = []
    else:
        concepts = []
        for concept in concepts_json.keys():
            concepts.append([concept, concepts_json[concept]])
    return await render_template(
        request,
        "topic_edit_concepts.html",
        tid=tid,
        concepts = concepts,
    )

@app.get("/topics/{tid}/edit/concept/{cid}")
async def topic_edit_concept(request: Request, tid: str, cid: int):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics/" + tid
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    concept_json = requests.get(api + f"/topics/concepts/get?tid={tid}&cid={str(cid)}").json()
    print(concept_json)

    if concept_json.get("error") or int(cid) < 0:
        return abort(404)
    return await render_template(
        request,
        "editor.html",
        type = "concept",
        tid = tid,
        cid = cid,
        content = Markup(concept_json.get("content")),
        token = request.session.get("token"),
    )

@app.get("/topics/{tid}/edit/concepts/new")
async def topic_edit_new_concept_get(request: Request, tid: str):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics/" + tid + "/edit/concept/new"
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    ejson = requests.get(api + f"/topics/get?tid={tid}&simple=1").json()
    if ejson.get("code") != None:
        return abort(404)
    return await render_template(
        request,
        "topic_new_concept.html",
        tid=tid,
    )

@app.post("/topics/{tid}/edit/concepts/new")
@csrf_protect
async def __topic_edit_new_concept_post__(request: Request, tid, title: str = FastForm("Untitled Concept")):
        a = requests.post(
            api + "/topics/concepts/new",
            json={
                "username": request.session.get("username"),
                "token": request.session.get("token"),
                "tid": tid,
                "title": title,
            },
        ).json()
        return a

@app.get("/topics/{tid}/edit/practice/new")
@csrf_protect
async def new_practice_question_get(request: Request, tid: str):
    default_values = {"type": "MCQ", "question": "", "answers": "", "correct_answer": "", "solution": ""}
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics/" + tid + "/edit/practice/new"
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    return await render_template(request, "topic_practice_new.html", default_values = default_values, mode = "new")

@app.post("/topics/{tid}/edit/practice/new")
@csrf_protect
async def new_practice_question_post(request: Request, tid: str, type: str = FastForm("MCQ"), question: str = FastForm("Question Not Yet Setup"), correct_answer: str = FastForm(None), solution: str = FastForm("There is no solution yet"), answers: str = FastForm(None)):
        default_values = {"type": "MCQ", "question": "", "answers": "", "correct_answer": "", "solution": ""}
        if type == "MCQ" and (answers is None or correct_answer not in ["A", "B", "C", "D"]):
            return await render_template(request, "topic_practice_new.html",  error = "Not all required fields have been filled in and/or the correct answer is invalid (must be one letter in an MCQ)", default_values = default_values, mode = "new")
        elif type == "MCQ" and len(answers.split("||")) != 4:
            return await render_template(request, "topic_practice_new.html",  error = "MCQ must have 4 questions seperated by ||", default_values = form, mode = "new")

        json = {
            "username": request.session.get('username'),
            "token": request.session.get("token"),
            "type": type,
            "question": question,
            "correct_answer": correct_answer,
            "solution": solution,
            "tid": tid,
        }
        if type == "MCQ":
            json["answers"] = answers
        return requests.post(api + "/topics/practice/new", json = json).json()

@app.get("/topic/new")
async def new_topic_get(request: Request):
    print("Got here")
    subject_json = requests.get(api + "/subjects/list").json()
    if subject_json == {}:
        subjects = []
    else:
        subjects = []
        for subject in subject_json.keys():
            subjects.append([subject, subject_json[subject]])
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics"
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    return await render_template(
        request,
        "topic_new.html",
        subjects = subjects
    )

@app.post("/topic/new")
@csrf_protect
async def new_topic_post(request: Request, name: str = FastForm(None), description: str = FastForm(None), metaid: str = FastForm(None)):
    x = requests.post(
        api + "/topics/new",
        json={
            "username": request.session.get("username"),
            "token": request.session.get("token"),
            "name": name,
            "description": description,
            "metaid": metaid
        }).json()
    if x.get("error") == "1000":
        return redirect(f"/topics/{x['tid']}")
    return x

@app.get("/topics/{tid}/learn")
async def redir_topic(request: Request, tid: str):
    if "username" not in request.session:
        return redirect("/topics/" + tid + "/learn/1")
    tracker_r = requests.get(api + "/profile/track?username=" + request.session.get("username") + "&tid=" + tid).json()
    cid = tracker_r["context"]['cid']
    if tracker_r["context"]["status"] == "LP":
        return redirect("/topics/" + tid + "/learn/" + str(cid))
    elif tracker_r["context"]["status"] == "PP":
        return redirect("/topics/" + tid + "/practice/" + str(cid))
    return abort(404)

@app.get("/topics/{tid}/learn/{cid}")
async def topic_concept_learn(request: Request, tid: str, cid: int):
    concept_json = requests.get(api + f"/topics/concepts/get?tid={tid}&cid={cid}").json()
    if concept_json.get("error") is not None:
        return abort(404)
    count_json = requests.get(
        api + f"/topics/concepts/get/count?tid={tid}"
    ).json()  # Get the page count of a concept
    if "username" in request.session:
        # User is logged in, track their progress
        tracker_r = requests.get(api + "/profile/track?username=" + request.session.get("username") + "&tid=" + tid).json()
        done = tracker_r["context"]['done']
        tracked_cid = tracker_r["context"]['cid']
        if int(tracked_cid) < int(cid) and not done and tracker_r["context"]["status"] == "LP":
            tracker_w = requests.post(api + "/profile/track", json = {
                "username": request.session.get("username"),
                "token": request.session.get("token"),
                "status": "LP",
                "tid": tid,
                "cid": cid
            }).json() # Track the fact that he went here in this case
    pages = [i for i in range(1, count_json['concept_count'] + 1)]
    return await render_template(
        request,
        "concept.html",
        tid=tid,
        cid=int(cid),
        concepts = pages,
        concept_count = count_json['concept_count'],
        content = Markup(concept_json['content']),
        title = concept_json["title"],
        admin = request.session.get("admin"),
    )

@app.get("/topics/{tid}/practice")
async def redir_topic_practice(request: Request, tid: str):
    if "username" not in request.session:
        return redirect("/topics/" + tid + "/practice/1")
    tracker = requests.get(api + "/profile/track?username=" + request.session.get("username") + "&tid=" + tid).json()
    cid = tracker["context"]['cid']
    if tracker["context"]["status"] == "PP":
        return redirect("/topics/" + tid + "/practice/" + str(cid))
    else:
        return redirect("/topics/" + tid + "/practice/1")

# For practice questions, only track when they get a question correct
@app.get("/topics/{tid}/practice/{qid}")
async def topic_practice_view(request: Request, tid: str, qid: int):
    practice_json = requests.get(api + f"/topics/practice/get?tid={tid}&qid={qid}").json()
    if practice_json.get("error") is not None:
        return await render_template(
            request,
            "generic_error.html",
            practice_mode = True,
            header="There are no practice question's for this topic yet...",
            error="Check back later, brave explorer!",
            tid = tid
        )
    print(practice_json)
    count_json = requests.get(
        api + f"/topics/practice/get/count?tid={tid}"
    ).json()  # Get the page count of a concept
    if practice_json["type"] == "MCQ":
        answers = practice_json["answers"].split("||")
    else:
        answers = None
    correct_answer = practice_json["correct_answer"]
    pages = [i for i in range(1, count_json['practice_count'] + 1)]

    # Check if they already answered said question
    try:
        key = "|".join(["practice", "answer", tid, str(qid)])
        solved = request.session[key]
        key = "|".join(["practice", "lives", tid, str(qid)])
        lives = str(request.session[key])
        key = "|".join(["practice", "path", tid, str(qid)])
        choices = request.session[key].split("|")
        if len(choices) == 2 or (len(choices) == 1 and choices[0] != correct_answer):
            # They had two chances, get the incorrect one and store in a variable
            inans = choices[0] # This was their first choice
        else:
            inans = None
    except:
        solved = None
        lives = None
        choices = None
        inans = None
    print(solved, lives, choices, solved)
    return await render_template(
        request,
        "topic_practice.html",
        token = request.session.get("token"),
        practice_mode = True,
        tid=tid,
        qid=int(qid),
        questions = pages,
        practice_count = count_json['practice_count'],
        type = practice_json["type"],
        question = Markup(practice_json["question"]),
        answers = answers,
        correct_answer = correct_answer,
        admin = request.session.get("admin"),
        solution = Markup(practice_json["solution"]),
        solved = solved,
        lives = lives,
        choices = choices,
        inans = inans,
    )

# They have solved the question, save it on server session and on other locations (a database) if logged in
@app.post("/topics/{tid}/practice/{qid}/solve")
@csrf_protect
async def topic_practice_solve(request: Request, tid: str, qid: int, data: TopicPracticeSolve):
    key = "|".join(["practice", "answer", tid, str(qid)])
    request.session[key] = data.answer
    key = "|".join(["practice", "lives", tid, str(qid)])
    request.session[key] = data.lives
    key = "|".join(["practice", "path", tid, str(qid)])
    request.session[key] = data.path
    if "username" in request.session.keys():
        tracker_w = requests.post(api + "/profile/track", json = {
            "username": request.session.get("username"),
            "token": request.session.get("token"),
            "status": "PP",
            "tid": tid,
            "cid": qid
        }).json() # Track the fact that he went here
        tracker_w = requests.post(api + "/profile/track/practice", json = {
            "username": request.session.get("username"),
            "token": request.session.get("token"),
            "tid": tid,
            "qid": qid,
            "answer": data.answer,
            "lives": data.lives,
            "path": data.path
        }).json() # And track the answer he/she gave
    return {"error": "1000"}

