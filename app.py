""" Imports """

from quart import (
    Quart,
    abort,
    render_template as __rt__,
    send_from_directory,
    send_file,
    request,
    session,
    redirect,
    make_push_promise,
    url_for,
    escape,
    Markup,
    jsonify,
)
from lib.catphi_csrf import CSRFProtect, CSRFError  # CSRF Form Protection
import asyncio
import requests as __r__
import time
import re
import secrets
import string
import logging
logging.captureWarnings(True)
secure_mode = False

# A wrapper around requests
class requests():
    @staticmethod
    def get(url):
        return __r__.get(url, verify = secure_mode)
    @staticmethod
    def post(url, json):
        return __r__.post(url, json = json, verify = secure_mode)

""" Configuration """

app = Quart(__name__, static_url_path="/static")
app.config["SECRET_KEY"] = "qEEZ0z1wXWeJ3lRJnPsamlvbmEq4tesBDJ38HD3dj329Ddrejrj34jfjrc4j3fwkjVrT34jkFj34jkgce3jfqkeieiei3jd44584830290riuejnfdiuwrjncjnwe8uefhnewfu553kf84EyfFH48SHSWk"
app.config["SESSION_COOKIE_SAMESITE"] = "Strict"
app.config["SESSION_COOKIE_SECURE"] = True
csrf = CSRFProtect(app)  # CSRF Form Protection
api = "https://127.0.0.1:3000"
""" Favicon """

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

# A wrapper arount Quart's render_template to make life easier
async def render_template(f, **kwargs):
    # This is a BristleRootShadow (brs) object which basically contains 
    brs = BRS(requests.get("https://127.0.0.1:3000/bristlefrost/rootspring/shadowsight").json()).brs_dict
    if f.__contains__("login.html") or f.__contains__("register.html") or f.__contains__("reset"):
        login_register = True
    else:
        login_register = False
    return await __rt__(f, username = session.get("username"), brs_list = brs, login_register = login_register, **kwargs)

@app.route("/favicon.ico")
async def favicon():
    return await send_file("static/favicon.ico")

@app.route("/test")
async def test():
    return await render_template("test.html", a = {"a": "1"})

@app.route("/topics/<tid>/edit")
async def topics_edit_menu(tid):
    if session.get("token") == None:
        session["redirect"] = "/topics/" + tid + "/edit"
        return redirect("/login")
    elif session.get("admin") in [0, None, "0"]:
        return abort(401)
    topic_exp_json = requests.get(api + f"/topics/experiment/get?tid={tid}").json()  # Get the experiment pertaining to the concept
    if topic_exp_json.get("error"):
        return abort(404)
    return await render_template(
            "topic_edit_menu.html",
            tid=tid,
            )

@app.route("/topics/<tid>/edit/concepts")
async def topic_edit_concepts(tid):
    if session.get("token") == None:
        session["redirect"] = "/topics/" + tid
        return redirect("/login")
    elif session.get("admin") in [0, None, "0"]:
        return abort(401)
    exp_json = requests.get(api + f"/topics/experiment/get?tid={tid}").json()  # Get the experiment pertaining to the topic
    if exp_json.get("error"):
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
            "topic_edit_concepts.html",
            tid=tid,
            concepts = concepts,
            )


@app.route("/topics/<tid>/edit/concept/<int:cid>")
async def topic_edit_concept(tid, cid):
    if session.get("token") == None:
        session["redirect"] = "/topics/" + tid
        return redirect("/login")
    elif session.get("admin") in [0, None, "0"]:
        return abort(401)
    concept_json = requests.get(api + f"/topics/concepts/get?tid={tid}&cid={str(cid)}").json()
    print(concept_json)

    if concept_json.get("error") or int(cid) < 0:
        return abort(404)
    return await render_template(
            "topic_concept_editor.html",
            tid=tid,
            cid=cid,
            content = Markup(concept_json.get("content").replace("<script", "").replace("</script", "")),
            token=session.get("token"),
            )

@app.route("/topics/<tid>/edit/concept/new", methods=["GET", "POST"])
async def topic_new_concept(tid):
    if session.get("token") == None:
        session["redirect"] = "/topics/" + tid + "/edit/concept/new"
        return redirect("/login")
    elif session.get("admin") in [0, None, "0"]:
        return abort(401)
    ejson = requests.get(
        api + f"/topics/experiment/get?tid={tid}"
    ).json()  # Get the experiment pertaining to the concept
    if ejson.get("error"):
        return abort(404)
    if request.method == "GET":
        return await render_template(
            "topic_new_concept.html",
            tid=tid,
        )
    elif request.method == "POST":
        form = await request.form
        print(form)
        if form.get("title") == None:
            return await render_template(
                "topic_new_concept.html",
                tid=tid,
                error = "You need to input a title!"
            )
        a = requests.post(
            api + "/topics/concepts/new",
            json={
                "username": session.get("username"),
                "token": session.get("token"),
                "tid": tid,
                "title": form.get("title"),
            },
        ).json()
        return a


@app.route("/topics/<tid>/edit/simulation")
async def topics_edit_simulation(tid):
    if session.get("token") == None:
        session["redirect"] = "/topics/" + tid
        return redirect("/login")
    elif session.get("admin") in [0, None, "0"]:
        return abort(401)
    ejson = requests.get(
        api + f"/topics/experiment/get?tid={tid}"
    ).json()  # Get the experiment pertaining to the concept
    if ejson.get("error"):
        return abort(404)
    return await render_template(
        "topic_simulation_editor.html",
        tid=tid,
        token=session.get("token"),
        code=ejson["code"],
    )


@app.route("/experiment/<sid>/edit")
async def experiment_edit_simulation(sid):
    if session.get("token") == None:
        session["redirect"] = "/experiment/" + sid + "/edit"
        return redirect("/login")
    elif session.get("admin") in [0, None, "0"]:
        return abort(401)
    ejson = requests.get(
        api + f"/experiment/get?sid={sid}&username={session['username']}"
    ).json()  # Get the experiment pertaining to the concept
    if ejson.get("error"):
        return abort(404)
    return await render_template(
        "generic_simulation_editor.html",
        sid=sid,
        token=session.get("token"),
        code=ejson["code"],
    )


@app.route("/experiment/new", methods=["GET", "POST"])
async def new_simulation():
    if request.method == "POST":
        form = await request.form
        poster = requests.post(api + "/experiment/new", json = {
            "username": session.get("username"),
            "token": session.get("token"),
            "description": form['description']
        }).json()
        return poster
    if session.get("token") == None:
        session["redirect"] = "/experiment/new"
        return redirect("/login")
    elif session.get("admin") in [0, None, "0"]:
        return abort(401)
    return await render_template(
        "admin_simulation_new.html",
    )

@app.route("/topics/<tid>/edit/practice/new", methods = ["GET", "POST"])
async def new_practice_question(tid):
    default_values = {"type": "MCQ", "question": "", "answers": "", "correct_answer": "", "solution": ""}
    if session.get("token") == None:
        session["redirect"] = "/topics/" + tid + "/edit/practice/new"
        return redirect("/login")
    elif session.get("admin") in [0, None, "0"]:
        return abort(401)
    if request.method == "GET":
        return await render_template("topic_practice_new.html", default_values = default_values, mode = "new")
    else:
        form = await request.form
        if "type" not in form.keys() or "question" not in form.keys() or "correct_answer" not in form.keys() or "solution" not in form.keys():
            return await render_template("topic_practice_new.html",  error = "Not all required fields have been filled in", default_values = default_values, mode = "new")
        elif form.get("type") == "MCQ" and (form.get("answers") is None or form.get("correct_answer") not in ["A", "B", "C", "D"]):
            return await render_template("topic_practice_new.html",  error = "Not all required fields have been filled in and/or the correct answer is invalid (must be one letter in an MCQ)", default_values = default_values, mode = "new")
        elif form.get("type") == "MCQ" and len(form.get("answers").split("||")) != 4:
            return await render_template("topic_practice_new.html",  error = "MCQ must have 4 questions seperated by ||", default_values = form, mode = "new")

        json = {
            "username": session.get('username'),
            "token": session.get("token"),
            "type": form.get("type"),
            "question": form.get("question"),
            "correct_answer": form.get("correct_answer"),
            "solution": form.get("solution"),
            "tid": tid,
        }
        if form.get("type") == "MCQ":
            json["answers"] = form.get("answers")
        return requests.post(api + "/topics/practice/new", json = json).json()

@app.route("/iframe/<sid>")
async def iframe_simulation(sid):
    simulation = requests.get(api + "/experiment/get?sid=" + sid).json()
    if simulation.get("error"):
        return abort(404)
    return await render_template(
        "iframe_simulation.html",
        desc = simulation.get("description"),
        code = simulation.get("code")
    )


@app.route("/topics/new", methods=["GET", "POST"])
async def new_topic():
    subject_json = requests.get(api + "/subjects/list").json()
    if subject_json == {}:
        subjects = []
    else:
        subjects = []
        for subject in subject_json.keys():
            subjects.append([subject, subject_json[subject]])
    if request.method == "GET":
        if session.get("token") == None:
            session["redirect"] = "/topics"
            return redirect("/login")
        elif session.get("admin") in [0, None, "0"]:
            return abort(401)
        return await render_template(
            "topic_new.html",
            subjects = subjects
        )
    form = await request.form
    if "name" not in form.keys() or "description" not in form.keys() or "metaid" not in form.keys():
        return await render_template(
            "topic_new.html",
            error="Invalid Topic Name And/Or Description And/Or Subject",
            subjects = subjects
        )
    x = requests.post(
        api + "/topics/new",
        json={
            "username": session.get("username"),
            "token": session.get("token"),
            "name": form["name"],
            "description": form["description"],
            "metaid": form["metaid"]
        },
    ).json()
    if x.get("error") == "1000":
        return redirect(f"/topics/{x['tid']}")
    return x


@app.route("/subjects/new", methods=["GET", "POST"])
async def new_subjects():
    if request.method == "GET":
        if session.get("token") == None:
            session["redirect"] = "/topics"
            return redirect("/login")
        if session.get("admin") in [0, None, "0"]:
            return abort(401)
        return await render_template(
            "subject_new.html",
        )
    form = await request.form
    if "name" not in form.keys() or "description" not in form.keys():
        return await render_template(
            "subject_new.html",
            error="Invalid Subject Name And/Or Description",
        )
    x = requests.post(
        api + "/subjects/new",
        json={
            "username": session.get("username"),
            "token": session.get("token"),
            "name": form["name"],
            "description": form["description"]
        },
    ).json()
    return x


@app.route("/topics/<topic>/concepts/new", methods=["GET", "POST"])
async def new_concept(topic):
    if request.method == "GET":
        if session.get("token") == None:
            session["redirect"] = "/topics"
            return redirect("/login")
        if session.get("admin") in [0, None, "0"]:
            return abort(401)
        return await render_template(
            "concept_new.html",
        )
    form = await request.form
    if "concept" not in form.keys():
        return await render_template(
            "concept_new.html",
            error="Invalid Concept Name",
        )
    x = requests.post(
        api + "/concepts/new",
        json={
            "username": session.get("username"),
            "token": session.get("token"),
            "topic": topic,
            "concept": form["concept"],
        },
    ).json()
    if x.get("error") == "1000":
        return redirect(f"/concept/{x['cid']}")
    return x


# Profile Operations
@app.route("/profile/me/")
@app.route("/profile/me")
async def profile_me():
    if session.get("token") == None or session.get("username") == None:
        session["redirect"] = "/profile/me"
        return redirect("/login")
    return redirect("/profile/" + session.get("username"))

@app.route("/profile/<username>/me/state/<state>")
async def profile_state_set(username, state):
    if session.get("token") == None or session.get("username") == None:
        session["redirect"] = "/profile/me/" + state
        return redirect("/login")
    elif state not in ["public", "private", "disable", "enable", "disable_admin"]:
        return abort(404)
    if username == session.get("username") or session.get("admin") == 1:
        pass
    else:
        return abort(401)

    post_data = {
        "state": state,
        "username": username,
        "token": session.get("token"),
    }

    if state == "disable_admin":
        post_data["state"] = "disable"
        post_data["disable_state"] = 2

    x = requests.post(
        api + "/profile/visible",
        json=post_data
        ).json()
    print(x)
    if state in ["disable", "disable_admin"] and session.get("admin") is not True:
        return redirect("/logout")
    return redirect("/settings/" + username)


@app.route("/profile/<username>/me/mfa/<state>", methods = ["GET", "POST"])
async def profile_mfa_set(username, state):
    if username != session.get("username"):
        return abort(403)

    elif state not in ["enable", "disable"]:
        return abort(404)
    if state == "enable":
        if request.method == "GET":
            # GET CODE
            rc = requests.post(api + "/auth/mfa/setup/1", json = {
                "token": session.get("token")
            }).json()
            if rc["error_code"] != None:
                return redirect("/logout")
            session["mfa_key"] = rc["context"]["key"]
            return await render_template("mfa.html", mode = "setup", key = rc["context"]["key"])
        else:
            # POST CODE
            obj = await request.form
            if len(obj["otp"]) != 6:
                return await render_template("mfa.html", mode = "setup", error = "OTP must be 6 characters long", key = session["mfa_key"])
            rc = requests.post(api + "/auth/mfa/setup/2", json = {
                "token": session.get("token"),
                "otp": obj["otp"]
            }).json()
            if rc["error_code"] != None:
                return await render_template("mfa.html", mode = "setup", error = Markup(rc["error_html"]), key = session["mfa_key"])
            del session["mfa_key"]
            return await render_template("mfa_backup_keys.html", backup_code = rc["context"]["backup_code"])

    if state == "disable":
        if request.method == "GET":
            return await render_template("mfa.html", mode = "disable")
        else:
            obj = await request.form
            if len(obj["otp"]) != 6:
                return await render_template("mfa.html", mode = "disable", error = "OTP must be 6 characters long")
            rc = requests.post(api + "/auth/mfa/disable", json = {
                "token": session.get("token"),
                "otp": obj["otp"]
            }).json()
            if rc["error_code"] != None:
                return await render_template("mfa.html", mode = "disable", error = Markup(rc["error_html"]))
            return redirect("/settings/" + username)

@app.route("/profile/<username>")
async def profile(username):
    # TODO: Finish profile
    if session.get("token") == None:
        profile = requests.get(api + "/profile?username=" + username).json()
    else:
        profile = requests.get(
            api + "/profile?username=" + username + "&token=" + session.get("token")
        ).json()
    if profile.get("error_code") == "PRIVATE_PROFILE":
        return await render_template(
            "generic_error.html",
            header="Profile Error",
            error="Profile is private",
        )
    elif profile.get("error_code") == "INVALID_PROFILE":
        return await render_template(
            "generic_error.html",
            header="Profile Error",
            error="Profile does not exist",
        )
    
    profile_owner = (session.get("username") == username or session.get("admin") == 1)
    private = profile['private']
    if not private:
        private = "Public"
    else:
        private = "Private"

    return await render_template(
        "profile.html",
        p_username=profile["username"],
        p_capusername = profile["username"].capitalize(),
        token=session.get("token"),
        p_admin=session.get("admin"),
        admin="admin" in profile["scopes"].split(":"),
        join_date=profile["join"],
        profile_owner = profile_owner,
        private = private,
        badges = profile["badges"],
        rank_name = profile["level"]["name"],
        rank_desc = profile["level"]["desc"],
        rank_levelup = profile["level"].get("levelup"),
        rank_levelup_name = profile["levelup_name"],
        items = profile["items"]
    )

@app.route("/settings/<username>")
async def settings(username):
    if "username" not in session or "token" not in session:
        return redirect("/login")
    if session.get("username") != username and session.get("admin") != 1:
        return abort(401)

    profile = requests.get(
        api + "/profile?username=" + username + "&token=" + session.get("token")
    ).json()
    if profile.get("error") == "1002":
        return await render_template(
            "generic_error.html",
            header="Profile Error",
            error="Profile is private",
        )
    priv = profile['private']
    mfa = profile["mfa"]
    if int(priv) == 0:
        priv = "Public"
    else:
        priv = "Private"
    return await render_template(
        "profile_settings.html",
        p_username=profile["username"],
        token=session.get("token"),
        private = priv,
        mfa = profile["mfa"]
    )


@app.route("/dashboard")
async def dashref():
    if "username" not in session:
        return redirect("/login")
    return redirect("/profile/" + session.get("username"))


# Actual Code
@app.route("/index/<path:fn>")
@app.route("/js/<path:fn>")
@app.route("/<folder1>/js/<path:fn>")
@app.route("/<folder1>/<folder2>/js/<path:fn>")
@app.route("/<folder1>/<folder2>/<folder3>/js/<path:fn>")
@app.route("/<folder1>/<folder2>/<folder3>/<folder4>/js/<path:fn>")
async def js_server(fn, folder1=None, folder2=None, folder3=None, folder4=None):
    if fn == "glow.js":
        return redirect(
            "/js/glow.3.0.min.js"
        )  # Go to minified for this particular file
    if re.match(r"^\w+$", fn) == False:
        return abort(403)  # Using .. or <> in this route
    elif fn == "jquery.min.js":
        return redirect(
            "https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"
        )
    try:
        return await send_from_directory("static", fn, cache_timeout=300)
    except FileNotFoundError:
        return abort(
            304
        )  # Try to fail gracefully in case they already have the file in cache


@app.route("/redir")
async def redir():
    if session.get("redirect") == None:
            return redirect("/topics")
    rdir = session.get("redirect")
    try:
        del session["redirect"]
    except:
        pass
    return redirect(rdir)


# Stage 1 (sending the email)
@app.route("/reset", methods=["GET", "POST"])
async def reset_pwd_s1():
    if session.get("token") != None:
        return redirect("/redir")

    # GET
    if request.method == "GET":
        return await render_template(
            "/reset_gen.html", 
        )
    # POST
    form = await request.form
    if form.get("username") in [None, ""] and form.get("email") in [None, ""]:
        return await render_template(
            "/reset_gen.html",
            error="You must provide an username or an email",
        )
    if form.get("username") is None or form.get("username") == "":
        json={"email": form["email"]}
    else:
        json={"username": form["username"]}
    x = requests.post(
            api + "/auth/reset/send", json=json
    ).json()
    print(x, json)
    if x["error"] == "1000":
        msg = "We have sent a confirmation email to the email you provided. Please check your spam folder if you did not recieve one"
    else:
        msg = "Something has went wrong. Please recheck your email and make sure it is correct"
    return await render_template(
        "/reset_confirm.html",  msg=msg
    )


@app.route("/reset/stage2", methods=["GET", "POST"])
async def reset_pwd():
    # GET
    if request.method == "GET":
        token = request.args.get("token")
        if token == None:
            return (
                await render_template(
                    "/reset_fail.html", 
                ),
                403,
            )
        a = requests.get(api + f"/auth/reset/check/token?token={token}").json()
        if a["status"] == "0":
            return (
                await render_template(
                    "/reset_fail.html", 
                ),
                403,
            )
        session["reset-token"] = token
        return await render_template("/reset.html", )
    # POST
    form = await request.form
    pwd = form.get("password")  # PWD = New Password
    cpwd = form.get("cpassword")  # CPWD = Confirm New Password
    if pwd == None or cpwd == None:
        return await render_template(
            "/reset.html",
            error="You must input a new password",
        )
    elif pwd != cpwd:
        return await render_template(
            "/reset.html",
            error="The passwords do not match",
        )
    if session.get("reset-token") == None:
        return (
            await render_template("/reset_fail.html", ),
            403,
        )
    if len(pwd) < 9:
        return await render_template(
            "register.html",
            error="Your password must be at least 9 characters long",
        )
    x = requests.post(
        api + "/auth/reset/change",
        json={"token": session["reset-token"], "new_password": pwd},
    ).json()
    if x["error"] == "1000":
        msg = "Your password has been reset successfully."
    else:
        if x["error"] == "1101":
            msg = "Your account has been disabled by an administrator. It may not have its password reset."
        else:
            msg = "Something has went wrong while we were trying to reset your password. Please try again later."
    return await render_template(
        "/reset_confirm.html",  msg=msg
    )

@app.route("/topics/<tid>/experiment/save", methods=["POST"])
async def save_topics(tid):
    data = await request.form
    if (
        "username" not in data.keys()
        or "token" not in data.keys()
        or "code" not in data.keys()
    ):
        return {"errpr": "Could not save data as required keys are not present"}
    a = requests.post(
        api + "/topics/experiment/save",
        json={
            "username": data["username"],
            "token": data["token"],
            "code": data["code"],
            "tid": tid,
        },
    )
    a = a.json()
    return a


@app.route("/experiment/<sid>/save", methods=["POST"])
async def experiment_save(sid):
    data = await request.form
    if (
        "username" not in data.keys()
        or "token" not in data.keys()
        or "code" not in data.keys()
    ):
        return {"errpr": "Could not save data as required keys are not present"}
    a = requests.post(
        api + "/experiment/save",
        json={
            "username": data["username"],
            "token": data["token"],
            "code": data["code"],
            "sid": sid,
        },
    )
    a = a.json()
    return a


@app.route("/topics/<tid>/concepts/<cid>/save", methods=["POST"])
async def save_page(tid, cid):
    data = await request.form
    if (
        "username" not in data.keys()
        or "token" not in data.keys()
        or "code" not in data.keys()
    ):
        return {"errpr": "Could not save data as required keys are not present"}
    a = requests.post(
        api + "/topics/concepts/save",
        json={
            "username": data["username"],
            "token": data["token"],
            "code": data["code"],
            "cid": cid,
            "tid": tid,
        },
    )
    a = a.json()
    return a


@app.route("/register", methods=["GET", "POST"])
async def register():
    if session.get("token") != None:
        return redirect("/redir")

    if request.method == "GET":
        return await render_template("register.html", )
    r = await request.form
    if "email" not in r.keys() or r.get("email") in ["", " "]:
        return await render_template(
            "register.html",
            error="Please enter your email",
        )
    if "password" not in r.keys() or r.get("password") in ["", " "]:
        return await render_template(
            "register.html",
            error="Please enter your password",
        )
    if "username" not in r.keys() or r.get("username") in ["", " ", "me"]:
        return await render_template(
            "register.html",
            error="Please enter a proper username that is not reserved (me etc.)",
        )
    if r.get("password") != r.get("cpassword"):
        return await render_template(
            "register.html",
            error="Your retyped password does not match",
        )
    if len(r.get("password")) < 9:
        return await render_template(
            "register.html",
            error="Your password must be at least 9 characters long",
        )
    rc = requests.post(
        api + "/auth/register",
        json={
            "email": r["email"],
            "username": r["username"],
            "password": r["password"],
        },
    )
    rc = rc.json()
    if rc["error"] == "1000":
        session["username"] = r["username"]
        session["token"] = rc["token"]
        return redirect("/redir")
    if rc["error"] == "1001":
        return await render_template(
            "register.html",
            error="That username or email is in use right now.",
        )


@app.route("/logout", methods=["GET", "POST"])
async def logout():
    redir = "/"
    session.clear()
    session["redirect"] = redir
    return redirect("/redir")


@app.route("/login", methods=["GET", "POST"])
async def login():
    if session.get("token") is not None:
        return redirect("/redir")

    if request.method == "GET":
        if session.get("redirect") is not None and session.get('defmsg') is None:
            session['defmsg'] = "You need to login in order to access this resource"
        if session.get("defmsg") is None:
            return await render_template("login.html")
        else:
            defmsg = session.get("defmsg")
            del session['defmsg']
            return await render_template("login.html",  error = defmsg)
    r = await request.form
    print(r)
    if "username" not in r.keys() or r.get("username") in ["", " "]:
        return await render_template(
            "login.html",
            error="Please enter your username",
        )
    if "password" not in r.keys() or r.get("password") in ["", " "]:
        return await render_template(
            "login.html",
            error="Please enter your password",
        )

    rc = requests.post(
        api + "/auth/login", json={"username": r["username"], "password": r["password"]}
    )
    rc = rc.json()
    if rc["context"].get("mfaChallenge") != None:
        return redirect(f"/login/mfa/{r['username']}/{rc['context']['mfaToken']}")
    elif rc["error_code"] == None:
        rc = rc["context"] # Get the status context
        session.clear() # remove old session
        # Check if the user is an admin
        if "admin" in rc["scopes"].split(":"):
            session["admin"] = 1
        else:
            session["admin"] = 0
        session["username"] = r["username"]
        session["token"] = rc["token"]
        return redirect("/topics")
    if rc["error_code"] == "INVALID_USER_PASS":
        return await render_template(
            "login.html",
            error=Markup(rc["error_html"]),
        )
    if rc["error_code"] == "ACCOUNT_DISABLED":
        if rc["context"]["status"] == 1:
            msg = "We could not log you in as you have disabled your account. Please click <a href='/reset'>here</a> to reset your password and re-enable your account"
        elif rc["context"]["status"] == 2:
            msg = "We could not log you in as an admin has disabled your account. Please click <a href='/contactus'>here</a> to contact our customer support"
        else:
            msg = f"Unknown account state. Please click <a href='/contactus'>here</a> to contact our customer support"
        return await render_template(
            "login.html",
            error=msg,
        )
    return rc

@app.route("/login/mfa/<username>/<token>", methods = ["GET", "POST"])
async def login_mfa(username, token):
    if session.get("token") is not None:
        return redirect("/redir")
    if request.method == "GET":
        return await render_template("mfa.html", mode = "login", proposed_username = username)
    r = await request.form
    if "otp" not in r.keys():
        return await render_template("mfa.html", mode = "login", error = "Please enter the OTP from your authentication app", proposed_username = username)
    try:
        otp = str(int(r['otp'].replace(' ', '')))
    except:
        return await render_template("mfa.html", mode = "login", error = "OTP must be a 6 digit number", proposed_username = username)
    if len(otp) != 6:
        return await render_template("mfa.html", mode = "login", error = "OTP must be 6 digit number", proposed_username = username)
    rc = requests.post(api + "/auth/mfa", json = {
        "token": token,
        "otp": otp
    }).json()
    if rc["error_code"] != None:
        return await render_template("mfa.html", mode = "login", error = rc["error_html"], proposed_username = username)
    elif rc["error_code"] == None:
        rc = rc["context"] # Get the status context
        session.clear() # remove old session
        # Check if the user is an admin
        if "admin" in rc["scopes"].split(":"):
            session["admin"] = 1
        else:
            session["admin"] = 0
        session["username"] = username
        session["token"] = rc["token"]
        return redirect("/topics")
    if rc["error_code"] == "ACCOUNT_DISABLED":
        if rc["context"]["status"] == 1:
            msg = "We could not log you in as you have disabled your account. Please click <a href='/reset'>here</a> to reset your password and re-enable your account"
        elif rc["context"]["status"] == 2:
            msg = "We could not log you in as an admin has disabled your account. Please click <a href='/contactus'>here</a> to contact our customer support"
        else:
            msg = f"Unknown account state. Please click <a href='/contactus'>here</a> to contact our customer support"
        return await render_template(
            "mfa.html",
            mode = "login",
            error=Markup(msg),
        )
    return rc

@app.route("/recovery/mfa/<username>", methods = ["GET", "POST"])
async def recovery_mfa(username):
    if request.method == "GET":
        return await render_template("mfa.html", mode = "backup")
    else:
        obj = await request.form
        if "otp" not in obj.keys() or len(obj["otp"]) == 0:
            return await render_template("mfa.html", mode = "backup", error = "No backup code was entered")
        rc = requests.post(api + "/auth/mfa/recovery", json = {
            "username": username,
            "backup_code": obj["otp"]
        }).json()
        if rc["error_code"] != None:
            return await render_template("mfa.html", mode = "backup", error = Markup(rc["error_html"]))
        return await render_template(
            "mfa.html",
            mode = "backup",
            error="Account successfully recovered. Please login again",
        )

@app.errorhandler(CSRFError)
async def handle_csrf_error(e):
    return (
        await render_template(
            "csrf_error.html",  reason=e.description
        ),
        400,
    )

@app.errorhandler(404)
async def handle_404_error(e):
    return await render_template("404.html"), 404

@app.route("/")
async def index():
    return await render_template("index.html")

@app.route("/topics/")
@app.route("/topics")
async def topics():
    topic_list_json = requests.get(api + "/topics/list").json()  # Get the list of topics in JSON
    topic_list = []  # ejson as list
    if topic_list_json.get("error") is not None:
        return await render_template(
            "topic_list.html", 
            topic_list=[], 
        )
    for topic in topic_list_json.keys():
        topic_list.append([topic, topic_list_json[topic]])
    return await render_template(
        "topic_list.html",
        topic_list=topic_list,
        admin=session.get("admin"),
    )

@app.route("/topics/<tid>")
@app.route("/topics/<tid>/")
async def get_topic_index(tid):
    topic_exp_json = requests.get(
        api + f"/topics/experiment/get?tid={tid}"
    ).json()  # Get the experiment pertaining to the topic
    try:
        if topic_exp_json.get("error") is not None:
            return abort(404)
    except TypeError:
        return abort(404)
    return await render_template(
        "topic_simulation.html",
        name=topic_exp_json["name"],
        code=topic_exp_json["code"],
        tid=tid,
        admin=session.get("admin"),
    )

@app.route("/topics/<tid>/learn")
async def redir_topic(tid):
    if "username" not in session:
        return redirect("/topics/" + tid + "/learn/1")
    tracker_r = requests.get(api + "/profile/track?username=" + session.get("username") + "&tid=" + tid).json()
    cid = tracker_r['cid']
    if tracker_r["status"] == "LP":
        return redirect("/topics/" + tid + "/learn/" + cid)
    elif tracker_r["status"] == "PP":
        return redirect("/topics/" + tid + "/practice/" + cid)

@app.route("/topics/<tid>/learn/<int:cid>")
async def topic_concept_learn(tid, cid):
    concept_json = requests.get(api + f"/topics/concepts/get?tid={tid}&cid={cid}").json()
    if concept_json.get("error") is not None:
        return abort(404)
    count_json = requests.get(
        api + f"/topics/concepts/get/count?tid={tid}"
    ).json()  # Get the page count of a concept
    if "username" in session:
        # User is logged in, track their progress
        tracker_r = requests.get(api + "/profile/track?username=" + session.get("username") + "&tid=" + tid).json()
        done = (tracker_r['done'] == '1')
        tracked_cid = tracker_r['cid']
        if int(tracked_cid) < int(cid) and not done and tracker_r["status"] == "LP":
            tracker_w = requests.post(api + "/profile/track", json = {"username": session.get("username"), "status": "LP", "tid": tid, "cid": cid}).json() # Track the fact that he went here in this case
    pages = [i for i in range(1, count_json['concept_count'] + 1)]
    return await render_template(
        "concept.html",
        tid=tid,
        cid=int(cid),
        concepts = pages,
        concept_count = count_json['concept_count'],
        content = Markup(concept_json['content']),
        title = concept_json["title"],
        admin=session.get("admin"),
    )

@app.route("/topics/<tid>/practice")
async def redir_topic_practice(tid):
    if "username" not in session:
        return redirect("/topics/" + tid + "/practice/1")
    tracker = requests.get(api + "/profile/track?username=" + session.get("username") + "&tid=" + tid).json()
    cid = tracker['cid']
    if tracker["status"] == "PP":
        return redirect("/topics/" + tid + "/practice/" + cid)
    else:
        return redirect("/topics/" + tid + "/practice/1")


@app.route("/topics/<tid>/practice/<int:qid>")
async def topic_practice_view(tid, qid):
    practice_json = requests.get(api + f"/topics/practice/get?tid={tid}&qid={qid}").json()
    if practice_json.get("error") is not None:
        return await render_template(
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
    if "username" in session:
        # User is logged in, track
        track = False
        tracker = requests.get(api + "/profile/track?username=" + session.get("username") + "&tid=" + tid).json()
        done = (tracker['done'] == '1')
        tracked_cid = tracker['cid']
        if (int(tracked_cid) < int(qid) and not done) or tracker["status"] in ["LP", ""]:
            track = True
        if track:
            tracker = requests.post(api + "/profile/track", json = {"username": session.get("username"), "status": "PP", "tid": tid, "cid": qid}).json() # Track the fact that he went here in this case
    if practice_json["type"] == "MCQ":
        answers = practice_json["answers"].split("||")
    else:
        answers = None
    correct_answer = practice_json["correct_answer"]
    pages = [i for i in range(1, count_json['practice_count'] + 1)]

    # Check if they already answered said question
    try:
        key = "|".join(["practice", "qa", tid, str(qid)])
        solved = session[key]
        key = "|".join(["practice", "lives", tid, str(qid)])
        lives = str(session[key])
        key = "|".join(["practice", "choices", tid, str(qid)])
        choices = session[key].split("|")
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
    print(solved, lives, choices)
    return await render_template(
        "topic_practice.html",
        token = session.get("token"),
        practice_mode = True,
        tid=tid,
        qid=int(qid),
        questions = pages,
        practice_count = count_json['practice_count'],
        type = practice_json["type"],
        question = Markup(practice_json["question"]),
        answers = answers,
        correct_answer = correct_answer,
        admin=session.get("admin"),
        solution = Markup(practice_json["solution"]),
        solved = solved,
        lives = lives,
        choices = choices,
        inans = inans,
    )

#TODO: Save on server session
# They have solved the question, save it on server session and on other locations (a database) if logged in
@app.route("/topics/<tid>/practice/<int:qid>/solve", methods = ["POST"])
async def topic_practice_solve(tid, qid):
    data = await request.form
    if "given_answer" not in data.keys() or "remaining_lives" not in data.keys() or "choices" not in data.keys():
        return jsonify({"error": "1001"})
    key = "|".join(["practice", "qa", tid, str(qid)])
    session[key] = data["given_answer"]
    key = "|".join(["practice", "lives", tid, str(qid)])
    session[key] = data["remaining_lives"]
    key = "|".join(["practice", "choices", tid, str(qid)])
    session[key] = data["choices"]
    print(session, data["given_answer"])
    return jsonify({"error": "1000"})

@app.route("/topics/<tid>/practice/<int:qid>/edit", methods = ["GET", "POST"])
async def topic_practice_edit(tid, qid):
    practice_json = requests.get(api + f"/topics/practice/get?tid={tid}&qid={qid}").json()
    if practice_json.get("error") is not None:
        return await render_template(
            "generic_error.html",
            header="This practice question doesn't exist yet",
            error=f"Please check the database for this topic and question ID\nTID: {{tid}}\nQID: {{qid}}",
            tid = tid,
        )

    # GET
    if request.method == "GET":
        if session.get("token") == None:
            session["redirect"] = "/topics/" + tid + "/practice/" + str(qid) + "/edit"
            return redirect("/login")
        elif session.get("admin") in [0, None, "0"]:
            return abort(401)
        return await render_template("topic_practice_new.html", default_values = practice_json, mode = "edit")
    # POST
    else:
        form = await request.form
        if "type" not in form.keys() or "question" not in form.keys() or "correct_answer" not in form.keys() or "solution" not in form.keys():
            return await render_template("topic_practice_new.html",  error = "Not all required fields have been filled in", default_values = form, mode = "edit")
        elif form.get("type") == "MCQ" and (form.get("answers") is None or form.get("correct_answer") not in ["A", "B", "C", "D"]):
            return await render_template("topic_practice_new.html",  error = "Not all required fields have been filled in and/or the correct answer is invalid (must be one letter in an MCQ)", default_values = form, mode = "edit")
        elif form.get("type") == "MCQ" and len(form.get("answers").split("||")) != 4:
            return await render_template("topic_practice_new.html",  error = "MCQ must have 4 questions seperated by ||", default_values = form, mode = "edit")

        json = {
            "username": session.get('username'),
            "token": session.get("token"),
            "type": form.get("type"),
            "question": form.get("question"),
            "correct_answer": form.get("correct_answer"),
            "solution": form.get("solution"),
            "tid": tid,
            "qid": qid,
        }
        if form.get("type") == "MCQ":
            json["answers"] = form.get("answers")
        return requests.post(api + "/topics/practice/save", json = json).json()

