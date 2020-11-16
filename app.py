# USE "daphne app:app" TO RUN THE APP

import quart.flask_patch # Needed for Flask Extensions to work
from quart import Quart, abort, render_template, send_from_directory, send_file, request, session, redirect, make_push_promise, url_for
from flask_wtf.csrf import CSRFProtect, CSRFError # CSRF Form Protection
import asyncio
import requests
import time
import re
app = Quart(__name__, static_url_path="/static")
app.config["SECRET_KEY"] = "qEEZ0z1wXWeJ3lRJnPsamlvbmEq4tesBDJ38HD3dj329Dd"
app.config['SESSION_COOKIE_SAMESITE'] = "Strict"
csrf = CSRFProtect(app) # CSRF Form Protection
api = "http://localhost:3000"

import secrets
import string

def get_token(length):
    secure_str = ''.join((secrets.choice(string.ascii_letters) for i in range(length)))
    return secure_str

@app.route("/favicon.ico")
async def favicon():
    return await send_file('static/favicon.ico')

@app.route('/concept/<cid>/edit/simulation')
async def concept_edit_simulation(cid = None):
    if cid == None:
        return abort(404)
    elif session.get("token") == None:
        session['redirect'] = "/concept/" + cid + "/edit/simulation"
        return redirect("/login")
    elif session.get("admin") in [0, None, "0"]:
        return abort(401)
    ejson = requests.get(api + f"/get_concept_exp?id={cid}").json() # Get the experiment pertaining to the concept
    print(ejson)
    if ejson.get("error"):
        return abort(404)
    return await render_template("concept_simulation_editor.html", cid = cid, username = session.get('username'), token = session.get("token"), code = ejson['code'])

@app.route("/topics/new", methods=['GET', 'POST'])
async def new_topic():
    if request.method == "GET":
        if session.get("token") == None:
            session['redirect'] = "/topics/new"
            return redirect("/login")
        if session.get("admin") in [0, None, "0"]:
            return abort(401)
        return await render_template("topic_new.html", username = session.get('username'), token = session.get("token"))
    form = await request.form
    print(form)
    if "topic" not in form.keys():
        return await render_template("topic_new.html", username = session.get('username'), token = session.get("token"), error = "Invalid Topic Name")
    x = requests.post(api + "/topics/new", json = {"username": session.get("username"), "token": session.get("token"), "topic": form['topic']}).json()
    return x

# Profile Operations
@app.route("/me/make_public")
async def profile_public_set():
    if session.get("token") == None or session.get("username") == None:
        session['redirect'] = "/me/make_public"
        return redirect("/login")
    x = requests.post(api + "/visible", json = {"state": "public", "username": session.get("username"), "token": session.get("token")}).json()
    return x

@app.route("/me/make_private")
async def profile_private_set():
    if session.get("token") == None or session.get("username") == None:
        session['redirect'] = "/me/make_private"
        return redirect("/login")
    x = requests.post(api + "/visible", json = {"state": "private", "username": session.get("username"), "token": session.get("token")}).json()
    return x


@app.route("/profile/<username>")
async def profile(username = None):
    if username == None:
        return abort(404)
    # TODO: Finish profile
    if session.get("token") == None:
        profile = requests.get(api + "/profile?username=" + username).json()
    else:
        profile = requests.get(api + "/profile?username=" + username + "&token=" + session.get("token")).json()
    if profile.get("error") == "1002":
        return await render_template("generic_error.html", username = session.get('username'), header = "Profile Error", error = "Profile is private")
    elif profile.get("error") == "1001":
        return await render_template("generic_error.html", username = session.get('username'), header = "Profile Error", error = "Profile does not exist")
    p_username = username.capitalize()
    return await render_template("profile.html", username = session.get('username'), token = session.get("token"), admin = profile['admin'], p_username = p_username, join_date = time.strftime("%dth %b %Y", time.localtime(profile['join'])))

@app.route("/dashboard")
async def dashref():
    if "username" not in session:
        return redirect("/login")
    return redirect("/profile/" + session.get("username"))

@app.route("/nojs")
async def nojs():
    return 'CatPhi unfortunately needs JavaScript to work. Please follow <a href="https://support.google.com/adsense/answer/12654?hl=en">this guide</a> for more information'

cache_time = 60*5

# Actual Code
@app.route('/js/<path:fn>')
@app.route('/<folder1>/js/<path:fn>')
@app.route('/<folder1>/<folder2>/js/<path:fn>')
@app.route('/<folder1>/<folder2>/<folder3>/js/<path:fn>')
@app.route('/<folder1>/<folder2>/<folder3>/<folder4>/js/<path:fn>')
async def js_server(fn, folder1=None, folder2=None, folder3=None, folder4=None):
    if session.get("newuser") == None or time.time() - session.get("newuser") > 10:
        print("Doing server push")
        await make_push_promise(url_for('static', filename='RSrun.3.0.min.js'))
        await make_push_promise(url_for('static', filename='RScompiler.3.0.min.js'))
        await make_push_promise(url_for('static', filename='glow.3.0.min.js'))
    session['newuser'] = time.time() # We have now served this user
    if fn == "glow.js":
        return redirect("/js/glow.3.0.min.js") # Go to minified for this particular file
    if re.match(r'^\w+$', fn) == False:
        return abort(403) # Using .. or <> in this route
    elif fn == "jquery.min.js":
        print("Got jquery request")
        return redirect("https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js")
    try:
        return await send_from_directory('static', fn, cache_timeout = 300)
    except FileNotFoundError:
        return abort(304) # Try to fail gracefully in case they already have the file in cache

@app.route("/redir")
async def redir():
    if session.get("redirect") == None:
        return redirect("/dashboard")
    rdir = session.get("redirect")
    try:
        del session['redirect']
    except:
        pass
    return redirect(rdir)

# Stage 1 (sending the email)
@app.route('/reset', methods = ["GET", "POST"])
async def reset_pwd_s1():
    if session.get("token") != None:
        return redirect("/redir")

    # GET
    if request.method == "GET":
        return await render_template("/reset_gen.html", username = session.get("username"))
    # POST
    form = await request.form
    if form.get("email") == None or form.get("email") == "":
        return await render_template("/reset_gen.html", username = session.get("username"), error = "You must provide an email address.")
    x = requests.post(api + "/auth/reset/send", json = {"email": form.get("email")}).json()
    if x['error'] == "1000":
        msg = "We have sent a confirmation email to the email you provided. Please check your spam folder if you did not recieve one"
    else:
        msg = "Something has went wrong. Please recheck your email and make sure it is correct"
    return await render_template("/reset_confirm.html", username = session.get("username"), msg = msg)

@app.route('/reset/stage2', methods=["GET", "POST"])
async def reset_pwd():
    # GET
    if request.method == "GET":
        token = request.args.get("token")
        if token == None:
            return await render_template("/reset_fail.html", username = session.get("username")), 403
        a = requests.get(api + f"/auth/gset?token={token}").json()
        if a['status'] == "0":
            return await render_template("/reset_fail.html", username = session.get("username")), 403
        session["reset-token"] = token
        return await render_template("/reset.html", username = session.get("username"))
    # POST
    form = await request.form
    pwd = form.get("password") # PWD = New Password
    cpwd = form.get("cpassword") # CPWD = Confirm New Password
    if pwd == None or cpwd == None:
        return await render_template("/reset.html", username = session.get("username"), error = "You must input a new password")
    elif pwd != cpwd:
        return await render_template("/reset.html", username = session.get("username"), error = "The passwords do not match")
    if session.get("reset-token") == None:
        return await render_template("/reset_fail.html", username = session.get("username")), 403
    if len(pwd) < 9:
        return await render_template("register.html", username = session.get("username"), error = "Your password must be at least 9 characters long")
    x = requests.post(api + "/auth/reset/change", json = {"token": session["reset-token"], "password": pwd}).json()
    if x['error'] == "1000":
        msg = "Your password has been reset successfully."
    else:
        msg = "Something has went wrong while we were trying to reset your password. Please try again later."
    return await render_template("/reset_confirm.html", username = session.get("username"), msg = msg)

@app.route('/save/<cid>', methods=["POST"])
async def save_simu(cid = None):
    if cid == None:
        return {"error": "Invalid Concept Specified"}
    data = await request.form
    print(data)
    if "username" not in data.keys() or "token" not in data.keys() or "code" not in data.keys():
        return {"errpr": "Could not save data as required keys are not present"}
    a = requests.post(api + "/save", json = {"username": data['username'], "token": data['token'], "code": data['code'], "cid": cid})
    a = a.json()
    return a

@app.route("/register", methods = ["GET", "POST"])
async def register():
    if session.get("token") != None:
        return redirect("/redir")

    if request.method == "GET":
        return await render_template("register.html", username = session.get("username"))
    r = await request.form
    if "email" not in r.keys() or r.get("email") in ["", " "]:
        return await render_template("register.html", username = session.get("username"), error = "Please enter your email")
    if "password" not in r.keys() or r.get("password") in ["", " "]:
        return await render_template("register.html", username = session.get("username"), error = "Please enter your password")
    if "username" not in r.keys() or r.get("username") in ["", " "]:
        return await render_template("register.html", username = session.get("username"), error = "Please enter a proper username")
    if r.get("password") != r.get("cpassword"):
        return await render_template("register.html", username = session.get("username"), error = "Your retyped password does not match")
    if len(r.get("password")) < 9:
        return await render_template("register.html", username = session.get("username"), error = "Your password must be at least 9 characters long")
    rc = requests.post(api + "/auth/register", json = {"email": r['email'], "username": r['username'], "password": r['password']})
    rc = rc.json()
    if rc['error'] == '1000':
        session['username'] = r['username']
        session['token'] = rc['token']
        return redirect("/redir")
    if rc['error'] == '1001':
        return await render_template("login.html", username = session.get("username"), error = "An Unknown Error Has Occurred. Please Try Again Later")

@app.route('/logout', methods=['GET', 'POST'])
async def logout():
    session.clear()
    session['redirect'] = "/"
    return redirect("/redir")

@app.route('/login', methods=["GET", "POST"])
async def login():
    if session.get("token") != None:
        return redirect("/redir")

    if request.method == "GET":
        return await render_template("login.html", username = session.get("username"))

    r = await request.form

    if "username" not in r.keys() or r.get("username") in ["", " "]:
        return await render_template("login.html", username = session.get("username"), error = "Please enter your username")
    if "password" not in r.keys() or r.get("password") in ["", " "]:
        return await render_template("login.html", username = session.get("username"), error = "Please enter your password")

    rc = requests.post(api + "/auth/login", json = {"username": r['username'], "password": r['password']})
    rc = rc.json()
    if rc['error'] == '1000':
        # Check if the user is an admin
        if rc['admin'] == 1:
            session['admin'] = 1
        else:
            session['admin'] = 0
        session['username'] = r['username']
        session['token'] = rc['token']
        return redirect("/redir")
    if rc['error'] == '1001':
        return await render_template("login.html", username = session.get("username"), error = "Invalid Username Or Password")

@app.errorhandler(CSRFError)
async def handle_csrf_error(e):
    return await render_template('csrf_error.html', username = session.get("username"), reason=e.description), 400

@app.errorhandler(404)
async def handle_404_error(e):
    return await render_template('404.html', username = session.get("username"))


@app.route('/')
async def index():
    return await render_template("index.html", username = session.get("username"))

@app.route('/topic/<topic>')
async def topic(topic):
    if "username" not in session:
        session['redirect'] = "/topic/" + topic
        return redirect("/login")
    ejson = requests.get(api + "/list_concepts?topic=" + topic).json() # Get the e/cJSON (exp/concepts JSON)
    ejson = ejson[topic] # Get the proper json
    elist = [] # ejson as list
    i = 0
    if ejson.get("error") != None:
        return await render_template("concept_list.html", topic = topic, elist = [], username = session.get("username"))
    while i < len(ejson.keys()):
        if ejson[str(i)]["cid"] == "default":
            i+=1
            continue
        elist.append([ejson[str(i)]["cid"], ejson[str(i)]["name"]])
        i+=1
    return await render_template("concept_list.html", topic = topic, elist = elist, username = session.get("username"), admin = session.get("admin"))

@app.route("/topics/")
@app.route("/topics")
async def topics():
    if "username" not in session:
        session['redirect'] = "/topics"
        return redirect("/login")
    ejson = requests.get(api + "/list_topics").json() # Get the list of topics in JSON
    elist = [] # ejson as list
    i = 0
    if ejson.get("error") != None:
        return await render_template("topic_list.html", elist = [], username = session.get("username"))
    for topic in ejson.values():
        elist.append(topic)
        i+=1
    del elist[-1] # Remove last element
    return await render_template("topic_list.html", elist = elist, username = session.get("username"), admin = session.get("admin"))

@app.route("/concept/<id>")
async def get_experiment(id=None):
    if id == None:
        return abort(404)
    if "username" not in session:
        session['redirect'] = "/concept/" + id
        return redirect("/login")
    ejson = requests.get(api + f"/get_concept_exp?id={id}").json() # Get the experiment pertaining to the concept
    if ejson.get("error"):
        return abort(404)
    await make_push_promise(url_for('static', filename='RSrun.3.0.min.js'))
    await make_push_promise(url_for('static', filename='glow.3.0.min.js'))
    return await render_template("concept_simulation.html", username = session.get("username"), name = ejson["name"], code = ejson["code"], cid = id, admin = session.get("admin"))

#asyncio.run(serve(app, config))
