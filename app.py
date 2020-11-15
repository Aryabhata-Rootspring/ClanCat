import quart.flask_patch # Needed for Flask Extensions to work
from quart import Quart, abort, render_template, send_from_directory, send_file, request, session, redirect
from flask_wtf.csrf import CSRFProtect, CSRFError # CSRF Form Protection
import asyncpg
import asyncio
from hypercorn.config import Config
from hypercorn.asyncio import serve
import requests
import time
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

# Only for testing
@app.route("/admin")
async def admin():
    if session.get("token") == None:
        session['redirect'] = "/admin"
        return redirect("/login")
    return await render_template("admin_console.html", username = session.get("username"))

@app.route("/favicon.ico")
async def favicon():
    return await send_file('static/favicon.ico')

@app.route('/edit/text')
async def edit_txt():
    if session.get("token") == None:
        session['redirect'] = "/edit/text"
        return redirect("/login")
    session['expid'] = get_token(101) 
    return await render_template("expedit.html", username = session.get('username'), token = session.get("token"))

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

# Actual Code
@app.route('/<folder1>/js/<path:fn>')
@app.route('/<folder1>/<folder2>/js/<path:fn>')
async def js_server(fn, folder1=None, folder2=None):
    if fn.__contains__(".."):
        return abort(403)
    try:
        return await send_file('static/' + fn)
    except FileNotFoundError:
        return abort(404)

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
    x = requests.post(api + "/auth/reset/change", json = {"token": session["reset-token"], "password": pwd}).json()
    if x['error'] == "1000":
        msg = "Your password has been reset successfully."
    else:
        msg = "Something has went wrong while we were trying to reset your password. Please try again later."
    return await render_template("/reset_confirm.html", username = session.get("username"), msg = msg)

@app.route('/save', methods=["POST"])
@csrf.exempt # This must be exempt in order for saving to work
async def save_simu():
    data = await request.form
    print(data)
    if session.get("expid") == None:
        session['expid'] = get_token(101) 
    if "username" not in data.keys() or "token" not in data.keys() or "code" not in data.keys() or "name" not in data.keys() or "topic" not in data.keys():
        return {"errpr": "Could not save data as required keys are not present"}
    a = requests.post(api + "/save", json = {"username": data['username'], "token": data['token'], "code": data['code'], "expid": session['expid'], "name": data["name"], "topic": data['topic']})
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

@app.route('/experiments')
async def experiments():
    if "username" not in session:
        session['redirect'] = "/experiments"
        return redirect("/login")
    ejson = requests.get(api + "/list_exp").json() # Get the eJSON (experiments JSON)
    elist = [] # ejson as list
    i = 0
    if ejson.get("error") != None:
        return await render_template("explist.html", elist = [], username = session.get("username"))
    while i < len(ejson.keys()):
        elist.append([ejson[str(i)]["owner"], ejson[str(i)]["expid"], ejson[str(i)]["name"]])
        i+=1
    return await render_template("explist.html", elist = elist, username = session.get("username"))

@app.route("/experiment/<id>")
async def get_experiment(id=None):
    if id == None:
        return abort(404)
    if "username" not in session:
        session['redirect'] = "/experiment/" + id
        return redirect("/login")
    ejson = requests.get(api + f"/get_exp?id={id}").json()
    if ejson.get("error"):
        return abort(404)
    return await render_template("exprun.html", username = session.get("username"), name = ejson["name"], code = ejson["code"], expid = id)

asyncio.run(serve(app, Config()))
