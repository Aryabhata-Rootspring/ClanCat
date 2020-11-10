import quart.flask_patch # Needed for Flask Extensions to work
from quart import Quart, render_template, send_from_directory, send_file, request, session, redirect
from flask_wtf.csrf import CSRFProtect, CSRFError # CSRF Form Protection
import asyncpg
import asyncio
from hypercorn.config import Config
from hypercorn.asyncio import serve
import requests
app = Quart(__name__, static_url_path="/static")
app.config["SECRET_KEY"] = "qEEZ0z1wXWeJ3lRJnPsamlvbmEq4tesBDJ38HD3dj329Dd"
csrf = CSRFProtect(app) # CSRF Form Protection
api = "http://localhost:3000"

import secrets
import string

def get_token(length):
    secure_str = ''.join((secrets.choice(string.ascii_letters) for i in range(length)))
    return secure_str

@app.route('/edit/text')
async def hello_world():
    if session.get("token") == None:
        session['redirect'] = "/edit/text"
        return redirect("/login")
    session['expid'] = get_token(101) 
    return await render_template("expedit.html")

@app.route('/<folder>/js/<path:fn>')
async def js_server(fn, folder):
    print("got here " + fn)
    return await send_file('static/' + fn)

@app.route("/redir")
async def redir():
    if session.get("redirect") == None:
        return redirect("/")
    return redirect(session.get("redirect"))

@app.route('/save', methods=["POST"])
@csrf.exempt # This must be exempt in order for saving to work
async def save_simu():
    print("CODE")
    data = await request.form
    if session.get("expid") == None:
        session['expid'] = get_token(101) 
    print(f"The data is {data}")
    if "owner" not in data.keys() or "code" not in data.keys():
        return {"errpr": "Could not save data as required keys are not present"}
    print(f"Owner: {data['owner']}\nCode: {data['code']}")
    a = requests.post(api + "/save", json = {"owner": data['owner'], "code": data['code'], "expid": session['expid']})
    a = a.json()
    return {"error": "Done"}

@app.route("/register", methods = ["GET", "POST"])
async def register():
    if request.method == "GET":
        return await render_template("register.html", username = session.get("username"))
    r = await request.form
    print(r)
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
    return redirect("/redir")

@app.route('/login', methods=["GET", "POST"])
async def login():
    if session.get("token") != None:
        return redirect("/redir")

    if request.method == "GET":
        return await render_template("login.html", username = session.get("username"))

    r = await request.form
    print(r)

    if "username" not in r.keys() or r.get("username") in ["", " "]:
        return await render_template("login.html", username = session.get("username"), error = "Please enter your username")
    if "password" not in r.keys() or r.get("password") in ["", " "]:
        return await render_template("login.html", username = session.get("username"), error = "Please enter your password")

    rc = requests.post(api + "/auth/login", json = {"username": r['username'], "password": r['password']})
    rc = rc.json()
    if rc['error'] == '1000':
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
    print("404")
    return await render_template('404.html', username = session.get("username"))


@app.route('/')
async def index():
    return await render_template("index.html", username = session.get("username"))

@app.route('/experiments')
async def experiments():
    ejson = requests.get(api + "/list_exp").json() # Get the eJSON (experiments JSON)
    elist = [] # ejson as list
    done_expids = [] # Already done experiments
    i = 0
    while i < len(ejson.keys()):
        if ejson[str(i)]["expid"] in done_expids:
            i+=1
            continue
        elist.append([ejson[str(i)]["owner"], ejson[str(i)]["token"], ejson[str(i)]["expid"]])
        done_expids.append(ejson[str(i)]["expid"])
        i+=1
    print(elist)
    return await render_template("explist.html", elist = elist, username = session.get("username"))

@app.route("/experiment/<id>")
async def get_exp(id=None):
    if id == None:
        return abort(404)
    ejson = requests.get(api + f"/get_exp?id={id}").json()
    if ejson.get("error"):
        return abort(404)
    return await render_template("exprun.html", username = session.get("username"), code = ejson["code"])

asyncio.run(serve(app, Config()))
