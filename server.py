"""
Internal Bot Server Code
"""
import asyncio
import secrets
import string
from hashlib import sha512
import smtplib
import time
from aiohttp import web
import asyncpg

SERVER_URL = "https://127.0.0.1:443"  # Main Server URL
HASH_SALT = "66801b86-06ff-49c7-a163-eeda39b8cba9_66bc6c6c-24e3-11eb-adc1-0242ac120002_66bc6c6c-24e3-11eb-adc1-0242ac120002"


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
        "CREATE TABLE IF NOT EXISTS login (token TEXT, username TEXT, password TEXT, email TEXT)"
    )
    # Create an index for login
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS login_index ON login (token, username, password, email)"
    )
    # A profile of a user
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS profile (username TEXT, join_epoch BIGINT, public BOOLEAN, exp_points BIGINT)"
    )
    # Create an index for the three things that will never/rarely change,
    # namely join date , username and public/private profile
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS profile_index ON profile (username, join_epoch, public)"
    )
    return __db


loop = asyncio.get_event_loop()
db = loop.run_until_complete(setup_db())
app = web.Application()
routes = web.RouteTableDef()

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


@routes.post("/save/concepts/experiments/title")
async def save_concept_title_experiment(request):
    data = await request.json()
    if (
        "username" not in data.keys()
        or "token" not in data.keys()
        or "code" not in data.keys()
        or "cid" not in data.keys()
    ):
        return web.json_response({"error": "0001"})  # Invalid Arguments
    # For every password and email, encode it to bytes and
    # SHA512 to get hash
    username = data["username"]
    # Check if the username is even registered with us and if the username
    # given in data.keys() is correct
    login_cred = await db.fetch(
        "SELECT username FROM login WHERE token = $1", data["token"]
    )
    if len(login_cred) == 0:
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    elif login_cred[0]["username"] != username:
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    elif data["token"] not in adminDict.values():
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    await db.execute(
        "UPDATE experiment_table SET code = $1 WHERE cid = $2",
        data["code"],
        data["cid"],
    )
    return web.json_response({"error": "Successfully saved experiment!"})


@routes.post("/concepts/new")
@routes.post("/concepts/add")
async def new_concept(request):
    data = await request.json()
    if (
        "username" not in data.keys()
        or "token" not in data.keys()
        or "topic" not in data.keys()
        or "concept" not in data.keys()
    ):
        return web.json_response({"error": "0001"})  # Invalid Arguments
    # For every password and email, encode it to bytes and
    # SHA512 to get hash
    username = data["username"]
    # Check if the username is even registered with us and if the username
    # given in data.keys() is correct
    login_cred = await db.fetch(
        "SELECT username FROM login WHERE token = $1", data["token"]
    )
    if len(login_cred) == 0:
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    elif login_cred[0]["username"] != username:
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    elif data["token"] not in adminDict.values():
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    # Firstly, make sure the topic actually exists
    tcheck = await db.fetch(
        "SELECT subject FROM experiment_table WHERE topic = $1", data["topic"]
    )
    if len(tcheck) == 0:
        return web.json_response({"error": "Topic Does Not Exist"})

    ccheck = await db.fetch(
        "SELECT subject FROM experiment_table WHERE topic = $1 AND name = $2",
        data["topic"],
        data["concept"],
    )
    if len(ccheck) != 0:
        return web.json_response({"error": "Topic/Concept Combination Already Exists"})
    while True:
        cid = get_token(101)
        concept_id_check = await db.fetch(
            "SELECT subject FROM experiment_table WHERE cid = $1", cid
        )
        if len(concept_id_check) == 0:
            break

    await db.execute(
        "INSERT INTO experiment_table (subject, topic, cid, name) VALUES ($1, $2, $3, $4)",
        "Physics",
        data["topic"],
        cid,
        data["concept"],
    )
    return web.json_response({"error": "1000", "cid": cid})


@routes.post("/concepts/page/new")
@routes.post("/concepts/page/add")
async def concept_page_add(request):
    data = await request.json()
    if (
        "username" not in data.keys()
        or "token" not in data.keys()
        or "cid" not in data.keys()
        or "title" not in data.keys()
    ):
        return web.json_response({"error": "0001"})  # Invalid Arguments
    # For every password and email, encode it to bytes and
    # SHA512 to get hash
    username = data["username"]
    # Check if the username is even registered with us and if the username
    # given in data.keys() is correct
    login_cred = await db.fetch(
        "SELECT username FROM login WHERE token = $1", data["token"]
    )
    if len(login_cred) == 0:
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    elif login_cred[0]["username"] != username:
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    elif data["token"] not in adminDict.values():
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    # Firstly, make sure the concept actually exists in
    # experiment_table
    tcheck = await db.fetch(
        "SELECT subject FROM experiment_table WHERE cid = $1", data["cid"]
    )
    if len(tcheck) == 0:
        # Concept Does Not Exist
        return web.json_response({"error": "Concept Does Not Exist"})
    await db.execute(
        "INSERT INTO concept_page_table (cid, title, content) VALUES ($1, $2, $3)",
        data["cid"],
        data["title"],
        f"Type your content for page {data['title']} here!",
    )
    page_count = await db.fetch(
        "SELECT COUNT(page_number) FROM concept_page_table WHERE cid = $1", data["cid"]
    )
    return web.json_response({"error": "1000", "page_count": page_count[0]["count"]})


@routes.post("/save/concepts/page")
async def concept_page_edit(request):
    data = await request.json()
    if (
        "username" not in data.keys()
        or "token" not in data.keys()
        or "cid" not in data.keys()
        or "page_number" not in data.keys()
        or "content" not in data.keys()
    ):
        return web.json_response({"error": "0001"})  # Invalid Arguments
    # For every password and email, encode it to bytes and
    # SHA512 to get hash
    username = data["username"]
    # Check if the username is even registered with us and if the username
    # given in data.keys() is correct
    login_cred = await db.fetch(
        "SELECT username FROM login WHERE token = $1", data["token"]
    )
    if len(login_cred) == 0:
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    elif login_cred[0]["username"] != username:
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    elif data["token"] not in adminDict.values():
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    # Firstly, make sure the concept actually exists in
    # experiment_table
    tcheck = await db.fetch(
        "SELECT subject FROM experiment_table WHERE cid = $1", data["cid"]
    )
    if len(tcheck) == 0:
        # Concept Does Not Exist
        return web.json_response({"error": "Concept Does Not Exist"})
    page_count = await db.fetch(
        "SELECT COUNT(page_number) FROM concept_page_table WHERE cid = $1", data["cid"]
    )
    if int(page_count[0]["count"]) < int(data["page_number"]):
        return web.json_response({"error": "0002"})  # Invalid Arguments
    pages = await db.fetch("SELECT page_number FROM concept_page_table WHERE cid = $1 ORDER BY page_number ASC", data['cid'])  # Get all the page numbers in ascending order
    page_number = pages[int(data['page_number']) - 1]["page_number"] # Calculate the absolute page number
    await db.execute(
        "UPDATE concept_page_table SET content = $1 WHERE cid = $2 AND page_number = $3",
        data["content"],
        data["cid"],
        int(page_number),
    )
    return web.json_response({"error": "Successfully saved page!"})


@routes.post("/topics/new")
@routes.post("/topics/add")
async def new_topic(request):
    data = await request.json()
    if (
        "username" not in data.keys()
        or "token" not in data.keys()
        or "topic" not in data.keys()
    ):
        return web.json_response({"error": "0001"})  # Invalid Arguments
    # For every password and email, encode it to bytes and
    # SHA512 to get hash
    username = data["username"]
    # Check if the username is even registered with us and if the username
    # given in data.keys() is correct
    login_cred = await db.fetch(
        "SELECT username FROM login WHERE token = $1", data["token"]
    )
    if len(login_cred) == 0:
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    elif login_cred[0]["username"] != username:
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    elif data["token"] not in adminDict.values():
        return web.json_response({"error": "Not Authorized"})  # Not Authorized
    # Make sure it doesn't already exist
    tcheck = await db.fetch(
        "SELECT subject FROM experiment_table WHERE topic = $1", data["topic"]
    )
    if len(tcheck) != 0:
        return web.json_response({"error": "Topic Already Exists"})
    await db.execute(
        "INSERT INTO experiment_table (subject, topic, cid, name) VALUES ($1, $2, $3, $4)",
        "Physics",
        data["topic"],
        "default",
        "default",
    )
    return web.json_response({"error": "1000"})


@routes.get("/topics/list")
async def list_topics(request):
    topics = await db.fetch("SELECT DISTINCT topic FROM experiment_table")
    tjson = {}
    i = 1
    for topic in topics:
        tjson[str(i)] = topic["topic"]
        i += 1
    tjson["total"] = len(topics)
    return web.json_response(tjson)


# Route that will get all experiment/concept IDs


@routes.get("/concepts/list")
async def list_concepts(request):
    data = request.rel_url.query
    if data.get("topic") is not None:
        # We want to get all experiments/concepts with a
        # specific topic
        experiments = await db.fetch(
            "SELECT DISTINCT cid, name, topic FROM experiment_table WHERE topic = $1 ORDER BY name DESC",
            data["topic"],
        )
    else:
        # 0003 = No Experiments Found. You must provide a topic in order to use
        # this
        return web.json_response({"error": "0003"})
    if len(experiments) == 0:
        # 0002 = No Experiments Found
        return web.json_response({"error": "0002"})
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
    return web.json_response(ejson)


@routes.get("/concepts/get/experiments/title")
async def get_concept_title_exp(request):
    cid = request.rel_url.query.get("id")
    if cid is None:
        # 0002 = No Experiments Found
        return web.json_response({"error": "0002"})
    experiments = await db.fetch(
        "SELECT name, code FROM experiment_table WHERE cid = $1", cid
    )
    if len(experiments) == 0:
        # 0002 = No Experiments Found
        return web.json_response({"error": "0002"})
    elif experiments[0]["code"] in ["", None]:
        code = "alert('This concept has not yet been configured yet!')"
    else:
        code = experiments[0]["code"]
    experiments = {"name": experiments[0]["name"], "code": code}
    return web.json_response(experiments)


@routes.get("/concepts/get/page/count")
async def get_concept_page_count(request):
    cid = request.rel_url.query.get("id")
    if cid is None:
        return web.json_response({"error": "0002"})
    page_count = await db.fetch(
        "SELECT COUNT(page_number) FROM concept_page_table WHERE cid = $1", cid
    )
    if len(page_count) == 0:
        page_count_json = {"page_count": 0}
    else:
        page_count_json = {"page_count": page_count[0]["count"]}
    return web.json_response(page_count_json)


@routes.get("/concepts/get/page")
async def get_concept_page(request):
    cid = request.rel_url.query.get("id")
    page_number = request.rel_url.query.get("page_number")
    if cid is None or page_number is None:
        return web.json_response({"error": "0003"})
    page = await db.fetch(
        "SELECT title, content FROM concept_page_table WHERE cid = $1 ORDER BY page_number ASC",
        cid, 
    )
    if len(page) == 0 or len(page) < int(page_number) or int(page_number) <= 0:
        return web.json_response({"error": "0002"}) # Invalid Parameters
    page_count_json = {"title": page[int(page_number) - 1]["title"], "content": page[int(page_number) - 1]["content"]}
    return web.json_response(page_count_json)


# Profile Code #


@routes.post("/profile/visible")
async def change_visibility(request):
    data = await request.json()
    state = data.get("state")
    username = data.get("username")
    token = data.get("token")
    if state not in ["public", "private"] or username is None or token is None:
        return web.json_response({"error": "1001"})
    usertok = await db.fetch("SELECT token FROM login WHERE username = $1", username)
    # Check if username and token match
    if usertok[0]["token"] == token:
        pass
    else:
        return web.json_response({"error": "1002"})
    visible = bool(state == "public")
    await db.execute(
        "UPDATE profile SET public = $1 WHERE username = $2", visible, username
    )
    return web.json_response({"error": "1000"})


@routes.get("/profile")
async def get_profile(request):
    username = request.rel_url.query.get("username")
    if username is None:
        return web.json_response({"error": "1001"})
    # Get the profile
    profile_db = await db.fetch(
        "SELECT public, join_epoch, exp_points FROM profile WHERE username = $1",
        username,
    )
    usertok = await db.fetch("SELECT token FROM login WHERE username = $1", username)
    if len(profile_db) == 0:
        return web.json_response({"error": "1001"})
    elif not profile_db[0]["public"]:
        priv = 1
        token = request.rel_url.query.get("token")
        if token is None:
            return web.json_response({"error": "1002"})  # Private
        elif usertok[0]["token"] == token:
            pass
        else:
            return web.json_response({"error": "1002"})  # Private
    else:
        priv = 0

    if usertok[0]["token"] in adminDict.values():
        is_admin = 1
    else:
        is_admin = 0
    return web.json_response(
        {
            "username": username,
            "admin": is_admin,
            "join": profile_db[0]["join_epoch"],
            "priv": priv,
            "experience": profile_db[0]["exp_points"],
        }
    )


# Authentication Code #

# Send a reset email (stage2 auth)


@routes.post("/auth/reset/send")
async def reset_passwd_send(request):
    data = await request.json()
    if "email" not in data.keys():
        return web.json_response({"error": "0001"})  # No Email Specified
    email = sha512(data["email"].encode()).hexdigest()
    login_cred = await db.fetch(
        "SELECT token, username from login WHERE email = $1", email
    )
    if len(login_cred) == 0:
        # Invalid Username Or Password
        return web.json_response({"error": "1001"})
    url_flag = True  # Flag to check if we have a good url id yet
    while url_flag:
        atok = get_token(101)
        if atok not in resetDict.values():
            url_flag = False
    resetDict[login_cred[0]["token"]] = atok
    eresetDict[atok] = data["email"]
    # Now send an email to the user
    reset_link = SERVER_URL + "/reset/stage2?token=" + atok
    reset_message = f"Subject: CCTP Password Reset\n\nUsername {login_cred[0]['username']}\nPlease use {reset_link} to reset your password.\n\nIf you didn't authorize this action, please change your password immediately"
    email_session = smtplib.SMTP("smtp.gmail.com", 587)
    email_session.starttls()  # TLS for security
    email_session.login(SENDER_EMAIL, SENDER_PASS)  # Email Auth
    email_session.sendmail(SENDER_EMAIL, data["email"], reset_message)
    email_session.close()
    return web.json_response({"error": "1000"})  # Success


# Change the actual password (stage3 auth)


@routes.post("/auth/reset/change")
async def reset_passwd_change(request):
    data = await request.json()
    if "token" not in data.keys() or "password" not in data.keys():
        # No Reset Token Specified Or No Password Given
        return web.json_response({"error": "0001"})
    if data.get("token") not in resetDict.values():
        # Reset Token Not Authorized
        return web.json_response({"error": "1001"})
    # Change the password of the field related to that users
    # account
    token = None
    for item in resetDict.items():
        if item[1] == data.get("token"):
            token = item[0]
            email = eresetDict.get(data.get("token"))
            break
    username = await db.fetch("SELECT username FROM login WHERE token = $1", token)
    if len(username) == 0:
        return web.json_response({"error": "1001"})
    username = username[0]["username"]
    password = sha512(
        ("Shadowsight1" + HASH_SALT + username + data["password"]).encode()
    ).hexdigest()  # New password
    # Make sure we cant use the same token again
    resetDict[token] = None
    await db.execute("UPDATE login SET password = $1 WHERE token = $2", password, token)
    reset_message = "Subject: Your CCTP Password Was Just Reset\n\nYour CatPhi password was just reset\n\nIf you didn't authorize this action, please change your password immediately"
    email_session = smtplib.SMTP("smtp.gmail.com", 587)
    email_session.starttls()  # TLS for security
    email_session.login(SENDER_EMAIL, SENDER_PASS)  # Email Auth
    email_session.sendmail(SENDER_EMAIL, email, reset_message)
    email_session.close()
    return web.json_response({"error": "1000"})  # Success


# This checks if the reset request is in resetDict and
# returns the result


@routes.get("/auth/gset")
async def gset(request):
    token = request.rel_url.query.get("token")
    if token is None or token not in resetDict.values():
        return web.json_response({"status": "0"})
    else:
        return web.json_response({"status": "1"})


@routes.post("/auth/login")
async def login(request):
    data = await request.json()
    if "username" not in data.keys() or "password" not in data.keys():
        return web.json_response({"error": "0001"})
    username = data["username"]
    password = sha512(
        ("Shadowsight1" + HASH_SALT + username + data["password"]).encode()
    ).hexdigest()
    login_creds = await db.fetch(
        "SELECT token from login WHERE username = $1 and password = $2",
        username,
        password,
    )
    if len(login_creds) == 0:
        # Invalid Username Or Password
        return web.json_response({"error": "1001"})
    if login_creds[0]["token"] in adminDict.values():
        is_admin = 1
    else:
        is_admin = 0
    # Add you to the list of logged in users
    loginDict[username] = login_creds[0]["token"]
    return web.json_response(
        {"error": "1000", "token": login_creds[0]["token"], "admin": is_admin}
    )


@routes.post("/auth/logout")
async def logout(request):
    data = await request.json()
    if "username" not in data.keys():
        return web.json_response({"error": "0001"})
    username = data["username"]
    try:
        # Removes you from the list of logged in users
        del loginDict[username]
    except KeyError:
        pass
    return web.json_response({"error": "1000"})


@routes.post("/auth/register")
async def register(request):
    data = await request.json()
    if (
        "email" not in data.keys()
        or "username" not in data.keys()
        or "password" not in data.keys()
    ):
        return web.json_response({"error": "0001"})
    # For every password and email, encode it to bytes and
    # SHA512 to get hash
    username = data["username"]
    password = sha512(
        ("Shadowsight1" + HASH_SALT + username + data["password"]).encode()
    ).hexdigest()
    email = sha512(data["email"].encode()).hexdigest()
    login_creds = await db.fetch(
        "SELECT token from login WHERE username = $1 OR email = $2", username, email
    )
    if len(login_creds) != 0:
        # Invalid Username Or Password
        return web.json_response({"error": "1001"})
    flag = True
    while flag:
        # Keep getting and checking token with DB
        token = get_token(101)
        login_creds = await db.fetch(
            "SELECT username from login WHERE token = $1", token
        )
        if len(login_creds) != 0:
            continue
        flag = False
    await db.execute(
        "INSERT INTO login (token, username, password, email) VALUES ($1, $2, $3, $4);",
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
    return web.json_response({"error": "1000", "token": token})


app.add_routes(routes)

# Run the on-bot web server
asyncio.ensure_future(web.run_app(app, port=3000))
