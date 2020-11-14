import asyncio
from aiohttp import web
import asyncpg
import secrets
import string
from hashlib import sha512
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

surl = "http://127.0.0.1:8000" # Main Server URL
salt = "66801b86-06ff-49c7-a163-eeda39b8cba9_66bc6c6c-24e3-11eb-adc1-0242ac120002_66bc6c6c-24e3-11eb-adc1-0242ac120002"


def get_token(length):
    secure_str = ''.join((secrets.choice(string.ascii_letters) for i in range(length)))
    return secure_str

async def setup_db():
    print("Setting up DB")
    db = await asyncpg.create_pool(
        host="database-1.civhw5bah3rj.us-east-2.rds.amazonaws.com",
        user="postgres",
        password="Waterbot123",
        database="CatPhi") #Login stuff
    await db.execute("CREATE TABLE IF NOT EXISTS experiment_table (token TEXT, owner TEXT, code TEXT, expid TEXT, name TEXT)") # Represents a simulation on the database
    await db.execute("CREATE INDEX IF NOT EXISTS experiment_index ON experiment_table (token, owner, code, expid)") # Create an index for the experiments
    await db.execute("CREATE TABLE IF NOT EXISTS login (token TEXT, username TEXT, password TEXT, email TEXT)") # Represents a single login in the database
    await db.execute("CREATE INDEX IF NOT EXISTS login_index ON login (token, username, password, email)") # Create an index for login
    return db
loop = asyncio.get_event_loop()
db = loop.run_until_complete(setup_db())
print(db)
app = web.Application()
routes = web.RouteTableDef()

resetDict = {} # resetDict is a dictionary of password reset requests currently present
eresetDict = {} # Emails, meow!

sender = "sandhoners123@gmail.com"
spass = "Ravenpaw11,"

@routes.post("/save")
async def save_file(request):
    data = await request.json()
    print(data)
    if "username" not in data.keys() or "token" not in data.keys() or "code" not in data.keys() or "expid" not in data.keys() or "name" not in data.keys():
        return web.json_response({"error": "0001"}) # Invalid Arguments
    print("Got valid post request for saving\nGetting token...")
    flag = True
    username = data['username'] # For every password and email, encode it to bytes and SHA512 to get hash 
    a = await db.fetch("SELECT username FROM login WHERE token = $1", data["token"]) # Check if the username is even registered with us and if the username given in data.keys() is correct
    if len(a) == 0:
        print("Invalid save request: User does not exist")
        return web.json_response({"error": "1001"}) # Not Authorized
    if a[0]["username"] != username:
        print("Invalid save request: User is invalid")
        return web.json_response({"error": "1001"}) # Not Authorized
    while(flag):
        # Keep getting and checking token with DB, use name as it will be the smallest
        token = get_token(101)
        a = await db.fetch("SELECT name from experiment_table WHERE token = $1", token)
        if len(a) != 0:
            continue
        flag = False
    print("Saving data")
    a = await db.execute("INSERT INTO experiment_table (owner, code, token, expid, name) VALUES ($1, $2, $3, $4, $5);", data['username'], data['code'], token, data['expid'], data['name'])
    return web.json_response({"error": "0000"})

@routes.post("/auth/register")
async def register(request):
    data = await request.json()
    if "email" not in data.keys() or "username" not in data.keys() or "password" not in data.keys():
        return web.json_response({"error": "0001"})
    print("Got valid signup request.\nGetting SHA512 of username, password and email")
    username = data['username'] # For every password and email, encode it to bytes and SHA512 to get hash
    password = sha512(("Shadowsight1" + salt + username + data['password']).encode()).hexdigest()
    email = sha512(data['email'].encode()).hexdigest()
    print("Verifying that this account doesn't already exist")
    a = await db.fetch("SELECT token from login WHERE username = $1 OR email = $2", username, email)
    if len(a) != 0:
        print("Authorization Failed: That User Already Exists")
        return web.json_response({"error": "1001"}) # Invalid Username Or Password
    print("Getting token")
    flag = True
    while(flag):
        # Keep getting and checking token with DB
        token = get_token(101)
        a = await db.fetch("SELECT username from login WHERE token = $1", token)
        if len(a) != 0:
            continue
        flag = False
    print("Got token, adding user to database")
    a = await db.execute("INSERT INTO login (token, username, password, email) VALUES ($1, $2, $3, $4);", token, username, password, email)
    return web.json_response({"error": "1000", "token": token}) # Login Was Successful!

# Route that will get all experiment IDs
@routes.get("/list_exp")
async def list_exp(request):
    data = request.rel_url.query
    if data.get("owner") != None:
        # We want to get all people who OWN this experiment
        experiments = await db.fetch("SELECT DISTINCT expid, name, owner FROM experiment_table WHERE owner = $1 ORDER BY owner ASC", data['owner'])
    else:
        experiments = await db.fetch("SELECT DISTINCT expid, name, owner FROM experiment_table ORDER BY owner ASC")
    if len(experiments) == 0:
        return web.json_response({"error": "0002"}) # 0002 = No Experiments Found
    ejson = {}
    i = 0 # Counter for eJSON
    for exp in experiments:
        # Add the experiment to the eJSON (experiment JSON)
        ejson[str(i)] = {"owner": exp["owner"], "expid": exp["expid"], "name": exp['name']}
        i+=1
    return web.json_response(ejson)

@routes.get("/get_exp")
async def get_exp(request):
    expid = request.rel_url.query.get("id")
    if expid == None:
        return web.json_response({"error": "0002"}) # 0002 = No Experiments Found
    experiments = await db.fetch("SELECT code FROM experiment_table WHERE expid = $1", expid)
    if len(experiments) == 0:
        return web.json_response({"error": "0002"}) # 0002 = No Experiments Found
    experiments = {"code": experiments[0]["code"], "versions": len(experiments)}
    return web.json_response(experiments)

# Change the actual password (stage3 auth)
@routes.post("/auth/reset/change")
async def reset_passwd_change(request):
    print("Got a password change request")
    data = await request.json()
    if "token" not in data.keys() or "password" not in data.keys():
        return web.json_response({"error": "0001"}) # No Reset Token Specified Or No Password Given
    if data.get("token") not in resetDict.values():
        return web.json_response({"error": "1001"}) # Reset Token Not Authorized
    # Change the password of the field related to that users account
    print("Getting token from resetDict")
    token = None
    for item in resetDict.items():
        if item[1] == data.get("token"):
            token = item[0]
            email = eresetDict.get(data.get("token"))
            print("Got user token: ", token)
            break
    unDB = await db.fetch("SELECT username FROM login WHERE token = $1", token)
    if len(unDB) == 0:
        return web.json_response({"error": "1001"})
    username = unDB[0]["username"]
    print("Request passed sanity checks\nSHA512ing password")
    password = sha512(("Shadowsight1" + salt + username + data['password']).encode()).hexdigest() # New password
    resetDict[token] = None # Make sure we cant use the same token again
    await db.execute("UPDATE login SET password = $1 WHERE token = $2", password, token)
    eMsg = f"Subject: Your CCTP Password Was Just Reset\n\nYour CatPhi password was just reset\n\nIf you didn't authorize this action, please change your password immediately"
    eSession = smtplib.SMTP('smtp.gmail.com', 587)
    eSession.starttls() # TLS for security
    eSession.login(sender, spass) # Email Auth
    eSession.sendmail(sender, email, eMsg)
    eSession.close()
    return web.json_response({"error": "1000"}) # Success

# Send a reset email (stage2 auth)
@routes.post("/auth/reset/send")
async def reset_passwd_send(request):
    data = await request.json()
    if "email" not in data.keys():
        return web.json_response({"error": "0001"}) # No Email Specified
    print("Got password reset request\nGetting SHA512 hash of email...")
    email = sha512(data['email'].encode()).hexdigest()
    print("Checking email")
    a = await db.fetch("SELECT token, username from login WHERE email = $1", email)
    print(f"Email is correct")
    if len(a) == 0:
        print("User does not exist. Could not reset password")
        return web.json_response({"error": "1001"}) # Invalid Username Or Password
    t = True # Flag to check if we have a good url id yet
    while(t):
        atok = get_token(101)
        print(atok)
        if atok not in resetDict.values():
            t = False
        print("Itering")
    print(f"Got reset token {atok}. Adding to resetDict")
    resetDict[a[0]['token']] = atok
    eresetDict[atok] = data['email']
    # Now send an email to the user
    resetLink = surl + "/reset/stage2?token=" + atok
    eMsg = f"Subject: CCTP Password Reset\n\nUsername {a[0]['username']}\nPlease use {resetLink} to reset your password.\n\nIf you didn't authorize this action, please change your password immediately"
    eSession = smtplib.SMTP('smtp.gmail.com', 587)
    eSession.starttls() # TLS for security
    eSession.login(sender, spass) # Email Auth
    eSession.sendmail(sender, data['email'], eMsg)
    eSession.close()
    return web.json_response({"error": "1000"}) # Success

# This checks if the reset request is in resetDict and returns the result
@routes.get("/auth/gset")
async def gset(request):
    a = request.rel_url.query.get("token")
    if a == None or a not in resetDict.values():
        return web.json_response({"status": "0"})
    else:
        return web.json_response({"status": "1"})
import time
import random
@routes.post("/auth/login")
async def login(request):
    data = await request.json()
    if "username" not in data.keys() or "password" not in data.keys():
        return web.json_response({"error": "0001"})
    print("Got valid login request.\nGetting SHA512 of username and password")
    username = data['username']
    password = sha512(("Shadowsight1" + salt + username + data['password']).encode()).hexdigest()
    print(username, password)
    print("Authorizing User...")
    a = await db.fetch("SELECT token from login WHERE username = $1 and password = $2", username, password)
    if len(a) == 0:
        print("Authorization Failed: Invalid Username Or Password")
        return web.json_response({"error": "1001"}) # Invalid Username Or Password
    print("User Authorized Successfully\nWaiting for 0.01 seconds to stop login hack attempts")
    return web.json_response({"error": "1000", "token": a[0]["token"]})
app.add_routes(routes)
print("Loading")
asyncio.ensure_future(web.run_app(app, port=3000)) # Run the on-bot web server
