from ..app_deps import *

router = APIRouter(
    tags=["Auth"],
)

@router.get("/login")
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

@router.post("/login")
@csrf_protect
async def login_post(request: Request, username: str = FastForm(None), password: str = FastForm(None)):
    rc = requests.post(
        api + "/auth/login", json={"username": username, "password": password}
    )
    rc = rc.json()
    if rc["context"].get("mfaChallenge") != None:
        return redirect(f"/login/mfa/{username}/{rc['context']['mfaToken']}")
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

@router.get("/login/mfa/{username}/{token}")
async def login_mfa_get(request: Request, username: str, token: str):
    if request.session.get("token") is not None:
        return redirect("/redir")
    if request.method == "GET":
        return await render_template(request, "mfa.html", mode = "login", proposed_username = username)

@router.post("/login/mfa/{username}/{token}")
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

@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    return redirect("/")

@router.get("/recovery")
async def recovery_get(request: Request):
    return await render_template(request, "mfa.html", mode = "backup", done = False)

@router.post("/recovery")
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

@router.get("/recovery/options")
async def recovery_options(request: Request):
    return await render_template(request, "recovery_options.html")

@router.get("/register")
async def register_get(request: Request):
    if request.session.get("token") != None:
        return redirect("/redir")

    return await render_template(request, "register.html")

@router.post("/register")
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
@router.get("/reset")
async def reset_pwd_s1_get(request: Request):
    if request.method == "GET":
        return await render_template(
            request,
            "/reset_gen.html",
        )

@router.post("/reset")
@csrf_protect
async def reset_pwd_s1_post(request: Request, username: str = FastForm(None), email: str = FastForm(None)):
    if username is None or username == "":
        json={"email": email}
    else:
        json={"username": username}
    x = requests.post(
            api + "/auth/reset/send", json=json
    ).json()
    print(x)
    if x["code"] is None:
        msg = "We have sent a confirmation email to the email you provided. Please check your spam folder if you did not recieve one"
    else:
        msg = "Something has went wrong. Please recheck your email and make sure it is correct"
    return await render_template(
        request,
        "/reset_confirm.html",
        msg=msg
    )

@router.get("/reset/stage2")
async def reset_pwd_get(request: Request, token: str):
    a = requests.get(api + f"/auth/reset/check/token?token={token}").json()
    if a["code"] == False:
        request.session["status_code"] = 403
        return await render_template(request, "generic_error.html", header = "Reset Password", error = "Something's Went Wrong. We cannot reset your password using this link. Plese try resetting your password again")
    return await render_template(request, "reset.html")

@router.post("/reset/stage2")
@csrf_protect
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

