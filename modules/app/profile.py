from ..app_deps import *

router = APIRouter(
    prefix="/profile",
    tags=["Core"],
)

@router.get("/me/")
@router.get("/me")
async def profile_me(request: Request):
    if request.session.get("token") == None or request.session.get("username") == None:
        request.session["redirect"] = "/profile/me"
        return redirect("/login")
    return redirect("/profile/" + request.session.get("username"))

@router.get("/{username}")
async def profile(request: Request, username: str):
    if request.session.get("token") == None:
        profile = requests.get(api + "/profile?username=" + username).json()
    else:
        profile = requests.get(
            api + "/profile?username=" + username + "&token=" + request.session.get("token")
        ).json()
    if profile.get("code") in ["PRIVATE_PROFILE", "INVALID_PROFILE"]:
        return await render_template(
            request,
            "generic_error.html",
            header="Profile Error",
            error="Profile either does not exist or is still being updated on our databases. Please check back in a few minutes once our databases are fully up to date.",
        )

    profile_owner = (request.session.get("username") == username or request.session.get("admin") == 1)
    private = profile['private']
    if not private:
        private = "Public"
    else:
        private = "Private"

    return await render_template(
        request,
        "profile.html",
        p_username = profile["username"],
        p_capusername = profile["username"].capitalize(),
        p_admin = request.session.get("admin"),
        admin = "admin" in profile["scopes"].split(":"),
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

@router.get("/{username}/me/profile/delete")
async def profile_delete_get(request: Request, username: str):
    return await render_template(request, "delete_account.html")

@router.post("/{username}/me/profile/delete")
@csrf_protect
async def profile_delete_get(request: Request, username: str, otp: str = FastForm("")):
    if request.session.get("mfa_delaccount") is None:
        rc = requests.post(api + "/auth/account/delete", json = {
            "username": username,
            "token": request.session.get("token")
        }).json()
        if rc["code"] == "MFA_NEEDED":
            request.session["mfa_delaccount"] = True
            return await render_template(request, "mfa.html", mode = "delete")
        elif rc["code"] != None:
            return await render_template(request, "mfa.html", mode = "delete", error = Markup(rc.get("html")))
    else:
        rc = requests.post(api + "/auth/account/delete", json = {
            "username": username,
            "token": request.session.get("token"),
            "otp": otp
        }).json()
        if rc["code"] is not None:
            return await render_template(request, "mfa.html", mode = "delete", error = Markup(rc.get("html")))
        del request.session["mfa_delaccount"]
    return redirect("/logout")

@router.post("/{username}/me/state")
@csrf_protect
async def profile_state_set(request: Request, username: str, state: str = FastForm("public")):
    if state not in ["public", "private", "disable", "enable", "disable_admin"]:
        return abort(400)
    elif request.session.get("token") is not None and (username == request.session.get("username") or request.session.get("admin") == 1):
        pass
    else:
        return abort(401)

    post_data = {
        "state": state,
        "username": username,
        "token": request.session.get("token"),
    }

    if state == "disable_admin":
        post_data["state"] = "disable"
        post_data["disable_state"] = 2

    x = requests.post(
        api + "/profile/visible",
        json=post_data
        ).json()
    if state == "disable":
        return redirect("/logout")
    return redirect("/profile/" + username + "/settings")

@router.post("/{username}/me/list")
@csrf_protect
async def profile_state_set(request: Request, username: str, state: str = FastForm("enable")):
    if state not in ["enable", "disable"]:
        return abort(404)

@router.post("/{username}/me/token")
@csrf_protect
async def profile_token_view(request: Request, username: str, confirm: str = FastForm("IDontKnowWhatIAmDoingTho:(")):
    expected_value = f"YesIKnowWhatIAmDoing2020AndIAmSureIWishToDoThisInRealLifePleaseDontDoThisUnlessYouAreDoingThisToFillOutTheCustomerSupportFormThanksBro{username}:)"
    print(expected_value, confirm)
    if expected_value.replace(" ", "") == confirm.replace(" ", ""):
        return await render_template(request, "token.html", mode = 1, api = api, token = request.session.get("token"))
    else:
        return await render_template(request, "token.html", mode = 0)
@router.get("/{username}/me/account/{type}/change")
async def profile_change_username_get(request: Request, username: str, type: str):
    try:
        del request.session["mfa_editaccount"]
    except:
        pass
    return await render_template(request, "edit_account.html", mode = type)

@router.post("/{username}/me/account/{type}/change")
@csrf_protect
async def profile_change_username_post(request: Request, username: str, type: str, current_password: str = FastForm(None), new_username: str = FastForm("username"), new_password: str = FastForm("password"), otp: str = FastForm(None)):
    if username != request.session.get("username"):
        return abort(401)
    if request.session.get("mfa_editaccount") is None:
        if type == "username":
            rc = requests.post(api + "/auth/account/edit/username", json = {
                "old_username": username,
                "new_username": new_username,
                "token": request.session.get("token"),
                "password": current_password
            }).json()
        elif type == "password":
            rc = requests.post(api + "/auth/account/edit/password", json = {
                "username": username,
                "new_password": new_password,
                "token": request.session.get("token"),
                "old_password": current_password
            }).json()
        else:
            rc = {"code": "ERROR", "html": "Invalid Type"}

        if rc["code"] == "MFA_NEEDED":
            request.session["mfa_editaccount"] = [type, current_password, new_username, new_password]
            return await render_template(request, "mfa.html", mode = type)
    elif request.session.get("mfa_editaccount") is None and rc["code"] != None:
        return await render_template(request, "edit_account.html", mode = type, error = Markup(rc.get("html")))
    elif request.session.get("mfa_editaccount") is not None:
        if request.session["mfa_editaccount"][0] == "username":
            new_username = request.session["mfa_editaccount"][2]
            rc = requests.post(api + "/auth/account/edit/username", json = {
                "old_username": username,
                "new_username": request.session["mfa_editaccount"][2],
                "token": request.session.get("token"),
                "password": request.session["mfa_editaccount"][1],
                "otp": otp
            }).json()
        elif request.session["mfa_editaccount"][0] == "password":
            rc = requests.post(api + "/auth/account/edit/password", json = {
                "username": username,
                "new_password": request.session["mfa_editaccount"][3],
                "token": request.session.get("token"),
                "old_password": request.session["mfa_editaccount"][1],
                "otp": otp
            }).json()
    if rc["code"] != None:
        if rc["code"] == "INVALID_USER_PASS":
            return await render_template(request, "edit_account.html", mode = "username", error = Markup(rc.get("html")))
        return await render_template(request, "mfa.html", mode = "edit", error = Markup(rc.get("html")))
    if type == "username":
        request.session["username"] = new_username
    try:
        del request.session["mfa_editaccount"]
    except:
        pass
    await asyncio.sleep(3) # Give the db three seconds to update
    return redirect("/profile/" + request.session["username"] + "/settings")

@router.get("/{username}/me/mfa/{state}")
async def profile_mfa_set_get(request: Request, username: str, state: str):
    if username != request.session.get("username"):
        return abort(401)
    elif state not in ["enable", "disable"]:
        return abort(404)

    if state == "enable":
        rc = requests.post(api + "/auth/mfa/setup/1", json = {
            "token": request.session.get("token")
        }).json()
        if rc["code"] != None:
            request.session["status_code"] = 400
            return await render_template(request, "mfa.html", mode = "setup", error = Markup(rc["html"]), key = request.session["mfa_key"])
        request.session["mfa_key"] = rc["context"]["key"]
        return await render_template(request, "mfa.html", mode = "setup", key = rc["context"]["key"])

    elif state == "disable":
        return await render_template(request, "mfa.html", mode = "disable")

@router.post("/{username}/me/mfa/{state}")
@csrf_protect
async def profile_mfa_set_post(request: Request, username: str, state: str, otp: str = FastForm("")):
    if state == "enable":
        rc = requests.post(api + "/auth/mfa/setup/2", json = {
            "token": request.session.get("token"),
            "otp": otp
        }).json()
        if rc["code"] != None:
            request.session["status_code"] = 400
            return await render_template(request, "mfa.html", mode = "setup", error = Markup(rc["html"]), key = request.session["mfa_key"])
        del request.session["mfa_key"]
        return redirect("/profile/" + username + "/settings")
    elif state == "disable":
        rc = requests.post(api + "/auth/mfa/disable", json = {
            "token": request.session.get("token"),
            "otp": otp
        }).json()
        if rc["code"] != None:
            request.session["status_code"] = 400
            return await render_template(request, "mfa.html", mode = "disable", error = Markup(rc["html"]))
        return redirect("/profile/" + username + "/settings")

@router.get("/{username}/settings")
async def settings(request: Request, username: str):
    if request.session.get("username") != username and request.session.get("admin") != 1:
        return abort(401)

    profile = requests.get(
        api + "/profile?username=" + username + "&token=" + request.session.get("token")
    ).json()
    if profile.get("code") in ["PRIVATE_PROFILE", "INVALID_PROFILE"]:
        return await render_template(
            request,
            "generic_error.html",
            header="Profile Error",
            error="This profile is private or does not exist yet/is being updated. Please wait for our databases to be updated",
        )
    priv = profile['private']
    mfa = profile["mfa"]
    if int(priv) == 0:
        priv = "Public"
    else:
        priv = "Private"
    return await render_template(
        request,
        "profile_settings.html",
        p_username=profile["username"],
        token=request.session.get("token"),
        private = priv,
        mfa = profile["mfa"]
    )

