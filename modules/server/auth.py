from ..server_deps import *

# resetDict is a dictionary of password reset requests
# currently present
resetDict = {}

# mfaDict is a dictionary for MFA Logins
mfaDict = {}

# mfaNewDict is a dictionary for new MFA setup
mfaNewDict = {}

SENDER_EMAIL = "sandhoners123@gmail.com"
SENDER_PASS = "onsybsptaicdvtwc"


router = APIRouter(
    prefix="/auth",
    tags=["Authentication"],
)

# Models
class AuthUsernameEdit(MFAModel):
    old_username: str
    new_username: str
    password: str

class AuthPasswordEdit(MFAModel):
    username: str
    new_password: str
    old_password: str

class AuthResetRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None

class AuthResetChange(TokenModel):
    new_password: str

class AuthLoginRequest(UserPassModel):
    pass

class AuthMFANewRequest(TokenModel):
    pass

class AuthMFARequest(MFAModel):
    pass

class AuthLogoutRequest(BaseModel):
    username: str

class AuthRegisterRequest(UserPassModel):
    email: str

class AuthRecoveryRequest(BaseModel):
    backup_key: str

class AuthDeleteRequest(MFAModel):
    username: str

@router.post("/account/delete")
async def delete_account(request: AuthDeleteRequest, bt: BackgroundTasks):
    profile_db = await db.fetchrow(
        "SELECT mfa, mfa_shared_key FROM login WHERE token = $1 AND username = $2",
        request.token,
        request.username
    )
    if profile_db is None:
        return brsret(code = "INVALID_PROFILE")
    elif profile_db["mfa"] is True:
        if request.otp is None:
            return brsret(code = "MFA_NEEDED", mfaChallenge = "mfa")
        else:
            otp = pyotp.TOTP(profile_db["mfa_shared_key"])
            if otp.verify(request.otp) is False:
                return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    bt.add_task(delete_disable_account_backend, request.token, request.username)
    return brsret()

async def delete_disable_account_backend(token: str, username: str):
    # Delete the user from login and profile
    await db.execute("DELETE FROM login WHERE token = $1", token)
    await db.execute("DELETE FROM profile WHERE username = $1", username)
    await db.execute("DELETE FROM profile_topic WHERE username = $1", username)
    await db.execute("DELETE FROM topic_practice_tracker WHERE username = $1", username)

@router.post("/account/edit/username")
async def edit_account_username(request: AuthUsernameEdit, bt: BackgroundTasks):
    profile_db = await db.fetchrow(
        "SELECT mfa, mfa_shared_key, password FROM login WHERE token = $1 AND username = $2",
        request.token,
        request.old_username
    )
    new_account_db = await db.fetchrow(
        "SELECT username FROM login WHERE username = $1",
        request.new_username
    )
    if profile_db is None:
        return brsret(code = "INVALID_PROFILE", html = "Invalid Profile.", support = True)
    if new_account_db is not None:
        return brsret(code = "USERNAME_TAKEN", html = "That username has been taken. Please choose another one")
    if profile_db["password"] is None:
        # Invalid Username Or Password
        return brsret(code = "INVALID_USER_PASS", html = "Account Recovery is needed.", support = False)
    print(verify_pwd(request.old_username, request.password, profile_db["password"]))
    if verify_pwd(request.old_username, request.password, profile_db["password"]) == False:
        return brsret(code = "INVALID_USER_PASS", html = "Invalid username or password.", support = False)
    if profile_db["mfa"] is True:
        if request.otp is None:
            return brsret(code = "MFA_NEEDED", mfaChallenge = "mfa", html = "MFA is needed")
        else:
            otp = pyotp.TOTP(profile_db["mfa_shared_key"])
            if otp.verify(request.otp) is False:
                return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    # Rehash the password
    password = hash_pwd(request.new_username, request.password)
    bt.add_task(edit_account_backend, "username", request.token, request.new_username, password, request.old_username)
    return brsret()

@router.post("/account/edit/password")
async def edit_account_password(request: AuthPasswordEdit, bt: BackgroundTasks):
    profile_db = await db.fetchrow(
        "SELECT mfa, mfa_shared_key, password FROM login WHERE token = $1 AND username = $2",
        request.token,
        request.username
    )
    if profile_db is None:
        return brsret(code = "INVALID_PROFILE", html = "Invalid Profile.", support = True)
    if profile_db["password"] is None:
        # Invalid Username Or Password
        return brsret(code = "INVALID_USER_PASS", html = "Account Recovery is needed.", support = False)
    if verify_pwd(request.username, request.old_password, profile_db["password"]) is False:
        return brsret(code = "INVALID_USER_PASS", html = "Invalid username or password.", support = False)
    if profile_db["mfa"] is True:
        if request.otp is None:
            return brsret(code = "MFA_NEEDED", mfaChallenge = "mfa")
        else:
            otp = pyotp.TOTP(profile_db["mfa_shared_key"])
            if otp.verify(request.otp) is False:
                return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    # Rehash the password
    password = hash_pwd(request.username, request.new_password)
    bt.add_task(edit_account_backend, "password", request.token, password)
    return brsret()


async def edit_account_backend(mode: str, token: str, new_data: str, password: Optional[str] = None, old_username: Optional[str] = None):
    if mode == "username":
        await db.execute(f"UPDATE login SET username = $1, password = $2 WHERE token = $3", new_data, password, token)
        await db.execute("UPDATE profile SET username = $1 WHERE username = $2", new_data, old_username)
        await db.execute("UPDATE profile_topic SET username = $1 WHERE username = $2", new_data, old_username)
        await db.execute("UPDATE topic_practice_tracker SET username = $1 WHERE username = $2", new_data, old_username)
    elif mode == "password":
        await db.execute(f"UPDATE login SET password = $1 WHERE token = $2", new_data, token)

# Send a reset email (stage2 auth)
@router.post("/reset/send", tags = ["Password Reset"])
async def reset_password_send(reset: AuthResetRequest, background_tasks: BackgroundTasks):
    if reset.username is None and reset.email is not None:
        login_cred = await db.fetchrow(
            "SELECT token, username FROM login WHERE email = $1", reset.email
        )
        if login_cred is None:
            # Invalid Username Or Password
            return brsret(code = "INVALID_EMAIL")

        email = reset.email
    elif reset.email is None and reset.username is not None:
        login_cred = await db.fetchrow(
            "SELECT token, username, email from login WHERE username = $1", reset.username
        )

        if login_cred is None:
            # Invalid Username Or Password
            return brsret(code = "INVAALID_USERNAME")

        email = login_cred["email"]
    else:
            # Invalid Username Or Password
            return brsret("NO_USERNAME_OR_EMAIL_PROVIDED")

    url_flag = True  # Flag to check if we have a good url id yet
    while url_flag:
        atok = get_token(101)
        if atok not in resetDict.values():
            url_flag = False
    resetDict[login_cred["token"]] = atok
    # Now send an email to the user
    reset_link = SERVER_URL + "/reset/stage2?token=" + atok
    reset_message = f"Subject: CCTP Password Reset\n\nUsername {login_cred['username']}\nPlease use {reset_link} to reset your password.\n\nIf you didn't authorize this action, please change your password immediately"
    background_tasks.add_task(send_email, email, reset_message)
    return brsret(code = None)

def send_email(email: str, reset_message: str = ""):
    email_session = smtplib.SMTP("smtp.gmail.com", 587)
    email_session.starttls()  # TLS for security
    email_session.login(SENDER_EMAIL, SENDER_PASS)  # Email Auth
    email_session.sendmail(SENDER_EMAIL, email, reset_message)
    email_session.close()


# Change the actual password (stage3 auth)
@router.post("/reset/change", tags = ["Password Reset"])
async def reset_password_change(reset: AuthResetChange, background_tasks: BackgroundTasks):
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
    password = hash_pwd(username, reset.new_password)
    # Make sure we cant use the same token again
    resetDict[token] = None

    # Get a new token on reset
    flag = True
    while flag:
        # Keep getting and checking token with DB
        new_token = get_token(1037)
        login_creds = await db.fetchrow(
            "SELECT username from login WHERE token = $1", new_token
        )
        if login_creds is not None:
            continue
        flag = False
    reset_message = "Subject: Your CCTP Password Was Just Reset\n\nYour CatPhi password was just reset\n\nIf you didn't authorize this action, please change your password immediately"
    # Add the two background tasks and return
    background_tasks.add_task(send_email, login_cred["email"], reset_message)
    background_tasks.add_task(reset_backend, password, token, new_token)
    return {"error": "1000"}  # Success

# Background task to update db on reset
async def reset_backend(password: str, token: str, new_token: str):
    await db.execute("UPDATE login SET password = $1, token = $3 WHERE token = $2", password, token, new_token)
    await db.execute("UPDATE login SET status = 0 WHERE token = $1", new_token)


# This checks if the reset request is in resetDict and
# returns the result


@router.get("/reset/check/token", tags = ["Password Reset"])
async def check_reset_token(token: str = None):
    if token is None or token not in resetDict.values():
        return brsret(code = False)
    return brsret(code = True)


@router.post("/login", tags = ["Authentication"])
async def login(login: AuthLoginRequest):
    if login.username is None or login.password is None:
        return brsret(code = "INVALID_USER_PASS", html = "Invalid username or password.", support = False)
    pwd = await db.fetchrow(
        "SELECT password, mfa from login WHERE username = $1",
        login.username
    )
    if pwd is None:
        # Invalid Username Or Password
        return brsret(code = "INVALID_USER_PASS", html = "Invalid username or password.", support = False)

    elif verify_pwd(login.username, login.password, pwd["password"]) == False:
        return brsret(code = "INVALID_USER_PASS", html = "Invalid username or password.", support = False)

    # Check for MFA
    elif pwd["mfa"] is True:
        flag = True
        while flag:
            token = get_token(101)
            if token not in mfaDict.values() and token not in mfaDict.keys():
                flag = False
        mfaDict[token] = login.username
        return brsret(mfaChallenge = "mfa", mfaToken = token)

    login_creds = await db.fetchrow(
        "SELECT token, status, scopes from login WHERE username = $1",
        login.username,
    )
    if login_creds is None:
        return {"error": "1001"}
    if login_creds["status"] in [None, 0]:
        pass
    else:
        # This account is flagged as disabled (1) or disabled-by-admin (2)
        return brsret(code = "ACCOUNT_DISABLED", status = login_creds["status"]) # Flagged Account
    return brsret(token = login_creds["token"], scopes = login_creds["scopes"])


@router.post("/mfa", tags = ["MFA"])
async def multi_factor_authentication(mfa: AuthMFARequest):
    if mfa.token not in mfaDict.keys():
        return brsret(code = "FORBIDDEN", html = "Forbidden Request<br/>Try logging out and back in again", support = True) # Forbidden as mfa token is wrong
    login_creds = await db.fetchrow(
        "SELECT mfa_shared_key, token, status, scopes FROM login WHERE username = $1",
        mfaDict[mfa.token],
    )
    if login_creds is None or login_creds["mfa_shared_key"] is None:
        return brsret(code = "MFA_NOT_FOUND", html = "No MFA Shared Key was found.", support = True)
    mfa_shared_key = login_creds["mfa_shared_key"]
    otp = pyotp.TOTP(mfa_shared_key)
    if otp.verify(mfa.otp) is False:
        return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    del mfaDict[mfa.token]
    if login_creds["status"] in [None, 0]:
        pass
    else:
        # This account is flagged as disabled (1) or disabled-by-admin (2)
        return brsret(code =  "ACCOUNT_DISABLED", status = login_creds["status"]) # Flagged or disabled account
    return brsret(token = login_creds["token"], scopes = login_creds["scopes"])


@router.post("/mfa/disable", tags = ["MFA"])
async def multi_factor_authentication_disable(mfa: AuthMFARequest):
    login_creds = await db.fetchrow(
        "SELECT mfa_shared_key FROM login WHERE token = $1",
        mfa.token,
    )
    if login_creds is None or login_creds["mfa_shared_key"] is None:
        return brsret(code = "MFA_NOT_FOUND", html = "No MFA Shared Key was found.", support = True)
    mfa_shared_key = login_creds["mfa_shared_key"]
    otp = pyotp.TOTP(mfa_shared_key)
    if otp.verify(mfa.otp) is False:
        return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    await db.execute("UPDATE login SET mfa = $1 WHERE token = $2", False, mfa.token)
    return brsret(code = None)


@router.post("/mfa/setup/1", tags = ["MFA"])
async def multi_factor_authentication_generate_shared_key(token: AuthMFANewRequest):
    login_creds = await db.fetchrow(
            "SELECT mfa_shared_key, status, email FROM login WHERE token = $1",
        token.token,
    )
    if login_creds is None or login_creds["status"] not in [None, 0]:
        return brsret(code = "ACCOUNT_DISABLED_OR_DOES_NOT_EXIST") # Flagged or disabled account and/or account does not exist
    key = pyotp.random_base32() # MFA Shared Key
    mfaNewDict[token.token] = {"key": key, "email": login_creds["email"]}
    return brsret(code = None, key = key)


@router.post("/mfa/setup/2", tags = ["MFA"])
async def multi_factor_authentication_enable(mfa: AuthMFARequest, background_tasks: BackgroundTasks):
    if mfa.token not in mfaNewDict.keys():
        return brsret(code = "FORBIDDEN", html = "Forbidden Request", support = True) # The other steps have not yet been done yet
    otp = pyotp.TOTP(mfaNewDict[mfa.token]["key"])
    if otp.verify(mfa.otp) is False:
        return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    await db.execute("UPDATE login SET mfa = $1, mfa_shared_key = $2 WHERE token = $3", True, mfaNewDict[mfa.token]["key"], mfa.token)
    background_tasks.add_task(send_email, mfaNewDict[mfa.token]["email"], f"Hi there\n\nSomeone has just tried to enable MFA on your account. If it wasn't you, please disable (and/or re-enable) MFA immediately using your backup code.\n\nThank you and have a nice day!")
    return brsret(code = None)


@router.post("/recovery")
async def account_recovery(account: AuthRecoveryRequest):
    login_creds = await db.fetchrow(
        "SELECT username, status FROM login WHERE backup_key = $1",
        account.backup_key,
    )
    if login_creds is None:
        return brsret(code = "INVALID_BACKUP_CODE", html = "Invalid Backup Code. Please try again", support = False)
    elif login_creds["status"] == 2:
        return brsret(code = "ACCOUNT_DISABLED", html = "Your account has been disabled by an administrator for violating our policies.", support = True)

    flag = True
    while flag:
        # Keep getting and checking token with DB (new token)
        token = get_token(1037)
        __login_creds = await db.fetchrow(
            "SELECT username from login WHERE token = $1", token
        )
        if __login_creds is not None:
            continue
        flag = False

    # Create new account recovery code/backup key
    flag = True
    while flag:
        backup_key = ""
        for i in range(0, 3):
            backup_key += pyotp.random_hex()
        __login_creds = await db.fetchrow(
            "SELECT username from login WHERE backup_key = $1", backup_key
        )
        if __login_creds is not None:
            continue
        flag = False

    def_password = pyotp.random_hex()
    def_password_hashed = hash_pwd(login_creds["username"], def_password)
    await db.execute("UPDATE login SET mfa = $1, password = $3, token = $4, backup_key = $5, status = 0 WHERE backup_key = $2", False, account.backup_key, def_password_hashed, token, backup_key)
    return brsret(code = None, html = f"Your account has successfully been recovered.<br/>Username: {login_creds['username']}<br/>Temporary Password: {def_password}<br/>New Backup Key: {backup_key}<br/>Change your password as soon as you login")


@router.post("/register")
async def register(register: AuthRegisterRequest, background_tasks: BackgroundTasks):
    username = register.username
    password = hash_pwd(username, register.password)
    email = register.email
    login_creds = await db.fetchrow(
        "SELECT token from login WHERE username = $1 OR email = $2", username, email
    )
    if login_creds is not None:
        # That username or email is in use
        return brsret(code = "USERNAME_OR_EMAIL_IN_USE", html = "That username or email is currently in use. Please try using another one")
    flag = True
    while flag:
        # Keep getting and checking token and account backup key with DB
        token = get_token(1037)
        backup_key = ""
        for i in range(0, 3):
            backup_key += pyotp.random_hex()
        login_creds = await db.fetchrow(
            "SELECT username from login WHERE token = $1 OR backup_key = $2",
            token,
            backup_key
        )
        if login_creds is not None:
            continue
        flag = False

    # Registration Validation Was Successful. Add the background task to add the user to the database and exit
    background_tasks.add_task(register_backend, token, username, password, email, backup_key)
    return brsret(code = None, token = token, backup_key = backup_key)


async def register_backend(token: str, username: str, password: str, email: str, backup_key: str):
    await db.execute(
        "INSERT INTO login (token, username, password, email, status, scopes, mfa, backup_key) VALUES ($1, $2, $3, $4, 0, $5, $6, $7);",
        token,
        username,
        password,
        email,
        "user",
        False,
        backup_key
    )
    # Register their join date and add the first time registration badge
    await db.execute(
        "INSERT INTO profile (username, joindate, public, badges, level, items) VALUES ($1, $2, $3, $4, $5, $6);",
        username,
        date.today(),
        True,
        "FIRST_TIME",
        "apprentice",
        "experience:0",
    )

