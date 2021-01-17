from ..server_deps import *

import pyximport
pyximport.install()

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
    tags=["Authentication"],
)

# Models
class UserCredsEdit(TokenModel):
    operation: int
    new_username: Optional[str] = None
    password: str
    new_password: Optional[str] = None
    old_username: str

class UserCredsReset(BaseModel):
    operation: int
    username: Optional[str] = None
    email: Optional[str] = None
    reset_token: Optional[str] = None
    new_password: Optional[str] = None

class AuthLogin(UserPassModel):
    otp: Optional[str] = None

class AuthMFANew(TokenModel):
    operation: int

class AuthMFA(MFAModel):
    pass

class AuthLogoutRequest(BaseModel):
    username: str

class AuthRegisterRequest(UserPassModel):
    email: str

class AuthRecoveryRequest(BaseModel):
    backup_key: str

class AuthDeleteRequest(MFAModel):
    username: str

# Responses
class AuthLoginResponse(BRSRetResponse):
    pass

# Basic Functions

async def update_login_attempts(username: str, reset: bool) -> bool:
    attempts = await db.fetchrow("SELECT status, attempts FROM login WHERE username = $1", username)
    if attempts is None:
        return False # Username doesnt even exist
    elif reset:
        attempt = 0
    else:
        try:
            attempt = attempts["attempts"] + 1 # Increment attempts by 1
        except:
            attempt = 1
    await db.execute("UPDATE login SET attempts = $1 WHERE username = $2", attempt, username)
    if attempt > AUTH_LIMIT:
        # Disable the account now that we have passed the limit (need account recovery or password reset)
        if attempts["status"] not in [2, 3]:
            attempts = await db.execute("UPDATE login SET status = 3 WHERE username = $1", username)
        return True
            
    

@router.delete("/users")
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

@router.patch("/users/creds")
async def edit_account(request: UserCredsEdit, bt: BackgroundTasks):
    """
        Patch a users credentials given the operation, new_username, password, new_password and old_username, 1 = Username, 2 = Password
    """
    if request.operation not in [1, 2]:
        return brsret(code = "INVALID_OPERATION")
    elif request.operation == 1 and request.new_username is None:
        return brsret(code = "NO_USERNAME_PROVIDED")
    elif request.operation == 2 and request.new_password is None:
        return brsret(code = "NO_PASSWORD_PROVIDED")
    profile_db = await db.fetchrow(
        "SELECT mfa, mfa_shared_key, password FROM login WHERE token = $1 AND username = $2",
        request.token,
        request.old_username
    )
    if request.operation == 1:
        new_account_db = await db.fetchrow("SELECT username FROM login WHERE username = $1",request.new_username)
        if new_account_db is not None:
            return brsret(code = "USERNAME_TAKEN", html = "That username has been taken. Please choose another one")
    if profile_db is None:
        return brsret(code = "INVALID_PROFILE", html = "Invalid Profile.", support = True)
    if profile_db["password"] is None:
        # Invalid Username Or Password
        return brsret(code = "INVALID_USER_PASS", html = "Account Recovery is needed.", support = False)
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
    if request.operation == 1:
        password = hash_pwd(request.new_username, request.password)
        bt.add_task(edit_account_backend, "username", request.token, request.new_username, password, request.old_username)
        return brsret()
    elif request.operation == 2:
        password = hash_pwd(request.old_username, request.new_password)
        bt.add_task(edit_account_backend, "password", request.token, password)
        return brsret()

async def edit_account_backend(mode: str, token: str, new_data: str, password: Optional[str] = None, old_username: Optional[str] = None):
    if mode == "username":
        await db.execute(f"UPDATE login SET username = $1, password = $2 WHERE token = $3", new_data, password, token)
    elif mode == "password":
        await db.execute(f"UPDATE login SET password = $1 WHERE token = $2", new_data, token)

# Post new passwords (credentials) Send a reset email (stage2 auth)
@router.put("/users/creds", tags = ["Password Reset"])
async def reset_password_send(reset: UserCredsReset, background_tasks: BackgroundTasks):
    """
        Put new users credentials given the operation, username, email and operation
    """
    if reset.operation not in [1, 2]:
        return brsret(code = "INVALID_OPERATION")
    if operation == 1: # Password reset email send
        login_cred = await db.fetchrow("SELECT token, username, status, email FROM login WHERE (email = $1 OR username = $2) AND email IS NOT NULL AND username IS NOT NULL", reset.email)
        email = login_cred["email"]
        if (reset.email is None and reset.username is None) or login_cred is None:
            return brsret(code = "NO_ACCOUNT_FOUND")
        if login_cred["status"] == 2:
            return brsret(code = "ACCOUNT_DISABLED_TOS")
        flag = True  # Flag to check if we have a good reset token yet
        while flag:
            reset_token = get_token(101)
            if reset_token not in resetDict.values():
                flag = False
        resetDict[reset_token] = {"token": login_cred["token"], "username": login_cred['username'], "email": login_cred["email"]}
        # Now send an email to the user
        reset_link = SERVER_URL + "/reset/stage2?token=" + atok
        reset_message = f"Subject: CCTP Password Reset\n\nUsername {login_cred['username']}\nPlease use {reset_link} to reset your password.\n\nIf you didn't authorize this action, please change your password immediately"
        background_tasks.add_task(send_email, email, reset_message)
        return brsret(code = None)
    elif operation == 2: # Actual password change
        if reset.token not in resetDict.keys():
            # Reset Token Not Authorized
            return brsret(code = "NOT_AUTHORIZED")
        data = resetDict[reset.token]
        login_cred = await db.fetchrow("SELECT username FROM login WHERE token = $1", data["token"])
        if login_cred is None:
            return brsret(code = "NO_ACCOUNT_FOUND")
        username = login_cred["username"] 
        password = hash_pwd(username, reset.new_password)
        # Reset the token
        del resetDict[reset.token]
        flag = True
        while flag:
            new_token = uuid.uuid4()
            login_creds = await db.fetchrow("SELECT username from login WHERE token = $1", new_token)
            if login_creds is None:
                flag = False
        reset_message = "Subject: Your CCTP Password Was Just Reset\n\nYour CatPhi password was just reset\n\nIf you didn't authorize this action, please change your password immediately"
        # Add the two background tasks and return
        background_tasks.add_task(send_email, login_cred["email"], reset_message)
        background_tasks.add_task(reset_backend, password, token, new_token)
        return brsret()  # Success

# Background task to update db on reset
async def reset_backend(password: str, token: str, new_token: str):
    await db.execute("UPDATE login SET password = $1, token = $3 WHERE token = $2", password, token, new_token)
    await db.execute("UPDATE login SET status = 0 WHERE token = $1", new_token)

def send_email(email: str, reset_message: str = ""):
    email_session = smtplib.SMTP("smtp.gmail.com", 587)
    email_session.starttls()  # TLS for security
    email_session.login(SENDER_EMAIL, SENDER_PASS)  # Email Auth
    email_session.sendmail(SENDER_EMAIL, email, reset_message)
    email_session.close()

# This checks if the reset request is in resetDict and
# returns the result

@router.get("/users")
async def login(login: AuthLogin):
    """
    Posts a login to a user to CatPhi

    - **username**: Account Username
    - **password**: Account Password
    - **otp**: OTP
    \f
    :param username: User input.
    :param password: User input.
    :param otp: User input.
    """

    login_creds = await db.fetchrow(
        "SELECT attempts, token, status, scopes, password, mfa, mfa_shared_key from login WHERE username = $1",
        login.username
    )
    if login_creds is None:
        return brsret(code = "INVALID_USER_PASS", html = "Invalid username or password.", locked = False, support = False)
    elif verify_pwd(login.username, login.password, login_creds["password"]) == False:
        locked = await update_login_attempts(login.username, False)
        return brsret(code = "INVALID_USER_PASS", html = "Invalid username or password.", locked = locked, support = False)

    # Check for MFA
    elif login_creds["mfa"] is True:
        if login.otp is None:
            return brsret(code = "MFA", mfaChallenge = "mfa", mfaToken = token)
        mfa_shared_key = login_creds["mfa_shared_key"]
        otp = pyotp.TOTP(mfa_shared_key)
        if otp.verify(mfa.otp) is False:
            return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
    # Check status
    if login_creds["status"] in [None, 0]:
        pass
    else:
        # This account is flagged as disabled (1) or disabled-by-admin (2) or locked (3)
        return brsret(code = "ACCOUNT_DISABLED", status = login_creds["status"], attempts = login_creds["attempts"]) # Flagged Account

    locked = await update_login_attempts(login.username, True)
    return brsret(token = login_creds["token"], scopes = login_creds["scopes"])

@router.delete("/users/mfa", tags = ["MFA"])
async def multi_factor_authentication_disable(mfa: AuthMFA):
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


@router.patch("/users/mfa", tags = ["MFA"])
async def multi_factor_authentication_generate_shared_key(token: AuthMFANew):
    if operation not in [1, 2]:
        return brsret(code = "INVALID_OPERATION")
    if operation == 1:
        login_creds = await db.fetchrow("SELECT mfa_shared_key, status, email FROM login WHERE token = $1", token.token)
        if login_creds is None or login_creds["status"] not in [None, 0]:
            return brsret(code = "ACCOUNT_DISABLED_OR_DOES_NOT_EXIST") # Flagged or disabled account and/or account does not exist
        key = pyotp.random_base32() # MFA Shared Key
        mfaNewDict[token.token] = {"key": key, "email": login_creds["email"]}
        return brsret(code = None, key = key)
    if operation == 2:
        if mfa.token not in mfaNewDict.keys():
            return brsret(code = "FORBIDDEN", html = "Forbidden Request", support = True) # The other steps have not yet been done yet
        otp = pyotp.TOTP(mfaNewDict[mfa.token]["key"])
        if otp.verify(mfa.otp) is False:
            return brsret(code = "INVALID_OTP", html = "Invalid OTP. Please try again", support = False)
        await db.execute("UPDATE login SET mfa = $1, mfa_shared_key = $2 WHERE token = $3", True, mfaNewDict[mfa.token]["key"], mfa.token)
        background_tasks.add_task(send_email, mfaNewDict[mfa.token]["email"], f"Hi there\n\nSomeone has just tried to enable MFA on your account. If it wasn't you, please disable (and/or re-enable) MFA immediately using your backup code.\n\nThank you and have a nice day!")
        return brsret(code = None)

@router.post("/users/recovery")
async def account_recovery(account: AuthRecoveryRequest):
    """
        Recover an account using backup key
    """
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
        token = uuid.uuid4()
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


@router.put("/users")
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
        token = uuid.uuid4()
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
        "INSERT INTO login (token, username, password, email, status, scopes, mfa, backup_key, attempts) VALUES ($1, $2, $3, $4, 0, $5, $6, $7, 0);",
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
        "INSERT INTO profile (username, joindate, public, badges, level, items, listing) VALUES ($1, $2, $3, $4, $5, $6, $7);",
        username,
        date.today(),
        True,
        ["FIRST_TIME"],
        "apprentice",
        orjson.dumps({"experience": 0}).decode(),
        False
    )

