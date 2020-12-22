from ..server_deps import *

# Badge Data
# Format is bid = {name: Name of the badge, image: Image URL to the badge, experience: Experience needed to get the badge}.
# To make sure it works on older clients, send the entire BADGES dict in a badge request

BADGES = {
    "FIRST_TIME": {
        "name": "Welcome To CatPhi!!!",
        "description": "Thank you for registering with CatPhi",
        "image": "https://interactive-examples.mdn.mozilla.net/media/cc0-images/grapefruit-slice-332-332.jpg",
        "experience": 0
    },
    "FIRST_BADGE": {
        "name": "First Badge",
        "description": "It's your first badge! Enjoy!!!!",
        "image": "https://cdn.pixabay.com/photo/2015/04/23/22/00/tree-736885__340.jpg",
        "experience": 10,
    },
    "APPRENTICE_I": {
        "name": "CatPhi Apprentice I",
        "description": "Congratulations on your first accomplishment as an apprentice",
        "image": "https://cdn.pixabay.com/photo/2015/04/23/22/00/tree-736885__340.jpg",
        "experience": 40,
    },
    "APPRENTICE_II": {
        "name": "CatPhi Apprentice II",
        "description": "Your almost a warrior now.",
        "image": "https://cdn.pixabay.com/photo/2015/04/23/22/00/tree-736885__340.jpg",
        "experience": 90,
    },
}

RANKS = {
    "leader": {
        "name": "Leader",
        "desc": "A CatPhi Leader. They make sure that CatPhi works correctly and they handle the entire website including the backend!<br/><strong><em>Not much else is known about them...</strong></em>",
    },
    "apprentice": {
        "name": "Apprentice",
        "desc": "A new explorer arrives... It's OK! Everone has to start somewhere!",
        "levelup": 100,
        "next": "young_warrior"
    },
    "young_warrior": {
        "name": "Young Warrior",
        "desc": "TODO",
        "levelup": 600,
        "next": "TODO"
    }
}

ITEMS = {
    "experience": {
        "name": "Experience Points",
        "desc": "A rare mystical substance found in the land of CatPhi that can do some magical and mysterious things. You can earn these from the Witches Of CatPhi by doing more topics and solving more practice questions<br/><strong><em>There is no other known way to get these...</strong></em>",
        "display": "<i class='fas fa-magic' style='margin-right: 3px'></i>",
        "special_effects": {
            "levelup:young_warrior": 100
        }
    },
}

# Get all new badges given a current set of badges and the new exp_point value
def get_new_badges(curr_badges, exp_points):
    new_badges = []
    for badge in BADGES.keys():
        if badge in curr_badges:
            continue # Ignore badges we already have
        if int(BADGES[badge]["experience"]) <= int(exp_points):
            new_badges.append(badge)
    return "||".join(new_badges), "||".join(curr_badges.split("||") + new_badges)

router = APIRouter(
    prefix="/profile",
    tags=["Profile"],
)

# Profile Models

class ProfileListingRequest(UserModel):
    state: str

class ProfileVisibleRequest(UserModel):
    state: str
    disable_state: Optional[int] = None

class ProfileTrackWriter(UserModel):
    tid: str
    status: str
    cid: int

class ProfileTrackPracticeWriter(UserModel):
    tid: str
    qid: int
    answer: str
    lives: str
    path: str

# Profile
@router.post("/visible")
async def change_visibility(pvr: ProfileVisibleRequest):
    # This includes account disabling which is also changing the visibility as well
    if pvr.state not in ["public", "private", "disable", "enable"]:
        return brsret(code = "INVALID_VISIBILITY", html = "Only public, private, disable and enable are allowed")
    usertok = await db.fetchrow("SELECT username, scopes FROM login WHERE token = $1", pvr.token)
    if usertok is None:
        return brsret(code = "INVALID_TOKEN")
    is_admin = ("admin" in usertok["scopes"].split(":"))
    # Check if username and token match
    if(usertok["username"] == pvr.username or is_admin):
        pass
    else:
        return brsret(code = "FORBIDDEN")

    # For account disabling, set state to private and flag account as disabled
    if pvr.state == "disable":
        state = "private" # Make the profile private on disable
        if pvr.disable_state is not None and is_admin:
            status = int(pvr.disable_state) # Admin disable
        else:
            status = 1
        await db.execute(
            "UPDATE login SET status = $1 WHERE username = $2", status, pvr.username
        )

    # For account re-enabling, first make sure the state is not 2 (admin disable) unless the user doing this is an admin
    elif pvr.state == "enable":
        status = await db.fetchrow(
            "SELECT status, scopes FROM login WHERE username = $1", pvr.username
        )
        if status is None or scopes is None:
            return brsret(code = "INTERNAL_DATABASE_ERROR", html = "Something's went wrong.", support = True)

        status = status["status"]
        if int(status) == 2:
            if "admin" in status["scopes"].split(":"): # Admin check
                pass
            else:
                return {"error": "1002"} # Only admins can reinstate state 2 disables
        await db.execute(
            "UPDATE login SET status = 0 WHERE username = $1", pvr.username # Re-enable the account now
        )
        return brsret(code = None)


    elif pvr.state in ["public", "private"]:
        visible = bool(pvr.state == "public")
        await db.execute(
            "UPDATE profile SET public = $1 WHERE username = $2", visible, pvr.username
        )
        return brsret(code = None)

@router.post("/listing")
async def profile_listing(plr: ProfileListingRequest):
    pass

@router.get("/")
async def get_profile(username: str, token: str = None):
    # Get the profile
    profile_db = await db.fetchrow(
        "SELECT profile.public, profile.joindate, profile.badges, profile.level, profile.items, login.scopes, login.mfa FROM profile INNER JOIN login ON profile.username = login.username WHERE profile.username = $1",
        username,
    )
    if profile_db is None:
        return brsret(code = "INVALID_PROFILE")
    elif not profile_db["public"]:
        private = True
        if token is None:
            return brsret(code = "PRIVATE_PROFILE")
        usertok = await db.fetchrow("SELECT username, scopes FROM login WHERE token = $1", token) # Get User Scopes
        if "admin" in usertok["scopes"].split(":") or usertok["username"] == username:
            pass
        else:
            return brsret(code = "PRIVATE_PROFILE")
    else:
        private = False
    join_obj = profile_db['joindate']

    # Format date
    day = join_obj.strftime("%-d")
    day = inflect_engine.ordinal(day)
    year = join_obj.strftime("%Y")
    month = join_obj.strftime("%-B")
    join = " ".join((month, day + ",", year))

    # Get badge URLs
    badges = {}
    for badge in profile_db["badges"].split("||"):
        try:
            badges[badge] = {"name": BADGES[badge]["name"], "image": BADGES[badge]["image"], "experience": BADGES[badge]["experience"], "description": BADGES[badge]["description"]}
        except:
            continue # Illegal badge

    # Get rank
    if "admin" in profile_db["scopes"].split(":"):
        level = RANKS["leader"]
        levelup_name = None
    else:
        level = RANKS[profile_db["level"]]
        levelup_name = RANKS[level["next"]]["name"]

    # Get items
    idict = []
    i = 0
    for item_obj in profile_db["items"].split("||"):
        item = item_count = item_obj.split(":")[0]
        item_count = item_obj.split(":")[1]
        idict.append({})
        idict[i] = ITEMS[item]
        idict[i]["internal_name"] = item
        idict[i]["count"] = int(item_count)
        i+=1

    mfa = profile_db['mfa']
    mfa = (mfa == True)

    return {
            "username": username,
            "scopes": profile_db["scopes"],
            "join": join,
            "private": private,
            "mfa": mfa,
            "badges": badges,
            "level": level,
            "levelup_name": levelup_name,
            "items": idict
    }

# Track users progress
# TODO: Add quizzes and other things
@router.post("/track")
async def profile_track_writer(tracker: ProfileTrackWriter):
    # First check if the user and token even exist
    profile_db = await db.fetchrow("SELECT mfa FROM login WHERE username = $1 AND token = $2", tracker.username, tracker.token)
    if profile_db is None:
        return brsret(code = "USER_DOES_NOT_EXIST")
    mode = 0 # Do nothing mode
    entry = await db.fetchrow("SELECT profile_topic.done, profile.badges, profile.items FROM profile_topic RIGHT JOIN profile ON profile_topic.username=profile.username WHERE profile_topic.tid = $1 AND profile.username = $2", tracker.tid, tracker.username)
    if entry is None:
        mode = 1 # Don't update, use insert statement mode
    elif entry["done"] is not True:
        mode = 2 # Update mode
    if mode == 1:
        await db.execute("INSERT INTO profile_topic (username, tid, progress, done) VALUES ($1, $2, $3, $4)", tracker.username, tracker.tid, tracker.status + str(tracker.cid), False)
        entry = await db.fetchrow("SELECT profile_topic.done, profile.badges, profile.items FROM profile_topic RIGHT JOIN profile ON profile_topic.username=profile.username WHERE profile_topic.tid = $1 AND profile.username = $2", tracker.tid, tracker.username)
    elif mode == 2:
        await db.execute("UPDATE profile_topic SET progress = $3 WHERE username = $1 AND tid = $2", tracker.username, tracker.tid, tracker.status + str(tracker.cid))
    elif mode == 0:
        return brsret(code = None, debug = mode)

    item_list = []
    for item in entry["items"].split("||"):
        if item.split(":")[0] != "experience":
            item_list.append(item)
            continue
        exp_points = str(int(item.split(":")[1]) + 10) # 10 new experience points per page
        item_list.append("experience:" + exp_points)
        break
    items = "||".join(item_list)
    exp_points = int(exp_points)
    # Get all the new badges a user has unlocked
    new_badges = get_new_badges(entry["badges"], exp_points)
    if new_badges[0] == '':
        await db.execute("UPDATE profile SET items = $2 WHERE username = $1", tracker.username, items)
        return brsret(code = None, debug = mode)
    await db.execute("UPDATE profile SET badges = $2, items = $3 WHERE username = $1", tracker.username, new_badges[1], items)
    return brsret(code = None, debug = mode, items = items, new_badges = new_badges[0])


@router.get("/track")
async def profile_track_reader(tid: str, username: str):
    info = await db.fetchrow("SELECT progress, done FROM profile_topic WHERE username = $1 AND tid = $2", username, tid) # Get the page info
    if info is None or info["progress"] is None:
        return brsret(
            status = "LP", # Default State is LP
            cid = 1,
            done = False,
        )
    status = info["progress"][0] + info["progress"][1]
    cid = info["progress"][2:]
    done = info["done"]
    if done is not True:
        done = False
    else:
        done = True
    return brsret(
        status = status,
        cid = cid,
        done = done,
    )
    return brsret(code = "INVALID_ARGUMENTS")  # Invalid arguments (Default)

@router.post("/track/practice")
async def profile_track_writer(tracker: ProfileTrackPracticeWriter):
    profile_db = await db.fetchrow("SELECT mfa FROM login WHERE username = $1 AND token = $2", tracker.username, tracker.token)
    if profile_db is None:
        return brsret(code = "USER_DOES_NOT_EXIST")
    mode = 0 # Do nothing mode
    entry = await db.fetchrow("SELECT profile_topic.done, profile.badges, profile.items FROM profile_topic RIGHT JOIN profile ON profile_topic.username=profile.username INNER JOIN topic_practice_tracker ON profile.username=topic_practice_tracker.username WHERE topic_practice_tracker.tid = $1 AND topic_practice_tracker.username = $2 AND topic_practice_tracker.qid = $3", tracker.tid, tracker.username, tracker.qid)
    if entry is None:
        mode = 1 # Don't update, use insert statement mode
    elif entry["done"] is not True:
        mode = 2 # Update mode
    if mode == 1:
        await db.execute("INSERT INTO topic_practice_tracker (username, tid, qid, answer, lives, path) VALUES ($1, $2, $3, $4, $5, $6)", tracker.username, tracker.tid, tracker.qid, tracker.answer, tracker.lives, tracker.path)
        entry = await db.fetchrow("SELECT profile_topic.done, profile.badges, profile.items FROM profile_topic RIGHT JOIN profile ON profile_topic.username=profile.username INNER JOIN topic_practice_tracker ON profile.username=topic_practice_tracker.username WHERE topic_practice_tracker.tid = $1 AND topic_practice_tracker.username = $2 AND topic_practice_tracker.qid = $3", tracker.tid, tracker.username, tracker.qid)
    elif mode == 2:
        await db.execute("UPDATE topic_practice_tracker SET answer = $4, lives = $5, path = $6 WHERE username = $1 AND tid = $2 AND qid = $3", tracker.username, tracker.tid, tracker.qid, tracker.answer, tracker.lives, tracker.path)
    elif mode == 0:
        return brsret(code = None, debug = mode)

    item_list = []
    for item in entry["items"].split("||"):
        if item.split(":")[0] != "experience":
            item_list.append(item)
            continue
        exp_points = str(int(item.split(":")[1]) + 10) # 10 new experience points per page
        item_list.append("experience:" + exp_points)
        break
    items = "||".join(item_list)
    exp_points = int(exp_points)
    # Get all the new badges a user has unlocked
    new_badges = get_new_badges(entry["badges"], exp_points)
    if new_badges[0] == '':
        await db.execute("UPDATE profile SET items = $2 WHERE username = $1", tracker.username, items)
        return brsret(code = None, debug = mode)
    await db.execute("UPDATE profile SET badges = $2, items = $3 WHERE username = $1", tracker.username, new_badges[1], items)
    return brsret(code = None, debug = mode, items = items, new_badges = new_badges[0])
