from ..server_deps import *

class SubjectNew(UserModel):
    name: str
    description: str

router = APIRouter(
    prefix="/subjects",
    tags=["Subjects"],
)

@router.get("/list")
async def list_subjects():
    subjects = await db.fetch("SELECT name, metaid FROM subject_table")
    sjson = {}
    for subject in subjects:
        sjson[subject["name"]] = subject["metaid"]
    return brsret(code = None, subjects = sjson)

@router.post("/new")
async def new_subject(subject: SubjectNew, bt: BackgroundTasks):
    auth_check = await authorize_user(subject.username, subject.token)
    if auth_check == False:
        return brsret(code = "NOT_AUTHORIZED")
    while True:
        id = get_token(101)
        id_check = await db.fetchrow("SELECT metaid FROM subject_table WHERE metaid = $1", id)
        if id_check is None:
            break
    await db.execute(
        "INSERT INTO subject_table (metaid, name, description) VALUES ($1, $2, $3)",
        id,
        subject.name,
        subject.description,
    )
    bt.add_task(server_watchdog) # Update the client
    return brsret()
