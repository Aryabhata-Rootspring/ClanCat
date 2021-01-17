from ..server_deps import *

class SubjectNew(UserModel):
    name: str
    description: str

router = APIRouter(
    tags=["Subjects"],
)

@router.get("/subjects")
async def list_subjects(operation: int):
    if operation not in [1]:
        return brsret(code = "INVALID_OPERATION")
    subjects = await db.fetch("SELECT name, metaid FROM subjects")
    sjson = {}
    for subject in subjects:
        sjson[subject["name"]] = subject["metaid"]
    return brsret(code = None, subjects = sjson)

@router.post("/subjects")
async def new_subject(subject: SubjectNew, bt: BackgroundTasks):
    auth_check = await authorize_user(subject.username, subject.token)
    if auth_check == False:
        return brsret(code = "NOT_AUTHORIZED")
    while True:
        id = get_token(101)
        id_check = await db.fetchrow("SELECT metaid FROM subjects WHERE metaid = $1", id)
        if id_check is None:
            break
    await db.execute(
        "INSERT INTO subjects (metaid, name, description) VALUES ($1, $2, $3)",
        id,
        subject.name,
        subject.description,
    )
    bt.add_task(server_watchdog) # Update the client
    return brsret()
