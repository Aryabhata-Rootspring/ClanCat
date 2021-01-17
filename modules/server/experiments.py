import pyximport
pyximport.install()

from ..server_deps import *

class GenericExperimentNew(UserModel):
    description: str
    exp_type: Optional[str] = "glowscript"

class SaveExperiment(UserModel):
    sid: str
    code: str

router = APIRouter(
    tags=["Experiments"],
)

@router.get("/experiments")
async def get_experiment(sid: str):
    experiment = await db.fetchrow("SELECT description, code, type FROM experiments WHERE sid = $1", sid)
    if experiment is None:
        return brsret(code = "FORBIDDEN", html = "Forbidden Request")  # Not Authorized
    return brsret(code = None, sid = sid, description = experiment["description"], exp_code = experiment["code"], type = experiment["type"])

@router.post("/experiments")
async def new_experiment(experiment: GenericExperimentNew, bt: BackgroundTasks):
    auth_check = await authorize_user(experiment.username, experiment.token)
    if auth_check == False:
        return brsret(code = "NOT_AUTHORIZED")
    while True:
        id = get_token(101)
        id_check = await db.fetchrow("SELECT sid FROM experiments WHERE sid = $1", id)
        if id_check is None:
            break
    await db.execute(
        "INSERT INTO experiments (sid, description, code, type) VALUES ($1, $2, $3, $4)",
        id,
        experiment.description,
        "arrow();",
        experiment.exp_type
    )
    return brsret(code = None, id = id)

@router.patch("/experiments")
async def save_experiment(save: SaveExperiment):
    auth_check = await authorize_user(save.username, save.token)
    if auth_check == False:
        return brsret(code = "NOT_AUTHORIZED")
    await db.execute(
        "UPDATE experiments SET code = $1 WHERE sid = $2",
        save.code,
        save.sid,
    )
    return brsret(code = None, outer_scope = {"message": "Successfully saved entity!"})

