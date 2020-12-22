from ..app_deps import *

router = APIRouter(
    prefix="/experiment",
    tags=["Experiments"],
)

@router.get("/new")
async def new_simulation_get(request: Request):
    if request.session.get("token") == None:
        request.session["redirect"] = "/experiment/new"
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    return await render_template(
        request,
        "admin_simulation_new.html",
    )

@router.post("/new")
async def new_simulation_post(request: Request, exp_type: str = FastForm("glowscript"), description: str = FastForm("No description yet")):
    poster = requests.post(api + "/experiment/new", json = {
        "username": request.session.get("username"),
        "token": request.session.get("token"),
        "description": description,
        "exp_type": exp_type
    }).json()
    if poster["code"] is not None:
        return await render_template(
            request,
            "admin_simulation_new.html",
            error = Markup(poster["error"])
        )
    return redirect(f"/experiment/{poster['context']['id']}/edit")

@router.post("/{sid}/save")
async def experiment_save(sid: str, data: SaveExperimentPage):
    a = requests.post(
        api + "/experiment/save",
        json={
            "username": data.username,
            "token": data.token,
            "code": data.code,
            "sid": sid,
        },
    )
    a = a.json()
    return a

@router.get("/{sid}/iframe")
async def iframe_simulation(request: Request, sid: str):
    simulation = requests.get(api + "/experiment/get?sid=" + sid).json()
    if simulation.get("code") != None:
        return abort(404)
    return await render_template(
        request,
        "iframe_simulation.html",
        desc = simulation["context"]["description"],
        code = simulation["context"]["exp_code"]
    )

