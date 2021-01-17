from ..app_deps import *

router = APIRouter(
    prefix = "/subjects",
    tags=["Subjects"],
)

@router.get("/admin/new")
async def new_subjects_get(request: Request):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics"
        return redirect("/login")
    if request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    return await render_template(
        request,
        "subject_new.html",
    )

@router.post("/admin/new")
@csrf_protect
async def new_subjects_post(request: Request, name: str = FastForm(None), description: str = FastForm(None)):
    x = requests.post(
        api + "/subjects",
        json={
            "username": request.session.get("username"),
            "token": request.session.get("token"),
            "name": name,
            "description": description
        },
    ).json()
    return x
