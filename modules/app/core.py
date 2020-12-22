from ..app_deps import *

router = APIRouter(
    tags=["Core"],
)

@router.get("/")
async def index(request: Request):
    return await render_template(request, "index.html")

@router.get("/redir")
async def redir(request: Request):
    if request.session.get("redirect") == None:
            return redirect("/topics")
    rdir = request.session.get("redirect")
    try:
        del request.session["redirect"]
    except:
        pass
    return redirect(rdir)

