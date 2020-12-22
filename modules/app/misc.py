from ..app_deps import *

router = APIRouter(
    tags=["Misc."],
)

@router.get("/temprun/{template}/")
@router.get("/temprun/{template}")
async def template_test_run(request: Request, template: str):
    try:
        return await render_template(request, template + ".html")
    except:
        return abort(404)

