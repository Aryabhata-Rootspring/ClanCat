from ..server_deps import *

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

