from ..app_deps import *

router = APIRouter(
    prefix = "/clancat",
    tags=["Clan Cat"],
)

# Server sends a GET request to this when we need to recall /clancat/bristlefrost/rootspring/shadowsight
@router.get("/brs/internal/cache/update") 
async def brs_request_event():
    print("NOTE: Updating cache on server request")
    builtins.brs = BRS(requests.get(api + "/clancat/bristlefrost/rootspring/shadowsight").json()).brs_dict
