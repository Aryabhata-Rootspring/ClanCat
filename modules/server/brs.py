from ..server_deps import *

router = APIRouter(
    prefix = "/clancat",
    tags=["Clan Cat"],
)

@router.get("/bristlefrost/rootspring/shadowsight")
async def bristlefrost_x_rootspring_x_shadowsight():
    # Get all topics
    topics = await db.fetch("SELECT subjects.metaid, topics.tid, topics.name AS topic_name, concepts.cid, concepts.title AS concept_name from concepts INNER JOIN topics ON topics.tid = concepts.tid INNER JOIN subjects ON topics.metaid = subjects.metaid ORDER BY tid, cid ASC")
    return topics

