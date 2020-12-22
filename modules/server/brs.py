from ..server_deps import *

router = APIRouter(
    prefix = "/clancat",
    tags=["Clan Cat"],
)

@router.get("/bristlefrost/rootspring/shadowsight")
async def bristlefrost_x_rootspring_x_shadowsight():
    # Get all topics
    topics = await db.fetch("SELECT subject_table.metaid, topic_table.tid, topic_table.name AS topic_name, concept_table.cid, concept_table.title AS concept_name from concept_table INNER JOIN topic_table ON topic_table.tid = concept_table.tid INNER JOIN subject_table ON topic_table.metaid = subject_table.metaid ORDER BY tid, cid ASC")
    return topics

