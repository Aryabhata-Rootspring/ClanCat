import pyximport
pyximport.install()

from ..server_deps import *

class TopicNew(UserModel):
    name: str
    description: str
    metaid: str

class ConceptNew(UserModel):
    tid: str
    title: str

class TopicPracticeNew(UserModel):
    type: str
    question: str
    answers: Optional[str] = None
    correct_answer: str
    tid: str
    solution: str

class SaveTopic(UserModel):
    tid: str
    description: str

class SaveTopicConcept(UserModel):
    tid: str
    cid: int
    code: str

class SaveTopicPractice(UserModel):
    type: str
    question: str
    answers: Optional[str] = None
    correct_answer: str
    tid: str
    qid: int
    solution: str
    recommended_time: Optional[int] = 0

router = APIRouter(
    prefix="/topics",
    tags=["Topics"],
)

@router.get("/concepts/get/count")
async def get_concept_count(tid: str):
    concept_count = await db.fetch("SELECT COUNT(cid) FROM concept_table WHERE tid = $1", tid)
    return brsret(code = None, concept_count = concept_count[0]["count"])

@router.get("/concepts/get")
async def get_concept(tid: str, cid: int):
    concept = await db.fetch("SELECT title, content FROM concept_table WHERE tid = $1 ORDER BY cid ASC", tid)
    if len(concept) == 0 or len(concept) < int(cid) or int(cid) <= 0:
        return brsret(code = "INVALID_PARAMETERS")
    return brsret(code = None, title = concept[int(cid) - 1]["title"], content = concept[int(cid) - 1]["content"])

@router.get("/concepts/list")
async def list_concepts(tid: str):
    concepts = await db.fetch("SELECT title FROM concept_table WHERE tid = $1 ORDER BY title ASC", tid)
    if len(concepts) == 0:
        return brsret(code = "NO_CONCEPTS_FOUND")
    cjson = {}
    i = 1
    for concept in concepts:
        cjson[concept['title']] = i
        i+=1
    return brsret(code = None, concepts = cjson)

@router.post("/concepts/new")
async def new_concept(concept: ConceptNew, bt: BackgroundTasks):
    auth_check = await authorize_user(concept.username, concept.token)
    if auth_check == False:
        return brsret(code = "NOT_AUTHORIZED")
    tcheck = await db.fetchrow("SELECT tid FROM topic_table WHERE tid = $1", concept.tid)
    if tcheck is None:
        # Topic Does Not Exist
        return brsret(code = "TOPIC_DOES_NOT_EXIST", html = "That topic does not exist yet")
    concept_count = await db.fetchrow("SELECT title FROM concept_table WHERE title = $1", concept.title)
    if concept_count is not None:
        return brsret(code = "CONCEPT_ALREADY_EXISTS")
    concept_count = await db.fetch("SELECT COUNT(cid) FROM concept_table WHERE tid = $1", concept.tid)
    cid=concept_count[0]["count"] + 1 # Get the count + 1 for next concept
    await db.execute(
        "INSERT INTO concept_table (tid, title, content, cid) VALUES ($1, $2, $3, $4)",
        concept.tid,
        concept.title,
        f"Type your content for concept {concept.title} here!",
        cid
        )
    bt.add_task(server_watchdog) #Update the client
    return brsret(code = None, page_count = cid)

@router.post("/concepts/save")
async def save_concept(save: SaveTopicConcept):
    auth_check = await authorize_user(save.username, save.token)
    if auth_check == False:
        return brsret(code = "NOT_AUTHORIZED")
    # Firstly, make sure the topic actually exists in topic_table
    tcheck = await db.fetchrow("SELECT tid FROM topic_table WHERE tid = $1", save.tid)
    if tcheck is None:
        # Topic Does Not Exist
        return brsret(code = "TOPIC_DOES_NOT_EXIST")
    concept_count = await db.fetch("SELECT COUNT(cid) FROM concept_table WHERE tid = $1", save.tid)
    if int(concept_count[0]["count"]) < int(save.cid):
        return brsret(code = "INVALID_ARGUMENTS")
    concepts = await db.fetch("SELECT cid FROM concept_table WHERE tid = $1 ORDER BY cid ASC", save.tid)  # Get all the concepts in ascending order
    absolute_cid = concepts[int(save.cid) - 1]["cid"] # Calculate the absolute concept id
    await db.execute(
        "UPDATE concept_table SET content = $1 WHERE tid = $2 AND cid = $3",
        save.code,
        save.tid,
        int(absolute_cid),
    )
    return brsret(code = None, outer_scope = {"message": "Successfully saved entity!"})

@router.get("/practice/get/count")
async def get_topic_practice_count(tid: str):
    topic_practice = await db.fetch("SELECT COUNT(1) FROM topic_practice WHERE tid = $1", tid)
    return brsret(code = None, practice_count = topic_practice[0]["count"])

@router.get("/practice/get")
async def get_concept_practice(tid: str, qid: int):
    question = await db.fetch("""
        SELECT type, question, correct_answer,
        answers, solution, recommended_time
        FROM topic_practice
        WHERE tid = $1 AND qid = $2
        ORDER BY qid ASC""",
        tid,
        qid
    )
    if len(question) == 0 or int(qid) <= 0:
        return brsret(code = "NO_PRACTICE_QUESTIONS")
    question = question[0] # Get the absolute practice question ID
    if question["solution"] is None or len(question["solution"]) < 3:
        solution = "There is no solution for this problem yet!"
    else:
        solution = question["solution"]
    return brsret(
        code = None,
        type = question["type"],
        question = question["question"],
        correct_answer = question["correct_answer"],
        answers = question["answers"],
        solution = solution,
        recommended_time = question["recommended_time"],
    )

@router.post("/practice/new")
async def new_topic_practice(topic_practice: TopicPracticeNew, bt: BackgroundTasks):
    auth_check = await authorize_user(topic_practice.username, topic_practice.token)
    if auth_check == False:
        return brsret(code = "NOT_AUTHORIZED")
    tcheck = await db.fetchrow("SELECT tid FROM topic_table WHERE tid = $1", topic_practice.tid)
    if tcheck is None:
        # Topic Does Not Exist
        return brsret(code = "TOPIC_DOES_NOT_EXIST", html = "That topic does not exist yet")

    if len(topic_practice.solution) < 3:
        solution = "There is no solution for this problem yet!"
    else:
        solution = topic_practice.solution
    practice_count = await db.fetch("SELECT COUNT(qid) FROM topic_practice WHERE tid = $1", topic_practice.tid)
    qid=practice_count[0]["count"] + 1 # Get the count + 1 for next concept

    await db.execute(
        "INSERT INTO topic_practice (qid, tid, type, question, correct_answer, answers, solution, recommended_time) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
        qid,
        topic_practice.tid,
        topic_practice.type,
        topic_practice.question,
        topic_practice.correct_answer,
        topic_practice.answers,
        topic_practice.solution,
        0,
    )
    return brsret(code = None, practice_count = qid)

@router.post("/practice/save")
async def topic_practice_save(save: SaveTopicPractice):
    auth_check = await authorize_user(save.username, save.token)
    if auth_check == False:
        return brsret(code = "NOT_AUTHORIZED")
    await db.execute(
        "UPDATE topic_practice SET type = $1, question = $2, answers = $3, correct_answer = $4, solution = $5, recommended_time = $6 WHERE tid = $7 AND qid = $8",
        save.type,
        save.question,
        save.answers,
        save.correct_answer,
        save.solution,
        save.recommended_time,
        save.tid,
        save.qid,
    )
    return brsret(code = None, outer_scope = {"message": "Successfully saved entity!"})

@router.get("/get")
async def get_topic(tid: str, simple: Optional[int] = 0):
    """NOTE: Simple determines whether to just fetch the name or to fetch both the name and the description"""
    if simple == 0:
        topic = await db.fetchrow("SELECT name, description FROM topic_table WHERE tid = $1", tid)
    else:
        topic = await db.fetchrow("SELECT name FROM topic_table WHERE tid = $1", tid)
    if topic is None:
        return brsret(code = "TOPIC_DOES_NOT_EXIST", html = "This topic does not exist yet")
    if simple == 0:
        if topic["description"] in ["", None]:
            topic_desc = "<script>alert('This topic has not yet been configured yet!');</script>"
        else:
            topic_desc = topic["description"]
        return brsret(code = None, name = topic["name"], description = topic_desc)
    else:
        return brsret(code = None, name = topic["name"])

@router.get("/list")
async def list_topics():
    topics = await db.fetch("SELECT name, tid FROM topic_table ORDER BY name ASC")
    tjson = {}
    for topic in topics:
        tjson[topic["name"]] = topic["tid"]
    return brsret(code = None, topics = tjson)

@router.post("/new")
async def new_topic(topic: TopicNew, bt: BackgroundTasks):
    auth_check = await authorize_user(topic.username, topic.token)
    if auth_check == False:
        return brsret(code = "NOT_AUTHORIZED")
    tcheck = await db.fetchrow("SELECT name FROM subject_table WHERE metaid = $1", topic.metaid)
    if tcheck is None:
        return brsret(code = "SUBJECT_DOES_NOT_EXIST", html = "That subject does not exist yet")
    while True:
        id = get_token(101)
        id_check = await db.fetchrow("SELECT tid FROM topic_table WHERE tid= $1", id)
        if id_check is None:
            break
    await db.execute(
        "INSERT INTO topic_table (name, description, tid, metaid) VALUES ($1, $2, $3, $4)",
        topic.name,
        topic.description,
        id,
        topic.metaid,
    )
    bt.add_task(server_watchdog)# Update the client
    return brsret(code = None, id = id)

@router.post("/save")
async def save_topic(save: SaveTopic):
    auth_check = await authorize_user(save.username, save.token)
    if auth_check == False:
        return brsret(code = "NOT_AUTHORIZED")
    await db.execute(
        "UPDATE topic_table SET description = $1 WHERE tid = $2",
        save.description,
        save.tid,
    )
    return brsret(code = None, outer_scope = {"message": "Successfully saved entity!"})
 
