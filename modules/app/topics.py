from ..app_deps import *

# Classes
class TopicPracticeSolve(BaseModel):
    answer: str
    lives: int
    path: str

class SaveTopic(BaseModel):
    username: str
    token: str
    description: str

class SaveExperimentPage(BaseModel):
    username: str
    token: str
    code: str

router = APIRouter(
    prefix="/topics",
    tags=["Topics"],
)

@router.get("/")
async def topics(request: Request):
    topic_list_json = requests.get(api + "/topics/list").json()  # Get the list of topics in JSON
    topic_list = []  # ejson as list
    if topic_list_json.get("code") is not None:
        return await render_template(
            request,
            "topic_list.html",
            topic_list=[]
        )
    topic_list_json = topic_list_json["context"]["topics"]
    for topic in topic_list_json.keys():
        topic_list.append([topic, topic_list_json[topic]])
    return await render_template(
        request,
        "topic_list.html",
        topic_list=topic_list,
        admin = request.session.get("admin"),
    )

@router.get("/{tid}")
async def get_topic_index(request: Request, tid: str):
    topic_json = requests.get(
        api + f"/topics/get?tid={tid}&simple=0"
    ).json()  # Get the full topic info
    if topic_json.get("code") != None:
        return abort(404)
    return await render_template(
        request,
        "topic_page.html",
        name=topic_json["context"]["name"],
        description=topic_json["context"]["description"],
        tid=tid,
        admin = request.session.get("admin"),
    )

@router.get("/{tid}/concepts/new")
async def new_concept_get(request: Request, tid: str):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics"
        return redirect("/login")
    if request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    return await render_template(
        request,
        "concept_new.html",
    )

@router.post("/{tid}/concepts/new")
@csrf_protect
async def new_concept_post(request: Request, tid: str, concept: str = FastForm("Untitled Concept")):
    x = requests.post(
        api + "/concepts/new",
        json={
            "username": request.session.get("username"),
            "token": request.session.get("token"),
            "topic": tid,
            "concept": concept,
        },
    ).json()
    return x

@router.get("/{tid}/edit")
async def topics_edit_description(request: Request, tid: str):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics/" + tid
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    ejson = requests.get(
        api + f"/topics/get?tid={tid}&simple=0" # We need the description here. No simple mode
    ).json()
    if ejson.get("code") != None:
        return abort(404)
    return await render_template(
        request,
        "editor.html",
        type = "topic",
        tid=tid,
        token=request.session.get("token"),
        description=ejson["context"]["description"],
    )

@router.get("/{tid}/editmenu")
async def topics_edit_menu(request: Request, tid: str):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics/" + tid + "/edit"
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    topic_exp_json = requests.get(api + f"/topics/get?tid={tid}&simple=1").json()
    if topic_exp_json.get("code") != None:
        return abort(404)
    return await render_template(
        request,
        "topic_edit_menu.html",
        tid=tid,
    )

@router.get("/{tid}/edit/concepts")
async def topic_edit_concepts(request: Request, tid: str):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics/" + tid
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    exp_json = requests.get(api + f"/topics/get?tid={tid}&simple=1").json()
    if exp_json.get("code") != None:
        return abort(404)
    concepts_json = requests.get(api + f"/topics/concepts/list?tid={tid}").json()
    if concepts_json.get("code") is not None:
        concepts = []
    else:
        concepts_json = concepts_json["context"]["concepts"]
        concepts = []
        for concept in concepts_json.keys():
            concepts.append([concept, concepts_json[concept]])
    return await render_template(
        request,
        "topic_edit_concepts.html",
        tid=tid,
        concepts = concepts,
    )

@router.get("/{tid}/edit/concept/{cid}")
async def topic_edit_concept(request: Request, tid: str, cid: int):
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics/" + tid
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    concept_json = requests.get(api + f"/topics/concepts/get?tid={tid}&cid={str(cid)}").json()

    if concept_json.get("code") is not None or int(cid) < 0:
        return abort(404)
    concept_json = concept_json["context"]
    return await render_template(
        request,
        "editor.html",
        type = "concept",
        tid = tid,
        cid = cid,
        content = Markup(concept_json.get("content")),
        token = request.session.get("token"),
    )

@router.post("/topics/{tid}/edit/concepts/new")
@csrf_protect
async def __topic_edit_new_concept_post__(request: Request, tid, title: str = FastForm("Untitled Concept")):
        a = requests.post(
            api + "/topics/concepts/new",
            json={
                "username": request.session.get("username"),
                "token": request.session.get("token"),
                "tid": tid,
                "title": title,
            },
        ).json()
        return a

@router.get("/{tid}/practice/{qid}/edit")
@router.get("/{tid}/edit/practice/new")
async def new_or_edit_practice_question_get(request: Request, tid: str, qid: Optional[int] = None):
    default_values = {"type": "MCQ", "question": "", "answers": "", "correct_answer": "", "solution": ""}
    if qid is not None:
        practice_json = requests.get(api + f"/topics/practice/get?tid={tid}&qid={str(qid)}").json()
        if practice_json["code"] is not None:
            return abort(404)
        default_values = practice_json["context"]
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics/" + tid + "/edit/practice/new"
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    return await render_template(request, "topic_practice_new.html", default_values = default_values, mode = "new")

@router.post("/{tid}/practice/{qid}/edit")
@router.post("/{tid}/edit/practice/new")
@csrf_protect
async def new_practice_question_post(request: Request, tid: str, qid: Optional[int] = None, type: str = FastForm("MCQ"), question: str = FastForm("Question Not Yet Setup"), correct_answer: str = FastForm(None), solution: str = FastForm("There is no solution yet"), answers: str = FastForm(None), recommended_time: int = FastForm(0)):
        default_values = {"type": "MCQ", "question": "", "answers": "", "correct_answer": "", "solution": ""}
        if type == "MCQ" and (answers is None or correct_answer not in ["A", "B", "C", "D"]):
            return await render_template(request, "topic_practice_new.html",  error = "Not all required fields have been filled in and/or the correct answer is invalid (must be one letter in an MCQ)", default_values = default_values, mode = "new")
        elif type == "MCQ" and len(answers.split("||")) != 4:
            return await render_template(request, "topic_practice_new.html",  error = "MCQ must have 4 questions seperated by ||", default_values = form, mode = "new")

        json = {
            "username": request.session.get('username'),
            "token": request.session.get("token"),
            "type": type,
            "question": question,
            "correct_answer": correct_answer,
            "solution": solution,
            "tid": tid,
        }
        if type == "MCQ":
            json["answers"] = answers
        if recommended_time != 0:
            json["recommended_time"] = int(recommended_time)
        if qid is not None:
            json["qid"] = int(qid)
            url = "/topics/practice/save"
        else:
            url = "/topics/practice/new"
        return requests.post(api + url, json = json).json()

@router.get("/new")
async def new_topic_get(request: Request):
    print("Got here")
    subject_json = requests.get(api + "/subjects/list").json()
    if subject_json == {} or subject_json.get("code") is not None:
        subjects = []
    else:
        subject_json = subject_json["context"]["subjects"]
        subjects = []
        for subject in subject_json.keys():
            subjects.append([subject, subject_json[subject]])
    if request.session.get("token") == None:
        request.session["redirect"] = "/topics"
        return redirect("/login")
    elif request.session.get("admin") in [0, None, "0"]:
        return abort(401)
    return await render_template(
        request,
        "topic_new.html",
        subjects = subjects
    )

@router.post("/new")
@csrf_protect
async def new_topic_post(request: Request, name: str = FastForm(None), description: str = FastForm(None), metaid: str = FastForm(None)):
    x = requests.post(
        api + "/topics/new",
        json={
            "username": request.session.get("username"),
            "token": request.session.get("token"),
            "name": name,
            "description": description,
            "metaid": metaid
        }).json()
    if x.get("error") == "1000":
        return redirect(f"/topics/{x['tid']}")
    return x

@router.get("/{tid}/learn")
async def redir_topic(request: Request, tid: str):
    if "username" not in request.session:
        return redirect("/topics/" + tid + "/learn/1")
    tracker_r = requests.get(api + "/profile/track?username=" + request.session.get("username") + "&tid=" + tid).json()
    cid = tracker_r["context"]['cid']
    if tracker_r["context"]["status"] == "LP":
        return redirect("/topics/" + tid + "/learn/" + str(cid))
    elif tracker_r["context"]["status"] == "PP":
        return redirect("/topics/" + tid + "/practice/" + str(cid))
    return abort(404)

@router.get("/{tid}/learn/{cid}")
async def topic_concept_learn(request: Request, tid: str, cid: int):
    concept_json = requests.get(api + f"/topics/concepts/get?tid={tid}&cid={cid}").json()
    if concept_json.get("code") is not None:
        return abort(404)
    concept_json = concept_json["context"]
    count_json = requests.get(
        api + f"/topics/concepts/get/count?tid={tid}"
    ).json()  # Get the page count of a concept
    count_json = count_json["context"]
    if "username" in request.session:
        # User is logged in, track their progress
        tracker_r = requests.get(api + "/profile/track?username=" + request.session.get("username") + "&tid=" + tid).json()
        done = tracker_r["context"]['done']
        tracked_cid = tracker_r["context"]['cid']
        if int(tracked_cid) < int(cid) and not done and tracker_r["context"]["status"] == "LP":
            tracker_w = requests.post(api + "/profile/track", json = {
                "username": request.session.get("username"),
                "token": request.session.get("token"),
                "status": "LP",
                "tid": tid,
                "cid": cid
            }).json() # Track the fact that he went here in this case
    pages = [i for i in range(1, count_json['concept_count'] + 1)]
    return await render_template(
        request,
        "concept.html",
        tid=tid,
        cid=int(cid),
        concepts = pages,
        concept_count = count_json['concept_count'],
        content = Markup(concept_json['content']),
        title = concept_json["title"],
        admin = request.session.get("admin"),
    )

@router.get("/{tid}/practice")
async def redir_topic_practice(request: Request, tid: str):
    if "username" not in request.session:
        return redirect("/topics/" + tid + "/practice/1")
    tracker = requests.get(api + "/profile/track?username=" + request.session.get("username") + "&tid=" + tid).json()
    cid = tracker["context"]['cid']
    if tracker["context"]["status"] == "PP":
        return redirect("/topics/" + tid + "/practice/" + str(cid))
    else:
        return redirect("/topics/" + tid + "/practice/1")

@router.get("/{tid}/practice/{qid}")
async def topic_practice_view(request: Request, tid: str, qid: int):
    practice_json = requests.get(api + f"/topics/practice/get?tid={tid}&qid={qid}").json()
    if practice_json.get("code") is not None:
        return await render_template(
            request,
            "generic_error.html",
            practice_mode = True,
            header="There are no practice question's for this topic yet...",
            error="Check back later, brave explorer!",
            tid = tid
        )
    practice_json = practice_json["context"]
    count_json = requests.get(
        api + f"/topics/practice/get/count?tid={tid}"
    ).json()["context"]  # Get the page count of a concept
    if practice_json["type"] == "MCQ":
        answers = practice_json["answers"].split("||")
    else:
        answers = None
    correct_answer = practice_json["correct_answer"]
    pages = [i for i in range(1, count_json['practice_count'] + 1)]

    # Check if they already answered said question
    try:
        key = "|".join(["practice", "answer", tid, str(qid)])
        solved = request.session[key]
        key = "|".join(["practice", "lives", tid, str(qid)])
        lives = str(request.session[key])
        key = "|".join(["practice", "path", tid, str(qid)])
        choices = request.session[key].split("|")
        if len(choices) == 2 or (len(choices) == 1 and choices[0] != correct_answer):
            # They had two chances, get the incorrect one and store in a variable
            inans = choices[0] # This was their first choice
        else:
            inans = None
    except:
        solved = None
        lives = None
        choices = None
        inans = None
    print(solved, lives, choices, solved)
    return await render_template(
        request,
        "topic_practice.html",
        practice_mode = True,
        tid=tid,
        qid=int(qid),
        questions = pages,
        practice_count = count_json['practice_count'],
        type = practice_json["type"],
        question = Markup(practice_json["question"]),
        answers = answers,
        correct_answer = correct_answer,
        admin = request.session.get("admin"),
        solution = Markup(practice_json["solution"]),
        solved = solved,
        lives = lives,
        choices = choices,
        inans = inans,
    )

# They have solved the question, save it on server session and on other locations (a database) if logged in
@router.post("/{tid}/practice/{qid}/solve")
@csrf_protect
async def topic_practice_solve(request: Request, tid: str, qid: int, data: TopicPracticeSolve):
    key = "|".join(["practice", "answer", tid, str(qid)])
    request.session[key] = data.answer
    key = "|".join(["practice", "lives", tid, str(qid)])
    request.session[key] = data.lives
    key = "|".join(["practice", "path", tid, str(qid)])
    request.session[key] = data.path
    if "username" in request.session.keys():
        tracker_w = requests.post(api + "/profile/track", json = {
            "username": request.session.get("username"),
            "token": request.session.get("token"),
            "status": "PP",
            "tid": tid,
            "cid": qid
        }).json() # Track the fact that he went here
        tracker_w = requests.post(api + "/profile/track/practice", json = {
            "username": request.session.get("username"),
            "token": request.session.get("token"),
            "tid": tid,
            "qid": qid,
            "answer": data.answer,
            "lives": data.lives,
            "path": data.path
        }).json() # And track the answer he/she gave
        return tracker_w
    return None

@router.post("/{tid}/concepts/{cid}/save")
@csrf_protect
async def save_page(tid: str, cid: str, data: SaveExperimentPage):
    a = requests.post(
        api + "/topics/concepts/save",
        json={
            "username": data.username,
            "token": data.token,
            "code": data.code,
            "cid": cid,
            "tid": tid,
        },
    )
    a = a.json()
    return a

@router.post("/{tid}/save")
async def save_topics(request: Request, tid: str, data: SaveTopic):
    a = requests.post(
        api + "/topics/save",
        json={
            "username": data.username,
            "token": data.token,
            "description": data.description,
            "tid": tid,
        },
    )
    a = a.json()
    return a

