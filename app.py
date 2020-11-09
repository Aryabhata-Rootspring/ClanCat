from quart import Quart, render_template, send_from_directory, send_file, request
import asyncpg
import asyncio
app = Quart(__name__, static_url_path="/static")

async def setup_db():
    db = await asyncpg.connect(
        host="database-1.civhw5bah3rj.us-east-2.rds.amazonaws.com",
        user="postgres",
        password="Waterbot123",
        database="AryabhataCheatList") #Login stuff
    await db.execute("CREATE TABLE simulations (owner TEXT NOT NULL, id SERIAL, code TEXT )") # Represents a simulation on the database
    return db
loop = asyncio.get_event_loop()
db = loop.run_until_complete(setup_db())

@app.route('/edit/text')
async def hello_world():
    return await render_template("catsim.html")

@app.route('/js/<path:fn>')
@app.route('/edit/js/<path:fn>')
async def js_server(fn):
    print("got here " + fn)
    return await send_file('static/' + fn)

@app.route('/save', methods=["POST"])
async def save():
    print("CODE")
    data = await request.form
    if "owner" not in data.keys() or "code" not in data.keys():
        return {"errpr": "Could not save data as required keys are not present"}
    a = await db.execute("INSERT INTO simulations (owner, code) VALUES ($1, $2);", data['owner'], data['code'])
    return a
app.run()
