import asyncpg

async def setup_db():
    __db = await asyncpg.create_pool(
        host="127.0.0.1", user="catphi", password="Rootspring11,", database="catphi"
    )  # Login stuff
    # Always do this to ensure best performance
    await __db.execute("VACUUM")
    # Represents a subject
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS subjects (metaid TEXT NOT NULL, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL)"
    )
    # Create an index for the subjects
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS subject_index ON subjects (metaid, name, description)"
    )
    # Represents a topic
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS topics (metaid TEXT NOT NULL, name TEXT NOT NULL UNIQUE, description TEXT NOT NULL, tid TEXT PRIMARY KEY)"
    )
    # Create an index for the topics
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS topics_index ON topics (metaid, name, description, tid)"
    )
    # Represents a concept
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS concepts (tid TEXT NOT NULL, title TEXT NOT NULL, cid INTEGER NOT NULL, content TEXT NOT NULL, FOREIGN KEY (tid) REFERENCES topics (tid) ON DELETE CASCADE ON UPDATE CASCADE)"
    )
    # Create an index for the concepts
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS concept_index ON concepts (tid, title, cid, content)"
    )
    # Represents a single login in the database
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS login (token UUID NOT NULL UNIQUE, username TEXT PRIMARY KEY, password TEXT NOT NULL, email TEXT NOT NULL UNIQUE, status INTEGER NOT NULL, scopes TEXT NOT NULL, mfa BOOLEAN NOT NULL, mfa_shared_key TEXT, backup_key TEXT NOT NULL UNIQUE, attempts INTEGER NOT NULL)"
    )
    # Create an index for login
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS login_index ON login (token, username, password, email, status, scopes, mfa, mfa_shared_key, backup_key)"
    )
    # A profile of a user
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS profile (username TEXT PRIMARY KEY, joindate DATE NOT NULL, public BOOLEAN NOT NULL, badges TEXT[] NOT NULL, level TEXT NOT NULL, listing BOOLEAN NOT NULL, items JSON, followers TEXT[], following TEXT[], FOREIGN KEY (username) REFERENCES login (username) ON DELETE CASCADE ON UPDATE CASCADE)"
    )
    # Create an index for the three things that will never/rarely change,
    # namely join date , username and public/private profile
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS profile_index ON profile (username, joindate, public, level, listing)"
    )
    # All the topics a user has completed or is working on
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS profile_topic (username TEXT PRIMARY KEY, tid TEXT NOT NULL, progress TEXT NOT NULL, done BOOLEAN, FOREIGN KEY (username) REFERENCES login (username) ON DELETE CASCADE ON UPDATE CASCADE, FOREIGN KEY (username) REFERENCES login (username) ON DELETE CASCADE ON UPDATE CASCADE)"
    )
    # Profile Concept Index
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS profile_topic_index ON profile_topic (username, tid, done)"
    )
    # General Purpose Simulations
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS experiments (sid TEXT PRIMARY KEY, description TEXT NOT NULL, code TEXT NOT NULL, type TEXT NOT NULL)"
    )
    # Generic Simulations (Experiments) Index
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS experiments_index ON experiments (sid, description, code, type)"
    )
    # Topic Practice
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS topic_practice (tid TEXT NOT NULL, qid INTEGER NOT NULL, type TEXT NOT NULL, question TEXT NOT NULL, answers TEXT, correct_answer TEXT NOT NULL, solution TEXT DEFAULT 'There is no solution for this problem yet!', recommended_time INTEGER, FOREIGN KEY (tid) REFERENCES topics (tid) ON DELETE CASCADE ON UPDATE CASCADE)"
    )
    # Topic Practice Index
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS topic_practice_index ON topic_practice (tid, qid, type, question, answers, correct_answer, solution, recommended_time)"
        )
    await __db.execute(
        "CREATE TABLE IF NOT EXISTS topic_practice_tracker (username TEXT NOT NULL, tid TEXT NOT NULL, qid INTEGER NOT NULL, answer TEXT NOT NULL, lives TEXT NOT NULL, path TEXT DEFAULT '')"
    )
    await __db.execute(
        "CREATE INDEX IF NOT EXISTS topic_practice_index ON topic_practice_tracker (username, tid, qid, answer, lives, path)"
    )
    return __db


