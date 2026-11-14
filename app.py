"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.


for my .schema:

CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  failed_logins INTEGER DEFAULT 0,
  locked_until TEXT
);

"""

import sqlite3

from flask import Flask, g, jsonify, request
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from datetime import datetime, timedelta
from fastapi import FastAPI


DATABASE = "recipes.db"
ph = PasswordHasher()
app = FastAPI()
app = Flask(__name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

@app.get("/health")
def health_check():
    return {"status": "ok"}

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
    }


@app.post("/users")
def register():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    missing_fields = []

    if not username:
        missing_fields.append("username")

    if not email:
        missing_fields.append("email")

    if not password:
        missing_fields.append("password")

    if missing_fields:
        return jsonify({
            "error": "Missing required fields",
            "fields": missing_fields
        }), 400

    db = get_db()
    try:
        hashed_password = ph.hash(password)

        db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, hashed_password),
        )
    
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username or email already in use"}), 409

    return (
        jsonify(
            {
                "username": username,
                "email": email,
            }
        ),
        201,
    )


@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}

    username = data.get("username")
    password = data.get("password")

    missing_fields = []

    if not username:
        missing_fields.append("username")

    if not password:
        missing_fields.append("password")

    if missing_fields:
        return jsonify({
            "error": "Missing required fields",
            "fields": missing_fields
        }), 400

    row = get_db().execute(
        "SELECT * FROM users WHERE username = ?",
        (username,)
    ).fetchone()

    if row is None:
        return jsonify({"error": "bad credentials"}), 401

    if row["locked_until"]:
        locked_until = datetime.fromisoformat(row["locked_until"])

        if datetime.utcnow() < locked_until:
            return jsonify({
                "error": "account locked, try again later",
                "message": "Too many failed login attempts. Try again later."
            }), 423


        get_db().execute(
            """
            UPDATE users
            SET failed_logins = 0,
                locked_until = NULL
            WHERE id = ?
            """,
            (row["id"],)
        )
        get_db().commit()

    try:
        ph.verify(row["password_hash"], password)
        get_db().execute(
            """
            UPDATE users
            SET failed_logins = 0,
                locked_until = NULL
            WHERE id = ?
            """,
            (row["id"],)
        )
        get_db().commit()

    except VerifyMismatchError:
        failed = row["failed_logins"] + 1

        if failed >= 3:
            lock_until = datetime.utcnow() + timedelta(minutes=5)

            get_db().execute(
                """
                UPDATE users
                SET failed_logins = ?,
                    locked_until = ?
                WHERE id = ?
                """,
                (failed, lock_until.isoformat(), row["id"])
            )

            get_db().commit()

            return jsonify({
                "error": "account locked",
                "message": "Too many failed login attempts.",
                "try_again_after": lock_until.isoformat()
            }), 423

        get_db().execute(
            """
            UPDATE users
            SET failed_logins = ?
            WHERE id = ?
            """,
            (failed, row["id"])
        )

        get_db().commit()

        return jsonify({
            "error": "bad credentials",
            "message": "Username or password is incorrect."
        }), 401

    return jsonify({
        "id": row["id"],
        "username": row["username"]
    }), 200


@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})


@app.get("/recipes")
def list_recipes():
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])


@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    row = get_db().execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404
    return jsonify(recipe_to_dict(row))


@app.post("/recipes")
def create_recipe():
    data = request.get_json(silent=True)
    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public)"
            " VALUES (?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201


@app.patch("/recipes/<int:recipe_id>")
def update_recipe(recipe_id):
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400
    fields, values = [], []
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)
    if not fields:
        return jsonify({"error": "nothing to update"}), 400
    values.append(recipe_id)
    db = get_db()
    try:
        cur = db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?", values
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (recipe_id,)
    ).fetchone()
    return jsonify(recipe_to_dict(row))


@app.delete("/recipes/<int:recipe_id>")
def delete_recipe(recipe_id):
    db = get_db()
    cur = db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()
    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404
    return "", 204


if __name__ == "__main__":
    app.run(debug=True)
