from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

DATABASE = "notes.db"


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS notes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        content TEXT NOT NULL
    )
    """)

    conn.commit()
    conn.close()

import logging

import logging

logger = logging.getLogger(__name__)

@app.route("/")
def index():
    try:
        logger.info("Fetching notes from database")
        
        conn = sqlite3.connect(DATABASE)

        cursor = conn.cursor()
        cursor.execute("SELECT * FROM notes")
        notes = cursor.fetchall()
        conn.close()

        logger.info(f"Successfully retrieved {len(notes)} notes")

        return render_template("index.html", notes=notes)

    except Exception as e:
        logger.error(f"Error retrieving notes: {e}")

        return "Error retrieving notes", 500


@app.route("/add", methods=["POST"])
def add_note():

    title = request.form["title"]
    content = request.form["content"]

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "INSERT INTO notes(title, content) VALUES(?, ?)",
        (title, content)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("index"))



@app.route("/delete/<int:id>")
def delete_note(id):

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM notes WHERE id=?",
        (id,)
    )

    conn.commit()
    conn.close()

    return redirect(url_for("index"))

@app.route("/delete/<int:id>")
def delete_note(id):

    try:
        logger.info(f"Delete request received for note ID: {id}")

        logger.info("Connecting to SQLite database")
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        logger.info("Database connection established successfully")

        logger.info(f"Checking if note exists with ID: {id}")
        cursor.execute(
            "SELECT * FROM notes WHERE id=?",
            (id,)
        )

        note = cursor.fetchone()

        if note is None:
            logger.warning(f"No note found with ID: {id}")
            conn.close()
            return "Note not found", 404

        logger.info(f"Note found: {note}")

        logger.info(f"Executing DELETE query for note ID: {id}")
        cursor.execute(
            "DELETE FROM notes WHERE id=?",
            (id,)
        )

        logger.info("Committing database changes")
        conn.commit()

        logger.info(f"Note with ID {id} deleted successfully")

        logger.info("Closing database connection")
        conn.close()

        logger.info("Redirecting user to home page")

        return redirect(url_for("index"))

    except sqlite3.Error as db_error:

        logger.error(
            f"SQLite database error while deleting note ID {id}: {db_error}"
        )

        return "Database Error", 500

    except Exception as e:

        logger.error(
            f"Unexpected error while deleting note ID {id}: {e}"
        )

        return "Application Error", 500



@app.route("/edit/<int:id>")
def edit_note(id):

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM notes WHERE id=?",
        (id,)
    )

    note = cursor.fetchone()

    conn.close()

    return render_template(
        "edit.html",
        note=note
    )


@app.route("/update/<int:id>", methods=["POST"])
def update_note(id):

    title = request.form["title"]
    content = request.form["content"]

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute(
        """
        UPDATE notes
        SET title=?, content=?
        WHERE id=?
        """,
        (title, content, id)
    )

    conn.commit()
    conn.close()

    return redirect("/")



if __name__ == "__main__":
    init_db()
    app.run(debug=True)