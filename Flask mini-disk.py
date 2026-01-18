#!/usr/bin/env python3  # Shebang to run with Python 3
# -*- coding: utf-8 -*-  # Source file encoding declaration
"""
Flask mini-disk:
upload / download / list / delete
Main color: rgb(120, 0, 0)  (dark red)
"""

import os                                               # Standard library: file handling
import uuid                                             # Standard library: generate unique IDs
import sqlite3                                          # Standard library: embedded SQL database
from datetime import datetime                           # Standard library: date and time helper
from pathlib import Path                                # Standard library: convenient path object
from functools import wraps                             # Standard library: decorator helper

from flask import (                                     # Flask framework imports
    Flask, g, request, redirect, url_for,
    render_template_string, flash, send_file, session)
from werkzeug.security import (                         # Password hashing & verification helpers
    generate_password_hash, check_password_hash)
from werkzeug.utils import secure_filename              # Sanitize filenames to prevent injection

# ────────────────────────── Basic configuration ──────────────────────────
BASE_DIRECTORY = Path(__file__).resolve().parent        # Folder where app.py resides
DATABASE_PATH = BASE_DIRECTORY / "disk.db"              # SQLite database file
UPLOAD_DIRECTORY = BASE_DIRECTORY / "uploads"           # Folder where all files are stored
UPLOAD_DIRECTORY.mkdir(exist_ok=True)                   # Create upload folder if missing

app = Flask(__name__)                                   # Create Flask application instance
app.config["SECRET_KEY"] = "please-change-me"           # Secret key for sessions / CSRF
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024     # Limit single upload to 50 MB

ALLOWED_EXTENSIONS = set()                              # Empty set → allow every extension

# ────────────────────────── Database helpers ────────────────────────────
def get_database_connection():                          # Open (or reuse) a SQLite connection
    if "database_connection" not in g:                  # Flask’s g stores app-context globals
        g.database_connection = sqlite3.connect(DATABASE_PATH)  # New connection
        g.database_connection.row_factory = sqlite3.Row         # Rows behave like dicts
    return g.database_connection                        # Return connection for this request

@app.teardown_appcontext
def close_database_connection(exception):               # Close connection when request ends
    connection = g.pop("database_connection", None)     # Pop from g (None if absent)
    if connection is not None:                          # If a connection exists
        connection.close()                              # Close it properly

def initialize_database():                              # One-time DB schema creation
    connection = sqlite3.connect(DATABASE_PATH)         # Temporary connection
    connection.executescript("""                        # Execute multiple SQL statements
    CREATE TABLE IF NOT EXISTS users (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,    -- Auto-increment user ID
        username  TEXT UNIQUE NOT NULL,                 -- Unique user name
        password  TEXT NOT NULL                         -- Hashed password
    );
    CREATE TABLE IF NOT EXISTS files (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,  -- Auto-increment file ID
        owner_id    INTEGER NOT NULL,                   -- FK → users.id
        real_name   TEXT NOT NULL,                      -- Original filename from user
        saved_name  TEXT NOT NULL,                      -- Name on disk (uuid + original)
        uploaded_at TEXT NOT NULL                       -- Timestamp string
    );
    """)
    connection.commit()                                 # Persist schema changes
    connection.close()                                  # Close initialization connection

initialize_database()                                   # Ensure DB exists when app starts

# ────────────────────────── Utility functions ──────────────────────────
def is_extension_allowed(filename: str) -> bool:        # Check if file extension is allowed
    if "." not in filename:                             # Reject files without dot
        return False
    if not ALLOWED_EXTENSIONS:                          # Empty set means accept any ext
        return True
    return filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS  # Validate against set

def login_required(view_function):                      # Decorator that forces authentication
    @wraps(view_function)                               # Preserve original function metadata
    def decorated_view(*args, **kwargs):                # Wrapper that checks session
        if "user_id" not in session:                    # Not logged in
            flash("Please log in first.")               # Show message
            return redirect(url_for("login"))           # Redirect to login page
        return view_function(*args, **kwargs)           # Proceed if authenticated
    return decorated_view                               # Return wrapped function

# ────────────────────────── Authentication routes ──────────────────────
@app.route("/register", methods=["GET", "POST"])        # User registration page
def register():
    if request.method == "POST":                        # Handle submitted form
        username_input = request.form["username"].strip()   # Fetch and trim username
        password_input = request.form["password"].strip()   # Fetch and trim password
        if not username_input or not password_input:    # Basic validation
            flash("Username and password cannot be empty.")
            return redirect(url_for("register"))

        connection = get_database_connection()          # Get DB connection
        try:                                            # Attempt to create user
            connection.execute(
                "INSERT INTO users(username, password) VALUES (?, ?)",
                (username_input, generate_password_hash(password_input)))
            connection.commit()
            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:                  # Username already exists
            flash("Username already taken.")
            return redirect(url_for("register"))

    return render_template_string(                      # Render registration form
        BASE_TEMPLATE.format(page_title="Register", page_content=REGISTER_HTML))

@app.route("/login", methods=["GET", "POST"])           # User login page
def login():
    if request.method == "POST":                        # Process submitted credentials
        username_input = request.form["username"].strip()
        password_input = request.form["password"].strip()

        connection = get_database_connection()          # Get DB connection
        user_record = connection.execute(
            "SELECT * FROM users WHERE username = ?", (username_input,)
        ).fetchone()

        if user_record and check_password_hash(user_record["password"], password_input):
            session.clear()                             # Reset session
            session["user_id"] = user_record["id"]      # Store user ID
            session["username"] = user_record["username"]  # Store username
            return redirect(url_for("file_list"))       # Go to main page

        flash("Incorrect username or password.")        # Login failed
        return redirect(url_for("login"))

    return render_template_string(                      # Render login form
        BASE_TEMPLATE.format(page_title="Login", page_content=LOGIN_HTML))

@app.route("/logout")                                   # Logout route
def logout():
    session.clear()                                     # Clear session data
    flash("Logged out.")
    return redirect(url_for("login"))                   # Back to login page

# ────────────────────────── File-handling routes ───────────────────────
@app.route("/", methods=["GET"])                        # Main page → file list
@login_required                                         # Must be logged in
def file_list():
    connection = get_database_connection()              # Get DB connection
    file_records = connection.execute(
        "SELECT id, real_name, uploaded_at FROM files "
        "WHERE owner_id = ? ORDER BY id DESC", (session["user_id"],)
    ).fetchall()                                        # Fetch user-owned files

    return render_template_string(                      # Render list with template
        BASE_TEMPLATE.format(page_title="My Files", page_content=LIST_HTML),
        file_records=file_records)

@app.route("/upload", methods=["POST"])                 # Upload endpoint
@login_required
def upload_file():
    uploaded_file = request.files.get("file")           # Retrieve file object
    if uploaded_file is None or uploaded_file.filename == "":  # No file selected
        flash("No file selected.")
        return redirect(url_for("file_list"))

    if not is_extension_allowed(uploaded_file.filename):# Extension check failed
        flash("File type not allowed.")
        return redirect(url_for("file_list"))

    original_name = secure_filename(uploaded_file.filename)    # Sanitize filename
    saved_name = f"{uuid.uuid4().hex}_{original_name}"         # Unique name on disk
    uploaded_file.save(UPLOAD_DIRECTORY / saved_name)          # Persist file

    connection = get_database_connection()             # Store metadata in DB
    connection.execute(
        "INSERT INTO files(owner_id, real_name, saved_name, uploaded_at) "
        "VALUES (?, ?, ?, ?)",
        (session["user_id"], original_name, saved_name,
         datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    connection.commit()
    flash("Upload successful.")
    return redirect(url_for("file_list"))

@app.route("/download/<int:file_id>")                   # Download endpoint
@login_required
def download_file(file_id: int):
    connection = get_database_connection()              # Get DB connection
    file_record = connection.execute(                   # Retrieve file metadata
        "SELECT real_name, saved_name FROM files "
        "WHERE id = ? AND owner_id = ?", (file_id, session["user_id"])
    ).fetchone()

    if file_record is None:                             # No record → not found / no rights
        flash("File not found or access denied.")
        return redirect(url_for("file_list"))

    file_path = UPLOAD_DIRECTORY / file_record["saved_name"]   # Actual file path
    if not file_path.exists():                          # Physical file missing
        flash("Physical file missing.")
        return redirect(url_for("file_list"))

    return send_file(file_path, as_attachment=True,     # Stream file to client
                     download_name=file_record["real_name"])

@app.route("/delete/<int:file_id>")                     # Delete endpoint
@login_required
def delete_file(file_id: int):
    connection = get_database_connection()              # Get DB connection
    file_record = connection.execute(                   # Fetch record to delete
        "SELECT saved_name FROM files "
        "WHERE id = ? AND owner_id = ?", (file_id, session["user_id"])
    ).fetchone()

    if file_record is None:                             # Record not found / no rights
        flash("File not found or access denied.")
        return redirect(url_for("file_list"))

    try:
        os.remove(UPLOAD_DIRECTORY / file_record["saved_name"]) # Remove from disk
    except FileNotFoundError:                           # Ignore if already gone
        pass

    connection.execute("DELETE FROM files WHERE id = ?", (file_id,))  # Remove DB row
    connection.commit()
    flash("File deleted.")
    return redirect(url_for("file_list"))

# ────────────────────────── HTML template strings ──────────────────────
CUSTOM_CSS = """                                         
<style>
:root{
  --main-red: rgb(120,0,0);                             /* Main brand color */
  --main-red-light: rgba(120,0,0,0.1);                  /* Light variant */
}
body          { background-color: #fff7f7; }            /* Light pinkish background */
.navbar,
.btn-primary  { background-color: var(--main-red)!important; border-color: var(--main-red)!important; }
.btn-primary:hover { background-color: rgb(150,20,20)!important; } /* Darker on hover */
.table thead  { background-color: var(--main-red-light); }          /* Light red table head */
.form-control:focus {                                   /* Red focus border for inputs */
  border-color: var(--main-red);
  box-shadow: 0 0 0 .2rem rgba(120,0,0,.25);
}
.btn-outline-light:hover{ background-color:#fff; color:var(--main-red)!important; } /* Logout hover */
</style>
"""

BASE_TEMPLATE = f"""                                   
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{{{ page_title }}}}</title>
<link rel="stylesheet"
      href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
{CUSTOM_CSS}
</head>
<body>
<nav class="navbar navbar-dark mb-4">                   <!-- Top navigation bar -->
  <div class="container-fluid">
    <a class="navbar-brand" href="{{{{ url_for('file_list') }}}}">Dark-Red Disk</a>
    {{% if session.get('user_id') %}}
       <span class="text-white me-3">Hello, {{{{ session['username'] }}}}</span>
       <a class="btn btn-sm btn-outline-light" href="{{{{ url_for('logout') }}}}">Logout</a>
    {{% endif %}}
  </div>
</nav>

<div class="container">                                <!-- Page content wrapper -->
  {{% with messages = get_flashed_messages() %}}
    {{% for message in messages %}}
      <div class="alert alert-info">{{{{ message }}}}</div>
    {{% endfor %}}
  {{% endwith %}}

  {{{{ page_content }}}}                               <!-- Inject route-specific HTML -->
</div>
</body>
</html>
"""

REGISTER_HTML = """                                     <!-- Registration form -->
<div class="row justify-content-center">
  <div class="col-md-4">
    <h4 class="text-center mb-4">Create Account</h4>
    <form method="post">
      <input name="username" class="form-control mb-3" placeholder="Username" required>
      <input type="password" name="password" class="form-control mb-3" placeholder="Password" required>
      <button class="btn btn-primary w-100">Register</button>
    </form>
    <div class="text-center mt-3">
      Already have an account? <a href="{{ url_for('login') }}">Login</a>
    </div>
  </div>
</div>
"""

LOGIN_HTML = """                                         <!-- Login form -->
<div class="row justify-content-center">
  <div class="col-md-4">
    <h4 class="text-center mb-4">User Login</h4>
    <form method="post">
      <input name="username" class="form-control mb-3" placeholder="Username" required>
      <input type="password" name="password" class="form-control mb-3" placeholder="Password" required>
      <button class="btn btn-primary w-100">Login</button>
    </form>
    <div class="text-center mt-3">
      No account? <a href="{{ url_for('register') }}">Register</a>
    </div>
  </div>
</div>
"""

LIST_HTML = """                                          <!-- File list + upload -->
<form class="mb-4" method="post" action="{{ url_for('upload_file') }}" enctype="multipart/form-data">
  <div class="input-group">
    <input type="file" name="file" class="form-control" required>
    <button class="btn btn-primary">Upload</button>
  </div>
</form>

<table class="table table-bordered align-middle">
  <thead>
    <tr>
      <th style="width:60px;">#</th>
      <th>Filename</th>
      <th style="width:180px;">Uploaded At</th>
      <th style="width:170px;">Actions</th>
    </tr>
  </thead>
  <tbody>
    {% for file_record in file_records %}
      <tr>
        <td>{{ loop.index }}</td>
        <td>{{ file_record["real_name"] }}</td>
        <td>{{ file_record["uploaded_at"] }}</td>
        <td>
          <a class="btn btn-sm btn-success"
             href="{{ url_for('download_file', file_id=file_record['id']) }}">Download</a>
          <a class="btn btn-sm btn-danger"
             href="{{ url_for('delete_file', file_id=file_record['id']) }}"
             onclick="return confirm('Delete this file?');">Delete</a>
        </td>
      </tr>
    {% else %}
      <tr><td colspan="4" class="text-center">No files yet.</td></tr>
    {% endfor %}
  </tbody>
</table>
"""

# ────────────────────────── Application entry point ────────────────────
if __name__ == "__main__":                              # Execute only if run directly
    app.run(debug=False)                                 # Enable Flask debug server
