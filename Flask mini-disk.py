#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Flask mini-disk Cloud Storage Demo
----------------------------------
Features:
- User registration, login, logout (account/password)
- Per-user file upload, download, listing and deletion (files stored by user, not in database)
- Each user can only view and operate on his/her own files
- Pure red color theme, large fonts and buttons for easy operation

Requirements:
- Python 3.x
- Flask (pip install flask)
- Werkzeug (Flask will install automatically)
- The script will create 'uploads/' and 'disk.db' under the script folder

Design:
- Files are stored under uploads/ as 'userID_uuid_originalname' for separation and uniqueness
- User data is stored in a sqlite3 database - it will auto-create one if missing
- All file types are accepted (modify ALLOWED_EXTENSIONS if needed)
- All templates use Jinja2 expressions and are correctly rendered (including links)
- All pages/components use large fonts and buttons for a friendly experience

Author: (your name)
Date: (date)
"""

import os                              # Filesystem operations
import uuid                            # For unique file naming
import sqlite3                         # For user account storage
from datetime import datetime          # For file time display
from pathlib import Path               # For platform-independent file paths
from functools import wraps            # For login-required decorator
from flask import (
    Flask, g, request, redirect, url_for,
    render_template_string, flash, send_file, session)
from werkzeug.security import (
    generate_password_hash, check_password_hash)       # Secure password storage
from werkzeug.utils import secure_filename             # Sanitize filenames

# ---- Configuration ----
BASE_DIRECTORY = Path(__file__).resolve().parent       # Script root directory
DATABASE_PATH = BASE_DIRECTORY / "disk.db"             # SQLite DB file
UPLOAD_DIRECTORY = BASE_DIRECTORY / "uploads"          # Upload folder path
UPLOAD_DIRECTORY.mkdir(exist_ok=True)                  # Create if missing
app = Flask(__name__)
app.config["SECRET_KEY"] = "please-change-me"          # Session encryption (change in production)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024    # Max upload size: 50MB per file
ALLOWED_EXTENSIONS = set()                             # Allow all file extensions

# ---- Database connection and user table creation ----
def get_db():
    """Get or create per-request sqlite3 connection, with Row dict support."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(exception):
    """Close per-request database connection if it exists."""
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    """Create user table if not exists, called at launch."""
    db = sqlite3.connect(DATABASE_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        username  TEXT UNIQUE NOT NULL,
        password  TEXT NOT NULL
    );
    """)
    db.commit()
    db.close()
init_db()                                              # Ensure table exists at startup

# ---- Utility functions ----
def is_allowed(filename: str) -> bool:
    """
    Check if uploaded file extension is allowed.
    Returns True for any extension unless ALLOWED_EXTENSIONS is set.
    """
    if "." not in filename:
        return False
    if not ALLOWED_EXTENSIONS:
        return True
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def login_required(view):
    """
    Decorator: require login status or redirect to login page.
    """
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped

def get_user_files(user_id: int):
    """
    Scan uploads folder, return info of all files belonging to this user.
    Returns: List of dicts: stored name, display/original name, and upload date string.
    Sorted by upload time descending.
    """
    files = []
    for name in os.listdir(UPLOAD_DIRECTORY):
        if not name:
            continue
        parts = name.split("_", 2)
        if len(parts) < 3:
            continue
        if parts[0] != str(user_id):
            continue  # Only show own files
        file_path = UPLOAD_DIRECTORY / name
        modified = datetime.fromtimestamp(file_path.stat().st_mtime)
        files.append({
            "stored_name": name,
            "original_name": parts[2],   # Recover original filename for user
            "uploaded_at": modified.strftime("%Y-%m-%d %H:%M:%S")
        })
    files.sort(key=lambda item: item["uploaded_at"], reverse=True)
    return files

# ---- Style and template constants ----
CUSTOM_CSS = """
<style>
:root{
  --pure-red: rgb(255,0,0);
  --pure-red-light: rgba(255,0,0,0.13);
}
body {
  background-color: #fffafa;
  font-family: "Segoe UI", Arial, sans-serif;
  font-size: 1.22rem;
}
.container {
  max-width: 580px;
  margin: 0 auto;
}
.navbar, .btn-primary {
  background-color: var(--pure-red)!important;
  border-color: var(--pure-red)!important;
}
.navbar {
  min-height: 44px !important;           /* Adjust navbar height (reduce) */
  padding-top: 0.15rem !important;
  padding-bottom: 0.15rem !important;
}
.navbar-brand {
  font-size: 1.35rem !important;         /* Smaller font for the logo */
  padding-top: 0.08rem !important;
  padding-bottom: 0.08rem !important;
  margin-bottom: 0 !important;
  margin-top: 0 !important;
}
.btn-primary:hover, .btn-primary:focus {
  background-color: #d70000!important;
}
.table thead {
  background-color: var(--pure-red-light);
}
.form-control:focus {
  border-color: var(--pure-red);
  box-shadow: 0 0 0 .21rem rgba(255,0,0,.19);
}
.btn-outline-light:hover {
  background-color: #fff;
  color: var(--pure-red)!important;
}
input, button, .form-control, .btn {
  font-size: 1.17rem;
  min-height: 2.5rem;
}
h4 { font-size: 2.2rem; }
.alert { font-size: 1.12rem; }
</style>
"""

BASE_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{ page_title }}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
""" + CUSTOM_CSS + """
</head>
<body>
<nav class="navbar navbar-dark mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{ url_for('file_list') }}">Pure Red Disk</a>
    {% if session.get('user_id') %}
      <span class="text-white me-3" style="font-size:1.19rem;">Hello, {{ session['username'] }}</span>
      <a class="btn btn-sm btn-outline-light" href="{{ url_for('logout') }}" style="font-size:1.13rem;">Logout</a>
    {% endif %}
  </div>
</nav>
<div class="container">
  {% with messages = get_flashed_messages() %}
    {% for msg in messages %}
      <div class="alert alert-info mt-3">{{ msg }}</div>
    {% endfor %}
  {% endwith %}
  {{ page_content|safe }}
</div>
</body>
</html>
"""

REGISTER_HTML = """
<div class="row justify-content-center">
  <div class="col-12">
    <h4 class="text-center mb-4">Create Account</h4>
    <form method="post" autocomplete="off">
      <input name="username" class="form-control mb-3" placeholder="Username" required>
      <input type="password" name="password" class="form-control mb-3" placeholder="Password" required>
      <button class="btn btn-primary w-100 mb-2" style="font-size:1.19rem;">Register</button>
    </form>
    <div class="text-center mt-3" style="font-size:1.06rem;">
      Already have an account?
      <a href="{{ url_for('login') }}"><b>Login</b></a>
    </div>
  </div>
</div>
"""

LOGIN_HTML = """
<div class="row justify-content-center">
  <div class="col-12">
    <h4 class="text-center mb-4">User Login</h4>
    <form method="post" autocomplete="off">
      <input name="username" class="form-control mb-3" placeholder="Username" required>
      <input type="password" name="password" class="form-control mb-3" placeholder="Password" required>
      <button class="btn btn-primary w-100 mb-2" style="font-size:1.19rem;">Login</button>
    </form>
    <div class="text-center mt-3" style="font-size:1.06rem;">
      No account?
      <a href="{{ url_for('register') }}"><b>Register</b></a>
    </div>
  </div>
</div>
"""

LIST_HTML = """
<form class="mb-4" method="post" action="{{ url_for('upload_file') }}" enctype="multipart/form-data">
  <div class="input-group">
    <input type="file" name="file" class="form-control" required>
    <button class="btn btn-primary" style="font-size:1.13rem;">Upload</button>
  </div>
</form>
<table class="table table-bordered align-middle" style="font-size:1.07rem;">
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
        <td>{{ file_record.original_name }}</td>
        <td>{{ file_record.uploaded_at }}</td>
        <td>
          <a class="btn btn-sm btn-success"
             href="{{ url_for('download_file', stored_name=file_record.stored_name) }}"
             style="font-size:1.07rem;">Download</a>
          <a class="btn btn-sm btn-danger"
             href="{{ url_for('delete_file', stored_name=file_record.stored_name) }}"
             onclick="return confirm('Delete this file?');"
             style="font-size:1.07rem;">Delete</a>
        </td>
      </tr>
    {% else %}
      <tr><td colspan="4" class="text-center">No files yet.</td></tr>
    {% endfor %}
  </tbody>
</table>
"""

# ---- Authentication and main routes ----

@app.route("/register", methods=["GET", "POST"])
def register():
    """
    User registration page and logic.
    GET: display form; POST: register and redirect to login.
    """
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        if not username or not password:
            flash("Username and password cannot be empty.")
            return redirect(url_for("register"))
        db = get_db()
        try:
            db.execute(
                "INSERT INTO users(username, password) VALUES(?, ?)",
                (username, generate_password_hash(password))
            )
            db.commit()
            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username already taken.")
            return redirect(url_for("register"))
    # Render sub-template first, then pass result into base template
    inner_html = render_template_string(REGISTER_HTML)
    return render_template_string(
        BASE_TEMPLATE,
        page_title="Register",
        page_content=inner_html
    )

@app.route("/login", methods=["GET", "POST"])
def login():
    """
    User login page and credential authentication.
    GET: display form; POST: check account.
    """
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"].strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?",
                          (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()                         # Remove old session keys
            session["user_id"] = user["id"]        # Save user id
            session["username"] = user["username"] # Save username
            return redirect(url_for("file_list"))
        flash("Incorrect username or password.")
        return redirect(url_for("login"))
    inner_html = render_template_string(LOGIN_HTML) # Render so url_for works!
    return render_template_string(
        BASE_TEMPLATE,
        page_title="Login",
        page_content=inner_html
    )

@app.route("/logout")
def logout():
    """
    Log out and clear login session.
    """
    session.clear()
    flash("Logged out.")
    return redirect(url_for("login"))

@app.route("/", methods=["GET"])
@login_required
def file_list():
    """
    Main page: show file list for current user, plus upload UI.
    """
    user_id = session["user_id"]
    files = get_user_files(user_id)
    inner_html = render_template_string(LIST_HTML, file_records=files)
    return render_template_string(
        BASE_TEMPLATE,
        page_title="My Files",
        page_content=inner_html
    )

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():
    """
    Handle file upload (for logged-in user).
    """
    uploaded = request.files.get("file")
    if uploaded is None or uploaded.filename == "":
        flash("No file selected.")
        return redirect(url_for("file_list"))
    if not is_allowed(uploaded.filename):
        flash("File type not allowed.")
        return redirect(url_for("file_list"))
    original = secure_filename(uploaded.filename)       # Original, safe name
    unique_part = uuid.uuid4().hex                      # Random uuid
    stored_name = f"{session['user_id']}_{unique_part}_{original}"  # On disk
    uploaded.save(UPLOAD_DIRECTORY / stored_name)
    flash("Upload successful.")
    return redirect(url_for("file_list"))

@app.route("/download/<path:stored_name>")
@login_required
def download_file(stored_name):
    """
    Download a file (only allowed for the owner).
    """
    if not stored_name.startswith(str(session["user_id"]) + "_"):
        flash("Access denied.")
        return redirect(url_for("file_list"))
    file_path = UPLOAD_DIRECTORY / stored_name
    if not file_path.exists():
        flash("File not found.")
        return redirect(url_for("file_list"))
    original = stored_name.split("_", 2)[2]    # Restore original filename
    return send_file(file_path, as_attachment=True, download_name=original)

@app.route("/delete/<path:stored_name>")
@login_required
def delete_file(stored_name):
    """
    Delete file (only allowed for the owner).
    """
    if not stored_name.startswith(str(session["user_id"]) + "_"):
        flash("Access denied.")
        return redirect(url_for("file_list"))
    file_path = UPLOAD_DIRECTORY / stored_name
    try:
        os.remove(file_path)
        flash("File deleted.")
    except FileNotFoundError:
        flash("File not found.")
    return redirect(url_for("file_list"))

# ---- Application entrypoint ----
if __name__ == "__main__":
    app.run(debug=False)
