#!/usr/bin/env python3  # Execute with Python 3
# -*- coding: utf-8 -*-  # Source encoding

"""
Flask mini-disk: upload / download / list / delete
Theme color: rgb(120, 0, 0) (dark red)
Files are NOT stored in the database; the program only scans the
uploads folder with os.listdir when information is required.
"""

import os                                               # File-system utilities
import uuid                                             # Random unique IDs
import sqlite3                                          # Embedded SQL database
from datetime import datetime                           # Date and time helper
from pathlib import Path                                # Path object helper
from functools import wraps                             # Decorator helpe
from flask import (                                     # Flask framework imports
    Flask, g, request, redirect, url_for,
    render_template_string, flash, send_file, session)
from werkzeug.security import (                         # Hashing helpers
    generate_password_hash, check_password_hash)
from werkzeug.utils import secure_filename              # Sanitise file names
# ────────────────────────── Basic configuration ──────────────────────────
BASE_DIRECTORY = Path(__file__).resolve().parent        # Folder where app.py lives
DATABASE_PATH = BASE_DIRECTORY / "disk.db"              # SQLite file path
UPLOAD_DIRECTORY = BASE_DIRECTORY / "uploads"           # Folder for all files
UPLOAD_DIRECTORY.mkdir(exist_ok=True)                   # Create if missing
app = Flask(__name__)                                   # Flask application object
app.config["SECRET_KEY"] = "please-change-me"           # Session secret key
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024     # 50 MB per upload
ALLOWED_EXTENSIONS = set()                              # Empty → every extension allowed
# ────────────────────────── Database helpers ────────────────────────────
def get_db():                                           # Return (or create) DB connection
    if "db" not in g:                                   # g = request-global storage
        g.db = sqlite3.connect(DATABASE_PATH)           # New connection
        g.db.row_factory = sqlite3.Row                  # Row behaves like dict
    return g.db                                         # Connection for this request

@app.teardown_appcontext
def close_db(exception):                                # Close connection after request
    db = g.pop("db", None)                              # Remove from g
    if db is not None:                                  # If a connection exists
        db.close()                                      # Close it

def init_db():                                          # Create tables if they do not exist
    db = sqlite3.connect(DATABASE_PATH)                 # Temporary connection
    db.executescript("""                                # Execute many SQL commands
    CREATE TABLE IF NOT EXISTS users (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,    -- User ID
        username  TEXT UNIQUE NOT NULL,                 -- Log-in name
        password  TEXT NOT NULL                         -- Hashed password
    );
    """)
    db.commit()                                         # Save schema
    db.close()                                          # Close temp connection
init_db()                                               # Ensure schema ready
# ────────────────────────── Utility functions ───────────────────────────
def is_allowed(filename: str) -> bool:                  # Validate file extension
    if "." not in filename:                             # Reject if no dot
        return False
    if not ALLOWED_EXTENSIONS:                          # Empty set → allow all
        return True
    ext = filename.rsplit(".", 1)[1].lower()            # Get extension
    return ext in ALLOWED_EXTENSIONS                    # True if allowed

def login_required(view):                               # Decorator to enforce log-in
    @wraps(view)                                        # Keep original metadata
    def wrapped(*args, **kwargs):                       # Wrapper function
        if "user_id" not in session:                    # Not authenticated
            flash("Please log in first.")               # Inform user
            return redirect(url_for("login"))           # Go to login page
        return view(*args, **kwargs)                    # Continue if logged in
    return wrapped                                      # Return new function

def get_user_files(user_id: int):                       # Return list of files for user
    files = []                                          # List of dictionaries
    for name in os.listdir(UPLOAD_DIRECTORY):           # Iterate over every file
        if not name:                                    # Skip empty names
            continue
        parts = name.split("_", 2)                      # Format: userID_uuid_original
        if len(parts) < 3:                              # Malformed name
            continue
        if parts[0] != str(user_id):                    # Not this owner
            continue
        file_path = UPLOAD_DIRECTORY / name             # Full path
        modified = datetime.fromtimestamp(              # Read modification time
            file_path.stat().st_mtime)
        files.append({                                  # Append information dict
            "stored_name": name,                        # Name on disk
            "original_name": parts[2],                  # Original filename
            "uploaded_at": modified.strftime("%Y-%m-%d %H:%M:%S")  # Nice time
        })
    files.sort(key=lambda item: item["uploaded_at"], reverse=True)  # Newest first
    return files                                        # Return list
# ────────────────────────── Authentication routes ──────────────────────
@app.route("/register", methods=["GET", "POST"])        # Sign-up page
def register():
    if request.method == "POST":                        # Form submitted
        username = request.form["username"].strip()     # Field: username
        password = request.form["password"].strip()     # Field: password
        if not username or not password:                # Validate non-empty
            flash("Username and password cannot be empty.")
            return redirect(url_for("register"))
        db = get_db()                                   # DB connection
        try:                                            # Attempt insert
            db.execute("INSERT INTO users(username, password) VALUES(?, ?)",
                       (username, generate_password_hash(password)))
            db.commit()
            flash("Registration successful. Please log in.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:                  # Duplicate name
            flash("Username already taken.")
            return redirect(url_for("register"))
    return render_template_string(                      # Render sign-up form
        BASE_TEMPLATE.format(page_title="Register", page_content=REGISTER_HTML))
@app.route("/login", methods=["GET", "POST"])           # Log-in page
def login():
    if request.method == "POST":                        # Credentials posted
        username = request.form["username"].strip()     # Username
        password = request.form["password"].strip()     # Password
        db = get_db()                                   # DB connection
        user = db.execute("SELECT * FROM users WHERE username = ?",
                          (username,)).fetchone()
        if user and check_password_hash(user["password"], password):
            session.clear()                             # Start fresh session
            session["user_id"] = user["id"]             # Store ID
            session["username"] = user["username"]      # Store name
            return redirect(url_for("file_list"))       # Go to list
        flash("Incorrect username or password.")        # Bad credentials
        return redirect(url_for("login"))
    return render_template_string(                      # Show login form
        BASE_TEMPLATE.format(page_title="Login", page_content=LOGIN_HTML))
@app.route("/logout")                                   # Log-out route
def logout():
    session.clear()                                     # Remove session keys
    flash("Logged out.")                                # Notify
    return redirect(url_for("login"))                   # Back to login
# ────────────────────────── File-handling routes ───────────────────────
@app.route("/", methods=["GET"])                        # Main page = file list
@login_required
def file_list():
    user_id = session["user_id"]                        # Current user ID
    files = get_user_files(user_id)                     # List of user files
    return render_template_string(                      # Render using template
        BASE_TEMPLATE.format(page_title="My Files", page_content=LIST_HTML),
        file_records=files)
@app.route("/upload", methods=["POST"])                 # Handle upload
@login_required
def upload_file():
    uploaded = request.files.get("file")                # Input type="file"
    if uploaded is None or uploaded.filename == "":     # Nothing selected
        flash("No file selected.")
        return redirect(url_for("file_list"))
    if not is_allowed(uploaded.filename):               # Extension blocked
        flash("File type not allowed.")
        return redirect(url_for("file_list"))
    original = secure_filename(uploaded.filename)       # Clean original name
    unique_part = uuid.uuid4().hex                      # Random hex
    stored_name = f"{session['user_id']}_{unique_part}_{original}"  # Disk name
    uploaded.save(UPLOAD_DIRECTORY / stored_name)       # Persist file
    flash("Upload successful.")                         # Notify user
    return redirect(url_for("file_list"))               # Back to list
@app.route("/download/<path:stored_name>")              # Download link
@login_required
def download_file(stored_name):
    if not stored_name.startswith(str(session["user_id"]) + "_"):    # Ownership check
        flash("Access denied.")                         # Not your file
        return redirect(url_for("file_list"))
    file_path = UPLOAD_DIRECTORY / stored_name          # Full file path
    if not file_path.exists():                          # Missing file
        flash("File not found.")
        return redirect(url_for("file_list"))
    original = stored_name.split("_", 2)[2]             # Extract original name
    return send_file(file_path, as_attachment=True,     # Send to browser
                     download_name=original)
@app.route("/delete/<path:stored_name>")                # Delete link
@login_required
def delete_file(stored_name):
    if not stored_name.startswith(str(session["user_id"]) + "_"):    # Check owner
        flash("Access denied.")
        return redirect(url_for("file_list"))
    file_path = UPLOAD_DIRECTORY / stored_name          # Full path
    try:
        os.remove(file_path)                            # Attempt deletion
        flash("File deleted.")
    except FileNotFoundError:                           # Already removed
        flash("File not found.")
    return redirect(url_for("file_list"))               # Back to lis
# ────────────────────────── HTML templates ─────────────────────────────
CUSTOM_CSS = """
<style>
:root{
  --main-red: rgb(120,0,0);                             /* Brand color */
  --main-red-light: rgba(120,0,0,0.1);                  /* Light variant */
}
body          { background-color: #fff7f7; }            /* Soft pink background */
.navbar,
.btn-primary  { background-color: var(--main-red)!important; border-color: var(--main-red)!important; }
.btn-primary:hover { background-color: rgb(150,20,20)!important; } /* Hover */
.table thead  { background-color: var(--main-red-light); }          /* Table head */
.form-control:focus { border-color: var(--main-red); box-shadow: 0 0 0 .2rem rgba(120,0,0,.25); }
.btn-outline-light:hover { background-color:#fff; color:var(--main-red)!important; } /* Logout hover */
</style>
"""

BASE_TEMPLATE = f"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{{{{ page_title }}}}</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
{CUSTOM_CSS}
</head>
<body>
<nav class="navbar navbar-dark mb-4">
  <div class="container-fluid">
    <a class="navbar-brand" href="{{{{ url_for('file_list') }}}}">Dark-Red Disk</a>
    {{% if session.get('user_id') %}}
      <span class="text-white me-3">Hello, {{{{ session['username'] }}}}</span>
      <a class="btn btn-sm btn-outline-light" href="{{{{ url_for('logout') }}}}">Logout</a>
    {{% endif %}}
  </div>
</nav>
<div class="container">
  {{% with messages = get_flashed_messages() %}}
    {{% for msg in messages %}}
      <div class="alert alert-info">{{{{ msg }}}}</div>
    {{% endfor %}}
  {{% endwith %}}
  {{{{ page_content }}}}                               <!-- Route-specific HTML -->
</div>
</body>
</html>
"""

REGISTER_HTML = """
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

LOGIN_HTML = """
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

LIST_HTML = """
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
        <td>{{ file_record.original_name }}</td>
        <td>{{ file_record.uploaded_at }}</td>
        <td>
          <a class="btn btn-sm btn-success"
             href="{{ url_for('download_file', stored_name=file_record.stored_name) }}">Download</a>
          <a class="btn btn-sm btn-danger"
             href="{{ url_for('delete_file', stored_name=file_record.stored_name) }}"
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
if __name__ == "__main__":                              # Run only when executed directly
    app.run(debug=True)                                 # Start Flask dev server
