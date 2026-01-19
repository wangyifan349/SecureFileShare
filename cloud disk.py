"""
File: app.py
Author: Wang YiFan
Description:
    This is a simple multi-user personal cloud disk system built with Flask.
    It supports user registration, login, password change, and the main file operations: 
    listing directories, single/multiple file uploads, batch deletion, batch moves, 
    single file download, download entire folder as zip, (all operations are relative to the user's root).
    The interface is rendered with Bootstrap and styled in a red-gold Chinese New Year vibe.
    All code and HTML are in this file. Fully commented in English, and all variables use 
    meaningful, standard English names.
Usage:
    pip install flask
    python app.py
    Visit http://127.0.0.1:5000/
    Each user manages their own files in separated directories.
Note:
    This code is for study/teaching/demo only. Not for production use.
"""

import os
import sqlite3
import shutil
import zipfile
import io
from flask import Flask, request, session, redirect, url_for, send_from_directory, abort, flash, get_flashed_messages, Response

from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# =========================
# Flask and App Settings
# =========================
app = Flask(__name__)
app.secret_key = 'goldenredcloudpan' # Secret for session
app.config['UPLOAD_FOLDER'] = os.path.abspath('user_files') # Root for all user files

DATABASE_FILE = 'cloud_disk.db'
ALLOWED_EXTENSIONS = set([
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif',
    'zip', 'doc', 'docx', 'ppt', 'pptx', 'xls', 'xlsx'
])

# ====================================
# Database Initialization
# ====================================
def get_database_connection():
    """Create a new database connection."""
    conn = sqlite3.connect(DATABASE_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    """Create users table if not exists."""
    conn = get_database_connection()
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()

@app.before_first_request
def setup_app():
    """Create upload folder and initialize database at first run."""
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    initialize_database()

# ==============================
# Utility Functions
# ==============================
def get_current_username():
    """Get the current logged-in user."""
    return session.get('username')

def login_required(view_func):
    """Decorator to force login for any view."""
    def wrapper(*args, **kwargs):
        if not get_current_username():
            return redirect(url_for('login'))
        return view_func(*args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper

def is_allowed_file(filename):
    """Check file extension against whitelist."""
    if '.' not in filename:
        return False
    extension = filename.rsplit('.', 1)[1].lower()
    return extension in ALLOWED_EXTENSIONS

def normalize_and_secure_subpath(subpath):
    """
    Security: Forbid absolute paths or directory traversal.
    Return a safe relative path or abort.
    """
    if not subpath:
        return ''
    # Convert backslash to slash, split, check for '..'
    if os.path.isabs(subpath) or '..' in subpath.replace("\\", "/").split("/"):
        abort(400, "Invalid path")
    return subpath

def get_user_root_folder(username):
    """Return the absolute path of the user's root folder."""
    return os.path.join(app.config['UPLOAD_FOLDER'], username)

def get_full_user_path(relative_subpath):
    """Get full user path securely from given relative path."""
    username = get_current_username()
    user_root = get_user_root_folder(username)
    safe_rel = normalize_and_secure_subpath(relative_subpath)
    full_path = os.path.normpath(os.path.join(user_root, safe_rel))
    if not full_path.startswith(user_root):
        abort(403)
    return full_path

def list_all_user_dirs(current_full_path, user_root_path):
    """
    Return all directories (relative paths to root) for moving target choices.
    Args:
      current_full_path: current path to scan in
      user_root_path: user's root folder
    Returns:
      list of relative dirs as strings (e.g. [".", "notes", "docs/work"])
    """
    result_list = []
    for dir_path, dir_names, file_names in os.walk(current_full_path):
        for dir_name in dir_names:
            abs_dir = os.path.join(dir_path, dir_name)
            relative_dir = os.path.relpath(abs_dir, user_root_path)
            result_list.append(relative_dir)
    return result_list

# ===============================
# Main Cloud Disk Index/Filelist
# ===============================
@app.route('/', defaults={'subpath': ''})
@app.route('/<path:subpath>')
@login_required
def index(subpath=''):
    """
    Display the user's current directory, list files and folders,
    allow batch operations and upload.
    """
    subpath = normalize_and_secure_subpath(subpath)
    user_root = get_user_root_folder(get_current_username())
    current_dir = os.path.normpath(os.path.join(user_root, subpath))
    if not current_dir.startswith(user_root):
        abort(403)

    # Ensure the directory exists
    if not os.path.exists(current_dir):
        os.makedirs(current_dir)
    
    # Build item list for table
    item_list = []
    file_names_in_dir = os.listdir(current_dir)
    for filename in file_names_in_dir:
        absolute_path = os.path.join(current_dir, filename)
        if os.path.isdir(absolute_path):
            item_list.append({
                'name': filename,
                'is_dir': True,
                'size': '',
                'subpath': os.path.normpath(os.path.join(subpath, filename))
            })
        else:
            # Get file size in KB, 2 decimals
            try:
                size_kb = round(os.path.getsize(absolute_path) / 1024, 2)
            except:
                size_kb = ''
            item_list.append({
                'name': filename,
                'is_dir': False,
                'size': size_kb,
                'subpath': os.path.normpath(os.path.join(subpath, filename))
            })
    # Sort: directories first, then files, both by name
    item_list.sort(key=lambda x: (not x['is_dir'], x['name'].lower()))

    # Get all directories for <select> in "move"
    all_sub_dirs = ['.']
    all_dirs_found = list_all_user_dirs(user_root, user_root)
    for relative_dir in all_dirs_found:
        all_sub_dirs.append(relative_dir)
    # Remove duplicates, sort results
    all_sub_dirs = sorted(list(set(all_sub_dirs)))

    parent_dir_subpath = os.path.dirname(subpath)
    current_path_display = "/" + subpath if subpath else "/"

    # HTML render with helper
    html = render_main_page_html(
        item_list,
        current_path_display,
        parent_dir_subpath,
        subpath,
        all_sub_dirs,
        get_flashed_messages()
    )
    return html

# ===============================
# User Registration
# ===============================
@app.route('/register', methods=["GET", "POST"])
def register():
    """
    New user registration page.
    """
    tip_message = ''
    if get_current_username():
        return redirect(url_for('index'))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            tip_message = "Username and password cannot be empty"
        else:
            conn = get_database_connection()
            cursor = conn.cursor()
            try:
                cursor.execute(
                    'INSERT INTO users (username, password) VALUES (?, ?)', 
                    (username, generate_password_hash(password))
                )
                conn.commit()
                user_directory = get_user_root_folder(username)
                if not os.path.exists(user_directory):
                    os.makedirs(user_directory)
                tip_message = "Registration successful, please login"
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                tip_message = "The username already exists"
            finally:
                conn.close()
    return render_simple_html('User Registration', """
        <form method="post" style="max-width:350px;margin:auto;">
            <div class="mb-3">
                <label class="form-label">Username</label>
                <input name="username" class="form-control" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <input type="password" name="password" class="form-control" required>
            </div>
            <input type="submit" class="btn btn-danger" value="Register">
        </form>
        <div style='text-align:center;margin-top:8px;'><a href='/login'>Already have an account? Login</a></div>
    """, tip_message)

# ===============================
# User Login
# ===============================
@app.route('/login', methods=["GET", "POST"])
def login():
    """
    User login view.
    """
    tip_message = ''
    if get_current_username():
        return redirect(url_for('index'))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_database_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE username=?', (username,))
        user_record = cursor.fetchone()
        conn.close()
        if not user_record or not check_password_hash(user_record["password"], password):
            tip_message = "Wrong username or password"
        else:
            session["username"] = username
            return redirect(url_for('index'))
    return render_simple_html('User Login', """
        <form method="post" style="max-width:350px;margin:auto;">
            <div class="mb-3">
                <label class="form-label">Username</label>
                <input name="username" class="form-control" required>
            </div>
            <div class="mb-3">
                <label class="form-label">Password</label>
                <input type="password" name="password" class="form-control" required>
            </div>
            <input type="submit" class="btn btn-warning" value="Login">
        </form>
        <div style='text-align:center;margin-top:8px;'><a href='/register'>No account? Register</a></div>
    """, tip_message)

# ===============================
# Logout
# ===============================
@app.route('/logout')
def logout():
    """
    User logout, clears all session data.
    """
    session.clear()
    return redirect(url_for('login'))

# ===============================
# Change Password
# ===============================
@app.route('/change_password', methods=["GET", "POST"])
@login_required
def change_password():
    """
    User changes their password.
    """
    tip_message = ''
    if request.method == "POST":
        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        if not old_password or not new_password:
            tip_message = "Password fields cannot be empty"
        else:
            conn = get_database_connection()
            cursor = conn.cursor()
            cursor.execute(
                'SELECT password FROM users WHERE username=?', 
                (get_current_username(),)
            )
            record = cursor.fetchone()
            if not record or not check_password_hash(record["password"], old_password):
                tip_message = "Original password incorrect"
            else:
                cursor.execute(
                    'UPDATE users SET password=? WHERE username=?', 
                    (generate_password_hash(new_password), get_current_username())
                )
                conn.commit()
                tip_message = "Password changed successfully"
            conn.close()
    return render_simple_html('Change Password', """
        <form method="post" style="max-width:350px;margin:auto;">
            <div class="mb-3">
                <label class="form-label">Old Password</label>
                <input type="password" name="old_password" class="form-control" required>
            </div>
            <div class="mb-3">
                <label class="form-label">New Password</label>
                <input type="password" name="new_password" class="form-control" required>
            </div>
            <input type="submit" class="btn btn-danger" value="Change Password">
        </form>
    """, tip_message)

# ===============================
# Upload Files (support multiple)
# ===============================
@app.route('/upload', methods=["POST"])
@login_required
def upload_file():
    """
    Handle file upload (support multiple).
    """
    relative_subpath = request.form.get('subpath', '')
    upload_directory = get_full_user_path(relative_subpath)
    if not os.path.exists(upload_directory):
        os.makedirs(upload_directory)
    if 'file' not in request.files:
        flash('Please select file(s)')
        return redirect(url_for('index', subpath=relative_subpath))
    uploaded_files = request.files.getlist('file')
    success_count = 0
    for file_item in uploaded_files:
        if not file_item.filename:
            continue
        filename = secure_filename(file_item.filename)
        if is_allowed_file(filename):
            file_item.save(os.path.join(upload_directory, filename))
            success_count += 1
    if success_count == 0:
        flash("No allowed files uploaded")
    else:
        flash(f"Successfully uploaded {success_count} file(s)")
    return redirect(url_for('index', subpath=relative_subpath))

# ===============================
# Create New Directory
# ===============================
@app.route('/mkdir', methods=["POST"])
@login_required
def create_directory():
    """
    Create new directory (subfolder) in current path.
    """
    relative_subpath = request.form.get('subpath', '')
    new_folder_name = request.form.get("new_folder", "").strip()
    if not new_folder_name or any(char in new_folder_name for char in r'\/<>:"|?*'):
        flash("Folder name cannot contain special characters")
        return redirect(url_for('index', subpath=relative_subpath))
    current_directory = get_full_user_path(relative_subpath)
    new_folder_path = os.path.join(current_directory, new_folder_name)
    if not new_folder_path.startswith(get_user_root_folder(get_current_username())):
        abort(403)
    if not os.path.exists(new_folder_path):
        os.makedirs(new_folder_path)
        flash("Folder created successfully")
    else:
        flash("Folder already exists")
    return redirect(url_for('index', subpath=relative_subpath))

# ===============================
# Download Single File
# ===============================
@app.route('/download_file/<path:relative_subpath>')
@login_required
def download_file(relative_subpath):
    """
    Download a single file as attachment.
    """
    absolute_path = get_full_user_path(relative_subpath)
    if not os.path.isfile(absolute_path):
        abort(404)
    file_directory = os.path.dirname(absolute_path)
    file_basename = os.path.basename(absolute_path)
    return send_from_directory(file_directory, file_basename, as_attachment=True)

# ===============================
# Download All Files/Dirs in Current Dir as Zip
# ===============================
@app.route('/download_all/<path:relative_subpath>')
@app.route('/download_all/', defaults={'relative_subpath': ''})
@login_required
def download_all(relative_subpath=''):
    """
    Download all contents of the current directory as a zip archive.
    """
    root_dir = get_full_user_path(relative_subpath)
    if not os.path.exists(root_dir):
        abort(404)
    # Create in-memory zip file
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        for dir_path, dir_names, file_names in os.walk(root_dir):
            for fn in file_names:
                abs_file = os.path.join(dir_path, fn)
                arcname = os.path.relpath(abs_file, root_dir)
                zip_file.write(abs_file, arcname)
    memory_file.seek(0)
    dir_display_name = os.path.basename(os.path.normpath(root_dir)) or "all"
    return Response(memory_file.getvalue(),
                    mimetype='application/zip',
                    headers={"Content-Disposition": f"attachment;filename={dir_display_name}.zip"})

# ===============================
# Batch Delete Files and Folders
# ===============================
@app.route('/delete', methods=["POST"])
@login_required
def batch_delete():
    """
    Batch delete selected files or folders.
    """
    relative_subpath = request.form.get('subpath', '')
    selected_items = request.form.getlist('checked_item')
    deleted_count = 0
    for item in selected_items:
        item_absolute_path = get_full_user_path(item)
        if os.path.isfile(item_absolute_path):
            try:
                os.remove(item_absolute_path)
                deleted_count += 1
            except:
                pass
        elif os.path.isdir(item_absolute_path):
            try:
                shutil.rmtree(item_absolute_path)
                deleted_count += 1
            except:
                pass
    flash(f"Deleted {deleted_count} item(s)")
    return redirect(url_for('index', subpath=relative_subpath))

# ===============================
# Batch Move Files and Folders
# ===============================
@app.route('/move', methods=["POST"])
@login_required
def batch_move():
    """
    Move selected files/folders to a specified existing subdirectory.
    """
    relative_subpath = request.form.get('subpath', '')
    selected_items = request.form.getlist('checked_item')
    move_to_dir_relative = request.form.get('move_to', '').strip()
    if not move_to_dir_relative:
        flash("Target folder is required")
        return redirect(url_for('index', subpath=relative_subpath))
    move_to_directory = get_full_user_path(move_to_dir_relative)
    if not os.path.isdir(move_to_directory):
        flash("Target is not a valid directory")
        return redirect(url_for('index', subpath=relative_subpath))
    moved_count = 0
    for item in selected_items:
        source_absolute_path = get_full_user_path(item)
        base_name = os.path.basename(source_absolute_path)
        target_path = os.path.join(move_to_directory, base_name)
        try:
            shutil.move(source_absolute_path, target_path)
            moved_count += 1
        except Exception as e:
            pass # Could log details
    flash(f"Moved {moved_count} item(s)")
    return redirect(url_for('index', subpath=relative_subpath))

# ===============================
# HTML Render (Bootstrap, Red/Gold Theme)
# ===============================
def render_simple_html(page_title, inner_content, tip_message=None):
    """
    Render a simple single-form page, for login/register/change password etc.
    """
    base_html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>{page_title} - Cloud Disk</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
        body {{
            background: #fbeee0;
        }}
        .container {{
            margin-top: 80px;
            background: #fffbe8;
            border-radius: 10px;
            box-shadow: 0 0 8px #fdbb26;
            max-width:500px;
            padding:40px;
        }}
        .btn-danger,.btn-warning,.btn-outline-danger,.btn-outline-warning {{
            background: #ff3533;
            border-color: #fdaf0b;
        }}
        a, .text-link {{ color:#d85421; }}
        </style>
    </head>
    <body>
    <div class="container">
        <h2 class='mb-4' style='color:#db960b'>{page_title}</h2>
        {f"<div class='alert alert-warning'>{tip_message}</div>" if tip_message else ""}
        {inner_content}
    </div>
    </body>
    </html>
    """
    return base_html

def render_main_page_html(item_list, current_path, parent_dir_path, subpath, all_directory_choices, flash_messages):
    """
    Render the main file manager HTML.
    """
    # Navbar
    html_head = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8"/>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Cloud Disk - My Files</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
        body {{
            background: #fbeee0;
        }}
        .container {{
            margin-top:35px;
            padding:15px 20px 30px 20px;
            background: #fffbe8;
            border-radius: 9px;
            box-shadow: 0 0 8px #fdbb26;
        }}
        thead th {{
            background: #fdaf0b;
            color:#fff;
        }}
        tr.file-row:hover {{
            background-color: #fbe3cf;
        }}
        .btn-danger,.btn-warning,.btn-outline-danger,.btn-outline-warning {{
            background: #ff3533;
            border-color: #fdaf0b;
        }}
        .navbar {{
            background:linear-gradient(90deg,#e94e0f, #ffd97d 90%);
            color:#fff;font-size:20px;
        }}
        </style>
    </head>
    <body>
    <nav class="navbar navbar-expand-lg">
        <span class="navbar-brand ps-3" style="color:#fff;font-size:1.25rem;">🧧 Simple Personal Cloud Disk Demo</span>
        <div class='ms-auto pe-3'>
            <span>Hello, <strong>{username}</strong></span>
            <a class='ms-3 text-link' href="/change_password">Change Password</a>
            <a class='ms-2 text-link' href="/logout">Logout</a>
        </div>
    </nav>
    <div class="container">
    """.format(username=get_current_username())

    # Path bar and nav links
    navigation_bar = f"""
    <nav class="mb-3 mt-2">
        Current Location: <span class='badge bg-warning text-dark mx-1'>{current_path}</span>
        {"<a href='/?'>Home</a>" if subpath else ""}
        {"<a href='/{parent_dir_path}'>Up</a>" if subpath else ""}
        <a class='btn btn-outline-danger btn-sm ms-2' href='/download_all/{subpath}'>Download This Folder</a>
    </nav>
    """
    flash_message_html = ""
    for msg in flash_messages:
        flash_message_html += f"<div class='alert alert-warning'>{msg}</div>"

    # Main file table (uses batch forms for delete/move)
    file_table_html = """
    <form id="mainForm" method="post" action='/delete'>
    <input type='hidden' name='subpath' value='{subpath}'>
     <table class='table table-bordered align-middle'>
        <thead>
            <tr>
                <th style="width:34px;"><input type='checkbox' onclick="setAll(this)"></th>
                <th>Name</th>
                <th>Type</th>
                <th>Size(KB)</th>
                <th>Action</th>
            </tr>
        </thead>
        <tbody>
    """.format(subpath=subpath)
    # Render each item row
    for item in item_list:
        row_html = "<tr class='file-row'>"
        row_html += "<td><input type='checkbox' name='checked_item' value='{v}'></td>".format(v=item['subpath'])
        if item['is_dir']:
            row_html += "<td><a href='/{sub}' style='color:#d85421;font-weight:bold;'>{n}/</a></td>".format(sub=item['subpath'], n=item['name'])
            row_html += "<td>Folder</td>"
            row_html += "<td></td>"
            row_html += "<td></td>"
        else:
            row_html += "<td>{n}</td>".format(n=item['name'])
            row_html += "<td>File</td>"
            row_html += f"<td>{item['size']}</td>"
            row_html += ("<td><a class='btn btn-outline-warning btn-sm' href='/download_file/{s}'>Download</a></td>").format(s=item['subpath'])
        row_html += "</tr>"
        file_table_html += row_html
    file_table_html += """
        </tbody>
     </table>
     <div class='mb-2'>
        <button type='submit' class='btn btn-danger btn-sm' onclick="return confirm('Are you sure to delete?')">Delete Selected</button>
        <button type='button' class='btn btn-outline-warning btn-sm' onclick="showMove()">Move Selected</button>
     </div>
    </form>
    """

    # Move Form (hidden by default)
    move_panel_html = """
    <form id="moveForm" method='post' action='/move' style="display:none;">
        <input type='hidden' name='subpath' value='{subpath}'>
        <input type='hidden' name='move_items_temp'>
        <label>Move to:</label>
        <select name='move_to' required>
    """.format(subpath=subpath)
    for relative_dir in all_directory_choices:
        if relative_dir == '':
            continue
        move_panel_html += f"<option value='{relative_dir}'>{relative_dir or '/'}</option>"
    move_panel_html += """</select> 
        <button class='btn btn-danger btn-sm'>Move</button> 
        <button class='btn btn-sm btn-link' type='button' onclick='hideMove()'>Cancel</button>
    </form>"""

    # File upload + new folder form
    upload_and_mkdir_form = f"""
    <div style='display:flex;flex-wrap:wrap;gap:16px;align-items:center;margin-bottom:10px;'>
        <form method='post' enctype="multipart/form-data" action='/upload' class='d-flex align-items-center'>
            <input type='hidden' name='subpath' value='{subpath}'>
            <input type='file' multiple name='file' class='form-control form-control-sm' style='max-width:250px;'>
            <input type='submit' class='btn btn-warning btn-sm ms-2' value='Upload'>
        </form>
        <form method="post" action='/mkdir' class='d-flex align-items-center'>
            <input type='hidden' name='subpath' value='{subpath}'>
            <input type='text' name='new_folder' class='form-control form-control-sm' placeholder='New Folder Name' style='max-width:120px;' required>
            <input type='submit' class='btn btn-danger btn-sm ms-2' value='Create Folder'>
        </form>
    </div>
    """

    # Main page footer, with client-side JS for move
    html_footer = """
    </div>
    <script>
    // Select all checkboxes
    function setAll(master){{
        var checkboxes = document.querySelectorAll('input[name=checked_item]');
        for(var i=0;i<checkboxes.length;i++){{checkboxes[i].checked=master.checked;}}
    }}
    // Show the move form, collect which items are checked
    function showMove(){{
        var form=document.getElementById('moveForm');
        form.style.display='block';
        var checkboxes=document.querySelectorAll('input[name=checked_item]:checked');
        if(checkboxes.length==0){{alert('Please select items first');return;}}
        if(form.elements['move_items_temp'])form.removeChild(form.elements['move_items_temp']);
        var hiddenInputs='';
        for(var i=0;i<checkboxes.length;i++){{
            hiddenInputs+="<input type='hidden' name='checked_item' value='"+encodeURIComponent(checkboxes[i].value)+"'>";
        }}
        form.insertAdjacentHTML('beforeend',hiddenInputs);
    }}
    // Hide the move form
    function hideMove(){{
        document.getElementById('moveForm').style.display='none';
    }}
    </script>
    </body></html>
    """

    # Assembled
    return html_head + navigation_bar + flash_message_html + upload_and_mkdir_form + file_table_html + move_panel_html + html_footer

# ====== Program Entry Point ======
if __name__ == "__main__":
    app.run(debug=True)
