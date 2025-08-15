import os
import re
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, send_file, flash, session
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from datetime import datetime
from io import BytesIO
from xhtml2pdf import pisa
import matplotlib.pyplot as plt
from functools import wraps

app = Flask(__name__)
app.secret_key = "secret123"  # keep yours if you prefer
UPLOAD_FOLDER = "uploads"
DB_FILE = "logs.db"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# ---------------- Helpers ----------------
def get_db():
    return sqlite3.connect(DB_FILE)

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in to continue.")
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper

def current_user():
    if "user_id" in session:
        return {"id": session["user_id"], "username": session.get("username")}
    return None

# ---------------- Database Setup / Migration ----------------
def column_exists(cur, table, column):
    cur.execute(f"PRAGMA table_info({table})")
    return any(col[1] == column for col in cur.fetchall())

def init_db():
    conn = get_db()
    c = conn.cursor()

    # users
    c.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        created_at TEXT
    )""")

    # uploads (add user_id if missing)
    c.execute("""
    CREATE TABLE IF NOT EXISTS uploads(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        upload_time TEXT
    )""")
    if not column_exists(c, "uploads", "user_id"):
        c.execute("ALTER TABLE uploads ADD COLUMN user_id INTEGER DEFAULT NULL")

    # logs (add user_id if missing)
    c.execute("""
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        filename TEXT,
        ip TEXT,
        timestamp TEXT,
        method TEXT,
        path TEXT,
        protocol TEXT,
        status INTEGER,
        size INTEGER,
        referrer TEXT,
        useragent TEXT
    )""")
    if not column_exists(c, "logs", "user_id"):
        c.execute("ALTER TABLE logs ADD COLUMN user_id INTEGER DEFAULT NULL")

    conn.commit()
    conn.close()

init_db()

# ---------------- Parse Log ----------------
log_pattern = re.compile(
    r'(\d+\.\d+\.\d+\.\d+) - - \[(.*?)\] "(.*?) (.*?) (.*?)" (\d+) (\d+) "(.*?)" "(.*?)"'
)

def parse_log_file(filepath, filename, user_id):
    conn = get_db()
    c = conn.cursor()
    with open(filepath, encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = log_pattern.match(line)
            if m:
                ip, timestamp, method, path, protocol, status, size, referrer, useragent = m.groups()
                c.execute(
                    """
                    INSERT INTO logs(filename, ip, timestamp, method, path, protocol, status, size, referrer, useragent, user_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (filename, ip, timestamp, method, path, protocol, int(status), int(size), referrer, useragent, user_id),
                )
    conn.commit()
    conn.close()

# ---------------- Auth Routes ----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            flash("Username and password are required.")
            return redirect(url_for("register"))

        conn = get_db()
        c = conn.cursor()
        try:
            c.execute(
                "INSERT INTO users(username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, generate_password_hash(password), datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            flash("Username already exists.")
            conn.close()
            return redirect(url_for("register"))

        # auto login after registration
        c.execute("SELECT id FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        session["user_id"] = row[0]
        session["username"] = username
        flash("Welcome! Account created.")
        return redirect(url_for("index"))
    return render_template("register.html", user=current_user())

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
        row = c.fetchone()
        conn.close()
        if row and check_password_hash(row[1], password):
            session["user_id"] = row[0]
            session["username"] = username
            flash("Logged in successfully.")
            return redirect(url_for("index"))
        flash("Invalid credentials.")
        return redirect(url_for("login"))
    return render_template("login.html", user=current_user())

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for("index"))

# ---------------- Core Routes ----------------
@app.route("/", methods=["GET", "POST"])
def index():
    """
    Public landing page if not logged in.
    Original upload/list UI if logged in (kept intact, now per-user).
    """
    user = current_user()
    if not user:
        return render_template("landing.html", user=None)

    conn = get_db()
    c = conn.cursor()

    if request.method == "POST":
        if 'logfile' not in request.files:
            flash("No file part")
            return redirect(request.url)
        file = request.files['logfile']
        if file.filename == "":
            flash("No file selected")
            return redirect(request.url)

        filename = secure_filename(file.filename)
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        parse_log_file(filepath, filename, user["id"])
        c.execute(
            "INSERT INTO uploads(filename, upload_time, user_id) VALUES (?, ?, ?)",
            (filename, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), user["id"]),
        )
        conn.commit()
        flash(f"{filename} uploaded successfully")
        return redirect(url_for("index"))

    c.execute("SELECT id, filename, upload_time FROM uploads WHERE user_id=? ORDER BY id DESC", (user["id"],))
    uploads = c.fetchall()
    conn.close()
    return render_template("index.html", uploads=uploads, user=user)

@app.route("/delete/<filename>")
@login_required
def delete_file(filename):
    user = current_user()
    try:
        os.remove(os.path.join(UPLOAD_FOLDER, filename))
    except Exception:
        pass
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM uploads WHERE filename=? AND user_id=?", (filename, user["id"]))
    c.execute("DELETE FROM logs WHERE filename=? AND user_id=?", (filename, user["id"]))
    conn.commit()
    conn.close()
    flash(f"{filename} deleted successfully")
    return redirect(url_for("index"))

@app.route("/dashboard/<filename>")
@login_required
def dashboard(filename):
    user = current_user()
    conn = get_db()
    df = pd.read_sql("SELECT * FROM logs WHERE filename=? AND user_id=?", conn, params=(filename, user["id"]))
    conn.close()
    if df.empty:
        flash("No data in this file")
        return redirect(url_for("index"))

    total_requests = len(df)
    total_errors = len(df[df['status'] >= 400])
    top_ips = df['ip'].value_counts().head(5).to_dict()
    top_pages = df['path'].value_counts().head(5).to_dict()
    top_errors = df[df['status'] >= 400]['path'].value_counts().head(5).to_dict()

    # charts
    plt.figure(figsize=(4, 4))
    df['status'].value_counts().plot.pie(autopct='%1.1f%%', startangle=90)
    plt.title("Status Codes Distribution")
    pie_path = os.path.join("static", "status_pie.png")
    plt.savefig(pie_path, bbox_inches="tight")
    plt.close()

    df['timestamp_dt'] = pd.to_datetime(df['timestamp'], format="%d/%b/%Y:%H:%M:%S %z", errors='coerce')
    req_over_time = df.groupby(df['timestamp_dt'].dt.floor('H')).size()
    plt.figure(figsize=(6, 3))
    req_over_time.plot.line(marker='o')
    plt.title("Requests Over Time")
    plt.xlabel("Time"); plt.ylabel("Requests")
    line_path = os.path.join("static", "requests_line.png")
    plt.savefig(line_path, bbox_inches="tight")
    plt.close()

    return render_template("dashboard.html", filename=filename,
                           total_requests=total_requests,
                           total_errors=total_errors,
                           top_ips=top_ips,
                           top_pages=top_pages,
                           top_errors=top_errors,
                           pie_path=pie_path,
                           line_path=line_path,
                           user=user)

@app.route("/download_pdf/<filename>")
@login_required
def download_pdf(filename):
    user = current_user()
    conn = get_db()
    df = pd.read_sql("SELECT * FROM logs WHERE filename=? AND user_id=?", conn, params=(filename, user["id"]))
    conn.close()

    total_requests = len(df)
    total_errors = len(df[df['status'] >= 400])
    top_ips = df['ip'].value_counts().head(5).to_dict()
    top_pages = df['path'].value_counts().head(5).to_dict()
    top_errors = df[df['status'] >= 400]['path'].value_counts().head(5).to_dict()

    # charts
    plt.figure(figsize=(4, 4))
    df['status'].value_counts().plot.pie(autopct='%1.1f%%', startangle=90)
    plt.title("Status Codes Distribution")
    pie_path = os.path.join("static", "status_pie_pdf.png")
    plt.savefig(pie_path, bbox_inches="tight")
    plt.close()

    df['timestamp_dt'] = pd.to_datetime(df['timestamp'], format="%d/%b/%Y:%H:%M:%S %z", errors='coerce')
    req_over_time = df.groupby(df['timestamp_dt'].dt.floor('H')).size()
    plt.figure(figsize=(6, 3))
    req_over_time.plot.line(marker='o')
    plt.title("Requests Over Time")
    plt.xlabel("Time"); plt.ylabel("Requests")
    line_path = os.path.join("static", "requests_line_pdf.png")
    plt.savefig(line_path, bbox_inches="tight")
    plt.close()

    html = render_template("pdf_report.html", filename=filename,
                           total_requests=total_requests,
                           total_errors=total_errors,
                           top_ips=top_ips,
                           top_pages=top_pages,
                           top_errors=top_errors,
                           pie_path=pie_path,
                           line_path=line_path,
                           user=user)
    output = BytesIO()
    pisa.CreatePDF(html, dest=output)
    output.seek(0)
    return send_file(output, mimetype='application/pdf', download_name=f'report_{filename}.pdf', as_attachment=True)

@app.route("/all_logs")
@login_required
def all_logs():
    user = current_user()
    search = request.args.get('search', '')
    filters = {k: request.args.get(k, '') for k in ['ip', 'timestamp', 'method', 'path', 'status']}
    conn = get_db()

    query = "SELECT * FROM logs WHERE user_id=?"
    params = [user["id"]]
    for k, v in filters.items():
        if v:
            query += f" AND {k} LIKE ?"
            params.append(f"%{v}%")
    if search:
        query += " AND (ip LIKE ? OR path LIKE ? OR useragent LIKE ?)"
        params.extend([f"%{search}%"] * 3)

    df = pd.read_sql(query, conn, params=params)

    if not df.empty:
        ip_counts = df['ip'].value_counts().to_dict()
        ip_errors = df[df['status'] >= 400]['ip'].value_counts().to_dict()

        def get_risk_status(row):
            if row['status'] >= 500: return "High"
            elif row['status'] >= 400: return "Medium"
            else: return "Low"

        df['Risk_Level'] = df.apply(get_risk_status, axis=1)
        df['Score'] = df['status']
        df['Total_Requests'] = df['ip'].map(ip_counts)
        df['Total_Errors'] = df['ip'].map(ip_errors).fillna(0).astype(int)

    conn.close()
    return render_template("all_logs.html",
                           logs=df.to_dict(orient='records'),
                           filters=filters, search=search, user=user)

@app.route("/download_csv")
@login_required
def download_csv():
    user = current_user()
    conn = get_db()
    df = pd.read_sql("SELECT * FROM logs WHERE user_id=?", conn, params=(user["id"],))
    conn.close()
    output = BytesIO()
    df.to_csv(output, index=False)
    output.seek(0)
    return send_file(output, mimetype="text/csv", download_name="all_logs.csv", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)
