import os
import sqlite3
from datetime import datetime, date

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, g, abort,
)
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user,
)

app = Flask(__name__)
app.secret_key = os.urandom(32)

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Bu sayfayı görüntülemek için giriş yapmalısınız."
login_manager.login_message_category = "error"

# ---------------------------------------------------------------------------
# Jinja2 filters
# ---------------------------------------------------------------------------

TR_MONTHS = [
    "", "Oca", "Şub", "Mar", "Nis", "May", "Haz",
    "Tem", "Ağu", "Eyl", "Eki", "Kas", "Ara",
]

def format_tr_datetime(value):
    """'2026-03-08 14:30' or '2026-03-08 14:30:00' → '08.03.2026 14:30'"""
    if not value:
        return "—"
    try:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(str(value), fmt)
                if fmt == "%Y-%m-%d":
                    return dt.strftime("%d.%m.%Y")
                return dt.strftime("%d.%m.%Y %H:%M")
            except ValueError:
                continue
    except Exception:
        pass
    return str(value)


def format_tr_date_only(value):
    """'2026-03-08 14:30:00' → '08.03.2026'"""
    if not value:
        return "—"
    try:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                dt = datetime.strptime(str(value), fmt)
                return dt.strftime("%d.%m.%Y")
            except ValueError:
                continue
    except Exception:
        pass
    return str(value)


app.jinja_env.filters["tr_datetime"] = format_tr_datetime
app.jinja_env.filters["tr_date"] = format_tr_date_only

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute("PRAGMA foreign_keys = ON")
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );
        CREATE TABLE IF NOT EXISTS todos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            due_date TEXT,
            is_completed INTEGER NOT NULL DEFAULT 0,
            completed_at TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now','localtime')),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
    """)
    cur = db.execute("SELECT id FROM users WHERE username = 'admin'")
    if cur.fetchone() is None:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin123"), "admin"),
        )
    db.commit()
    db.close()

# ---------------------------------------------------------------------------
# User model for Flask-Login
# ---------------------------------------------------------------------------

class User(UserMixin):
    def __init__(self, id, username, role):
        self.id = id
        self.username = username
        self.role = role

    @property
    def is_admin(self):
        return self.role == "admin"


@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if row:
        return User(row["id"], row["username"], row["role"])
    return None

# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("todos"))
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        db = get_db()
        row = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            user = User(row["id"], row["username"], row["role"])
            login_user(user)
            return redirect(request.args.get("next") or url_for("todos"))
        flash("Kullanıcı adı veya şifre hatalı.", "error")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/sifre-degistir", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        db = get_db()
        row = db.execute("SELECT password_hash FROM users WHERE id = ?", (current_user.id,)).fetchone()

        if not check_password_hash(row["password_hash"], current_pw):
            flash("Mevcut şifre yanlış.", "error")
        elif len(new_pw) < 4:
            flash("Yeni şifre en az 4 karakter olmalıdır.", "error")
        elif new_pw != confirm_pw:
            flash("Yeni şifreler eşleşmiyor.", "error")
        else:
            db.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (generate_password_hash(new_pw), current_user.id),
            )
            db.commit()
            flash("Şifre başarıyla değiştirildi.", "success")
            return redirect(url_for("todos"))

    return render_template("change_password.html")

# ---------------------------------------------------------------------------
# Todo routes
# ---------------------------------------------------------------------------

def stamp_newly_completed(db, user_id):
    """Set completed_at for tasks that are marked done but lack a timestamp."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.execute(
        "UPDATE todos SET completed_at = ? WHERE user_id = ? AND is_completed = 1 AND completed_at IS NULL",
        (now, user_id),
    )
    db.commit()


@app.route("/")
@login_required
def todos():
    db = get_db()
    stamp_newly_completed(db, current_user.id)

    sort = request.args.get("sort", "asc")
    order = "ASC" if sort == "asc" else "DESC"

    active = db.execute(
        f"SELECT * FROM todos WHERE user_id = ? AND is_completed = 0 ORDER BY due_date {order}",
        (current_user.id,),
    ).fetchall()

    completed = db.execute(
        f"SELECT * FROM todos WHERE user_id = ? AND is_completed = 1 ORDER BY due_date {order}",
        (current_user.id,),
    ).fetchall()

    return render_template("todos.html", active=active, completed=completed, sort=sort)


@app.route("/gorev/ekle", methods=["POST"])
@login_required
def add_todo():
    title = request.form.get("title", "").strip()
    due_date = request.form.get("due_date", "")
    due_time = request.form.get("due_time", "")
    if not title:
        flash("Görev başlığı gereklidir.", "error")
        return redirect(url_for("todos"))

    due_datetime = None
    if due_date:
        due_datetime = f"{due_date} {due_time}" if due_time else due_date

    db = get_db()
    db.execute(
        "INSERT INTO todos (user_id, title, due_date) VALUES (?, ?, ?)",
        (current_user.id, title, due_datetime),
    )
    db.commit()
    return redirect(url_for("todos"))


@app.route("/gorev/<int:todo_id>/tamamla", methods=["POST"])
@login_required
def toggle_todo(todo_id):
    db = get_db()
    row = db.execute("SELECT * FROM todos WHERE id = ? AND user_id = ?", (todo_id, current_user.id)).fetchone()
    if not row:
        abort(404)
    new_status = 0 if row["is_completed"] else 1
    if new_status == 1:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        db.execute("UPDATE todos SET is_completed = 1, completed_at = ? WHERE id = ?", (now, todo_id))
    else:
        db.execute("UPDATE todos SET is_completed = 0, completed_at = NULL WHERE id = ?", (todo_id,))
    db.commit()
    return redirect(url_for("todos"))


@app.route("/gorev/<int:todo_id>/geri-al", methods=["POST"])
@login_required
def undo_todo(todo_id):
    db = get_db()
    row = db.execute("SELECT * FROM todos WHERE id = ? AND user_id = ?", (todo_id, current_user.id)).fetchone()
    if not row:
        abort(404)
    db.execute("UPDATE todos SET is_completed = 0, completed_at = NULL WHERE id = ?", (todo_id,))
    db.commit()
    return redirect(url_for("todos"))


@app.route("/gorev/<int:todo_id>/sil", methods=["POST"])
@login_required
def delete_todo(todo_id):
    db = get_db()
    db.execute("DELETE FROM todos WHERE id = ? AND user_id = ?", (todo_id, current_user.id))
    db.commit()
    return redirect(url_for("todos"))

# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

@app.route("/yonetim")
@login_required
def admin_panel():
    if not current_user.is_admin:
        abort(403)
    db = get_db()
    users = db.execute("SELECT id, username, role FROM users ORDER BY id").fetchall()
    return render_template("admin.html", users=users)


@app.route("/yonetim/kullanici/ekle", methods=["POST"])
@login_required
def admin_add_user():
    if not current_user.is_admin:
        abort(403)
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")
    if not username or not password:
        flash("Kullanıcı adı ve şifre gereklidir.", "error")
        return redirect(url_for("admin_panel"))
    if role not in ("admin", "user"):
        role = "user"
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
        db.commit()
        flash(f"'{username}' kullanıcısı oluşturuldu.", "success")
    except sqlite3.IntegrityError:
        flash(f"'{username}' kullanıcı adı zaten mevcut.", "error")
    return redirect(url_for("admin_panel"))


@app.route("/yonetim/kullanici/<int:user_id>/sil", methods=["POST"])
@login_required
def admin_delete_user(user_id):
    if not current_user.is_admin:
        abort(403)
    if user_id == current_user.id:
        flash("Kendinizi silemezsiniz.", "error")
        return redirect(url_for("admin_panel"))
    db = get_db()
    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    flash("Kullanıcı silindi.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/yonetim/kullanici/<int:user_id>/sifre", methods=["POST"])
@login_required
def admin_change_user_password(user_id):
    if not current_user.is_admin:
        abort(403)
    new_pw = request.form.get("new_password", "")
    if len(new_pw) < 4:
        flash("Şifre en az 4 karakter olmalıdır.", "error")
        return redirect(url_for("admin_panel"))
    db = get_db()
    row = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        abort(404)
    db.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (generate_password_hash(new_pw), user_id),
    )
    db.commit()
    flash(f"'{row['username']}' kullanıcısının şifresi değiştirildi.", "success")
    return redirect(url_for("admin_panel"))

# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
