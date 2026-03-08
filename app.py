import os
from datetime import datetime, date

import psycopg2
import psycopg2.extras
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
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:%23L%2AnZ7.u%216z%259xM@db.ldcqwqptxmkxbrgvfbmj.supabase.co:5432/postgres",
)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"
login_manager.login_message = "Bu sayfayı görüntülemek için giriş yapmalısınız."
login_manager.login_message_category = "error"

# ---------------------------------------------------------------------------
# Jinja2 filters
# ---------------------------------------------------------------------------

def format_tr_datetime(value):
    """Format a date/datetime value to 'DD.MM.YYYY HH:MM'."""
    if not value:
        return "—"
    if isinstance(value, datetime):
        return value.strftime("%d.%m.%Y %H:%M")
    if isinstance(value, date):
        return value.strftime("%d.%m.%Y")
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
    """Format a date/datetime value to 'DD.MM.YYYY'."""
    if not value:
        return "—"
    if isinstance(value, (datetime, date)):
        return value.strftime("%d.%m.%Y")
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
        g.db = psycopg2.connect(DATABASE_URL)
        g.db.autocommit = False
    return g.db


def get_cursor(db=None):
    if db is None:
        db = get_db()
    return db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        try:
            db.close()
        except Exception:
            pass


def init_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = True
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS todos (
            id SERIAL PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title TEXT NOT NULL,
            due_date TEXT,
            is_completed BOOLEAN NOT NULL DEFAULT FALSE,
            completed_at TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT NOW()
        );
    """)
    cur.execute("SELECT id FROM users WHERE username = 'admin'")
    if cur.fetchone() is None:
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            ("admin", generate_password_hash("admin123"), "admin"),
        )
    cur.close()
    conn.close()

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
    cur = get_cursor(db)
    cur.execute("SELECT * FROM users WHERE id = %s", (int(user_id),))
    row = cur.fetchone()
    cur.close()
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
        cur = get_cursor(db)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        cur.close()
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
        cur = get_cursor(db)
        cur.execute("SELECT password_hash FROM users WHERE id = %s", (current_user.id,))
        row = cur.fetchone()
        cur.close()

        if not check_password_hash(row["password_hash"], current_pw):
            flash("Mevcut şifre yanlış.", "error")
        elif len(new_pw) < 4:
            flash("Yeni şifre en az 4 karakter olmalıdır.", "error")
        elif new_pw != confirm_pw:
            flash("Yeni şifreler eşleşmiyor.", "error")
        else:
            cur = get_cursor(db)
            cur.execute(
                "UPDATE users SET password_hash = %s WHERE id = %s",
                (generate_password_hash(new_pw), current_user.id),
            )
            db.commit()
            cur.close()
            flash("Şifre başarıyla değiştirildi.", "success")
            return redirect(url_for("todos"))

    return render_template("change_password.html")

# ---------------------------------------------------------------------------
# Todo routes
# ---------------------------------------------------------------------------

def stamp_newly_completed(db, user_id):
    """Set completed_at for tasks that are marked done but lack a timestamp."""
    cur = get_cursor(db)
    cur.execute(
        "UPDATE todos SET completed_at = NOW() WHERE user_id = %s AND is_completed = TRUE AND completed_at IS NULL",
        (user_id,),
    )
    db.commit()
    cur.close()


@app.route("/")
@login_required
def todos():
    db = get_db()
    stamp_newly_completed(db, current_user.id)

    sort = request.args.get("sort", "asc")
    order = "ASC" if sort == "asc" else "DESC"

    cur = get_cursor(db)
    cur.execute(
        f"SELECT * FROM todos WHERE user_id = %s AND is_completed = FALSE ORDER BY due_date {order} NULLS LAST",
        (current_user.id,),
    )
    active = cur.fetchall()

    cur.execute(
        f"SELECT * FROM todos WHERE user_id = %s AND is_completed = TRUE ORDER BY due_date {order} NULLS LAST",
        (current_user.id,),
    )
    completed = cur.fetchall()
    cur.close()

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
    cur = get_cursor(db)
    cur.execute(
        "INSERT INTO todos (user_id, title, due_date) VALUES (%s, %s, %s)",
        (current_user.id, title, due_datetime),
    )
    db.commit()
    cur.close()
    return redirect(url_for("todos"))


@app.route("/gorev/<int:todo_id>/tamamla", methods=["POST"])
@login_required
def toggle_todo(todo_id):
    db = get_db()
    cur = get_cursor(db)
    cur.execute("SELECT * FROM todos WHERE id = %s AND user_id = %s", (todo_id, current_user.id))
    row = cur.fetchone()
    if not row:
        cur.close()
        abort(404)
    if row["is_completed"]:
        cur.execute("UPDATE todos SET is_completed = FALSE, completed_at = NULL WHERE id = %s", (todo_id,))
    else:
        cur.execute("UPDATE todos SET is_completed = TRUE, completed_at = NOW() WHERE id = %s", (todo_id,))
    db.commit()
    cur.close()
    return redirect(url_for("todos"))


@app.route("/gorev/<int:todo_id>/geri-al", methods=["POST"])
@login_required
def undo_todo(todo_id):
    db = get_db()
    cur = get_cursor(db)
    cur.execute("SELECT * FROM todos WHERE id = %s AND user_id = %s", (todo_id, current_user.id))
    row = cur.fetchone()
    if not row:
        cur.close()
        abort(404)
    cur.execute("UPDATE todos SET is_completed = FALSE, completed_at = NULL WHERE id = %s", (todo_id,))
    db.commit()
    cur.close()
    return redirect(url_for("todos"))


@app.route("/gorev/<int:todo_id>/sil", methods=["POST"])
@login_required
def delete_todo(todo_id):
    db = get_db()
    cur = get_cursor(db)
    cur.execute("DELETE FROM todos WHERE id = %s AND user_id = %s", (todo_id, current_user.id))
    db.commit()
    cur.close()
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
    cur = get_cursor(db)
    cur.execute("SELECT id, username, role FROM users ORDER BY id")
    users = cur.fetchall()
    cur.close()
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
    cur = get_cursor(db)
    try:
        cur.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (%s, %s, %s)",
            (username, generate_password_hash(password), role),
        )
        db.commit()
        flash(f"'{username}' kullanıcısı oluşturuldu.", "success")
    except psycopg2.IntegrityError:
        db.rollback()
        flash(f"'{username}' kullanıcı adı zaten mevcut.", "error")
    finally:
        cur.close()
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
    cur = get_cursor(db)
    cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
    db.commit()
    cur.close()
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
    cur = get_cursor(db)
    cur.execute("SELECT username FROM users WHERE id = %s", (user_id,))
    row = cur.fetchone()
    if not row:
        cur.close()
        abort(404)
    cur.execute(
        "UPDATE users SET password_hash = %s WHERE id = %s",
        (generate_password_hash(new_pw), user_id),
    )
    db.commit()
    cur.close()
    flash(f"'{row['username']}' kullanıcısının şifresi değiştirildi.", "success")
    return redirect(url_for("admin_panel"))

# ---------------------------------------------------------------------------
# Boot
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
