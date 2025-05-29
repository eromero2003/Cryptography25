from flask import Flask, render_template, request, redirect, session, jsonify
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
import base64
import os
import sqlite3

app = Flask(__name__)
app.secret_key = os.urandom(24)

def init_db():
    with sqlite3.connect("vault.db") as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                master_hash TEXT NOT NULL,
                salt BLOB NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                password BLOB NOT NULL,
                user_id INTEGER NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """)

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

@app.route("/", methods=["GET", "POST"])
def login():
    init_db()
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
       
        if not username or not password:
            return "Username and password are required", 400
       
        with sqlite3.connect("vault.db") as conn:
            user = conn.execute("SELECT id, master_hash, salt FROM users WHERE username = ?", (username,)).fetchone()
            if user:
                uid, master_hash, salt = user
                key = derive_key(password, salt)
                if key.decode() == master_hash:
                    session["key"] = key.decode()
                    session["user_id"] = uid
                    return redirect("/dashboard")
                else:
                    return "Invalid password", 403
            else:
                return "User not found", 404

    return render_template("login.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
       
        if not username or not password:
            return "Username and password are required", 400
       
        with sqlite3.connect("vault.db") as conn:
            salt = os.urandom(16)
            key = derive_key(password, salt)
            try:
                conn.execute("INSERT INTO users (username, master_hash, salt) VALUES (?, ?, ?)", (username, key.decode(), salt))
                return redirect("/")
            except sqlite3.IntegrityError:
                return "Username already exists", 409
    return render_template("signup.html")

@app.route("/add", methods=["GET", "POST"])
def add_password():
    if "user_id" not in session:
        return redirect("/")
   
    if request.method == 'POST':
        site = request.form['website']
        username = request.form['username']
        password = request.form['password']
       
        fernet = Fernet(session["key"].encode())
        encrypted_password = fernet.encrypt(password.encode())

        with sqlite3.connect("vault.db") as conn:
            conn.execute("INSERT INTO credentials (site, username, password, user_id) VALUES (?, ?, ?, ?)",
                         (site, username, encrypted_password, session["user_id"]))
            conn.commit()
       
        return redirect('/dashboard')
   
    return render_template('add_password.html')

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/")

    with sqlite3.connect("vault.db") as conn:
        creds = conn.execute(
            "SELECT id, site, username, password FROM credentials WHERE user_id = ?",
            (session["user_id"],)
        ).fetchall()
    passwords = [
        (cid, site, user, base64.b64encode(pwd).decode())
        for cid, site, user, pwd in creds
    ]
    return render_template("dashboard.html", passwords=passwords)

@app.route("/edit/<int:cred_id>", methods=["GET", "POST"])
def edit_password(cred_id):
    if "user_id" not in session:
        return redirect("/")
    with sqlite3.connect("vault.db") as conn:
        cred = conn.execute("SELECT site, username, password FROM credentials WHERE id = ? AND user_id = ?", 
                            (cred_id, session["user_id"])).fetchone()
        if not cred:
            return "Credential not found", 404

    fernet = Fernet(session["key"].encode())
    decrypted_pwd = fernet.decrypt(cred[2]).decode()

    if request.method == "POST":
        new_site = request.form["website"]
        new_user = request.form["username"]
        new_pwd = request.form["password"]

        encrypted_pwd = fernet.encrypt(new_pwd.encode())
        with sqlite3.connect("vault.db") as conn:
            conn.execute("""
                UPDATE credentials 
                SET site = ?, username = ?, password = ? 
                WHERE id = ? AND user_id = ?
            """, (new_site, new_user, encrypted_pwd, cred_id, session["user_id"]))
            conn.commit()

        return redirect("/dashboard")

    return render_template("edit_password.html", site=cred[0], username=cred[1], password=decrypted_pwd)

@app.route("/reveal_password", methods=["POST"])
def reveal_password():
    if "user_id" not in session:
        return jsonify({"success": False, "message": "Not logged in"}), 401

    encrypted = request.form.get("encrypted")
    master_password = request.form.get("master_password")
    if not encrypted or not master_password:
        return jsonify({"success": False, "message": "Missing data"}), 400

    with sqlite3.connect("vault.db") as conn:
        user = conn.execute("SELECT master_hash, salt FROM users WHERE id = ?", (session["user_id"],)).fetchone()
        if not user:
            return jsonify({"success": False, "message": "User not found"}), 404
        master_hash, salt = user
        key = derive_key(master_password, salt)
        if key.decode() != master_hash:
            return jsonify({"success": False, "message": "Incorrect master password"}), 403
        try:
            fernet = Fernet(key)
            decrypted = fernet.decrypt(base64.b64decode(encrypted)).decode()
            return jsonify({"success": True, "password": decrypted})
        except Exception as e:
            print(f"Reveal: Exception {e}")
            return jsonify({"success": False, "message": "Failed to decrypt"})

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")
if __name__ == "__main__":
    init_db()
    app.run(debug=False)






















